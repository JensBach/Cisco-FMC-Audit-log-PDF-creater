using FmcAuditLog;
using Microsoft.Extensions.Configuration;

var opts = ParseArgs(args);

if (opts.ContainsKey("help"))
{
    Console.WriteLine("""
        FMC Audit Log -> PDF (read-only)

          --import-secrets [sti]   Flyt .password ind i .NET user-secrets og slet filen
          --days N                 Antal dage tilbage (default 30)
          --subsystem NAVN         Filtrer subsystem, fx Policies (default: alle)
          --domain UUID            Domain UUID (default: fra login)
          --anonymize              Anonymiser brugere, IP'er og objektnavne
          --out FIL.pdf            Output-fil
          --save-json FIL          Gem hentede data (default: auditlog-cache.json)
          --from-json [FIL]        Brug gemte data i stedet for FMC (hurtig PDF-test)
          --from-dump [MAPPE]      Byg cache ud fra rå --dump sider
          --include-all            Medtag internaladmin og @ANUBIS:system-user (udelades som standard)
          --demo                   Brug genererede testdata i stedet for FMC
          --dump MAPPE             Gem rå JSON-svar fra FMC (fejlsøgning)
          --strict-tls             Valider FMC-certifikat (default: accepter self-signed)
          --policy-only            Hent kun policy-udtræk (gemmes i policy-cache.json)
          --no-policy              Udelad policy-udtræk i rapporten
        """);
    return 0;
}

if (opts.TryGetValue("import-secrets", out var importPath))
    return SecretsImporter.Import(string.IsNullOrEmpty(importPath) ? null : importPath);

var config = new ConfigurationBuilder()
    .AddUserSecrets<Program>(optional: true)
    .AddEnvironmentVariables("FMCAUDIT_")
    .Build();

if (opts.TryGetValue("probe", out var probePath) && probePath is not null)
{
    using var probe = new FmcClient(config["Fmc:Host"]!, config["Fmc:Username"]!, config["Fmc:Password"]!, true);
    using var pdoc = await probe.GetAsync(probePath);
    Console.WriteLine(pdoc.RootElement.GetRawText());
    return 0;
}

var days = opts.TryGetValue("days", out var d) && int.TryParse(d, out var dd) ? dd : 30;
var subsystem = opts.GetValueOrDefault("subsystem");
var anonymize = opts.ContainsKey("anonymize");
var to = DateTimeOffset.Now;
var from = to.AddDays(-days);
var withPolicy = !opts.ContainsKey("no-policy");
PolicySnapshot? policy = null;

if (opts.ContainsKey("policy-only"))
{
    using var pfmc = new FmcClient(config["Fmc:Host"]!, config["Fmc:Username"]!, config["Fmc:Password"]!,
        ignoreCertificate: !opts.ContainsKey("strict-tls"));
    await pfmc.AuthenticateAsync();
    Console.WriteLine($"Henter policy-udtræk (read-only), ændringer siden {from:yyyy-MM-dd} ...");
    var snap = await PolicyExtractor.FetchAsync(pfmc, from);
    snap.Save(PolicySnapshot.DefaultFile);
    Console.WriteLine($"{snap.Policies.Count} policies, {snap.Rules.Count} regler, {snap.ChangedObjects.Count} ændrede objekter, " +
                      $"{snap.Deployments.Count} deployments -> {Path.GetFullPath(PolicySnapshot.DefaultFile)}");
    return 0;
}

List<AuditRecord> records;
string fmcName;

if (opts.TryGetValue("from-json", out var jsonIn))
{
    records = AuditCache.Load(jsonIn ?? AuditCache.DefaultFile);
    fmcName = $"FMC {config["Fmc:Host"] ?? ""}".Trim();
    Console.WriteLine($"Indlæst {records.Count} records fra {jsonIn ?? AuditCache.DefaultFile}");
}
else if (opts.TryGetValue("from-dump", out var dumpIn))
{
    records = AuditCache.LoadDump(dumpIn ?? "/tmp/fmcdump");
    fmcName = $"FMC {config["Fmc:Host"] ?? ""}".Trim();
    Console.WriteLine($"Indlæst {records.Count} records fra dump");
    AuditCache.Save(records, AuditCache.DefaultFile);
}
else if (opts.ContainsKey("demo"))
{
    records = DemoData.Generate(from, to);
    fmcName = "FMC-DEMO (10.16.0.10)";
}
else
{
    var host = config["Fmc:Host"];
    var user = config["Fmc:Username"];
    var pass = config["Fmc:Password"];
    if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(pass))
    {
        Console.Error.WriteLine("Mangler credentials. Kør først: dotnet run -- --import-secrets");
        return 1;
    }

    Console.WriteLine($"Logger ind på FMC {host} som {user} (read-only)...");
    using var fmc = new FmcClient(host, user, pass, ignoreCertificate: !opts.ContainsKey("strict-tls"));
    fmc.DumpDirectory = opts.GetValueOrDefault("dump");
    await fmc.AuthenticateAsync();
    Console.WriteLine($"Henter audit records fra {from:yyyy-MM-dd HH:mm} ...");
    records = await fmc.GetAuditRecordsAsync(from, subsystem, opts.GetValueOrDefault("domain"));
    fmcName = $"FMC {host}";
    var jsonOut = opts.GetValueOrDefault("save-json") ?? AuditCache.DefaultFile;
    AuditCache.Save(records, jsonOut);
    Console.WriteLine($"Rå data gemt i {Path.GetFullPath(jsonOut)}");
    if (withPolicy)
    {
        Console.WriteLine("Henter policy-udtræk (read-only) ...");
        policy = await PolicyExtractor.FetchAsync(fmc, from);
        policy.Save(PolicySnapshot.DefaultFile);
    }
}

if (withPolicy && policy is null && !opts.ContainsKey("demo"))
{
    policy = PolicySnapshot.TryLoad(PolicySnapshot.DefaultFile);
    if (policy is not null) Console.WriteLine($"Policy-udtræk indlæst fra {PolicySnapshot.DefaultFile} ({policy.FetchedAt:dd-MM-yyyy HH:mm})");
}

if (records.Count > 0 && !opts.ContainsKey("days") && (opts.ContainsKey("from-json") || opts.ContainsKey("from-dump")))
    from = records.Min(r => r.Time);
records = records.Where(r => r.Time >= from && r.Time <= to).Select(Classifier.RenameDefaultUser).ToList();

var excludedUsers = opts.ContainsKey("include-all")
    ? []
    : config.GetSection("Fmc:ExcludeUsers").Get<string[]>() ?? ["internaladmin", "@ANUBIS:system-user"];
var beforeExclude = records.Count;
records = records.Where(r => !excludedUsers.Contains(r.Username, StringComparer.OrdinalIgnoreCase)).ToList();
var excludedCount = beforeExclude - records.Count;

if (subsystem is not null)
    records = records.Where(r => string.IsNullOrEmpty(r.Subsystem) ||
                                 r.Subsystem.Contains(subsystem, StringComparison.OrdinalIgnoreCase)).ToList();

if (anonymize)
{
    var extra = config.GetSection("Fmc:AnonymizeTerms").Get<string[]>() ?? [];
    var anon = new Anonymizer(extra);
    if (policy is not null) anon.Register(policy);
    records = anon.Apply(records);
    if (policy is not null) policy = anon.Apply(policy);
    fmcName = "FMC (anonymiseret)";
}

var outFile = opts.GetValueOrDefault("out") ??
              $"FMC-AuditLog-{(anonymize ? "anonymiseret-" : "")}{DateTime.Now:yyyyMMdd-HHmm}.pdf";

PdfReport.Generate(records, new ReportOptions
{
    Title = "Cisco FMC – Audit Log Rapport",
    FmcName = fmcName,
    From = from,
    To = to,
    Subsystem = subsystem,
    Anonymized = anonymize,
    ExcludedUsers = excludedUsers,
    ExcludedCount = excludedCount,
    Policy = policy
}, outFile);

Console.WriteLine($"{records.Count} records -> {Path.GetFullPath(outFile)}");
return 0;

static Dictionary<string, string?> ParseArgs(string[] args)
{
    var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < args.Length; i++)
    {
        if (!args[i].StartsWith("--")) continue;
        var key = args[i][2..];
        string? value = null;
        if (i + 1 < args.Length && !args[i + 1].StartsWith("--")) value = args[++i];
        result[key] = value;
    }
    return result;
}

public partial class Program;
