using System.Text.Json;

namespace FmcAuditLog;

public sealed record PolicyInfo(string Type, string Name, string LastUser, DateTimeOffset? Modified, int RuleCount);

public sealed record RuleInfo(
    string Policy, int Index, string Name, string Category, string Section, string Action, bool Enabled,
    List<string> SourceZones, List<string> DestinationZones, List<string> SourceNetworks,
    List<string> DestinationNetworks, List<string> Ports, List<string> Applications,
    string IpsPolicy, DateTimeOffset? Modified, List<string> Comments);

public sealed record ObjectInfo(string Type, string Name, string Value, string LastUser, DateTimeOffset? Modified);

public sealed record DeployedDevice(string Device, string Container, string Status, int? Version);

public sealed record DeploymentJob(
    string Name, string Status, DateTimeOffset? Start, DateTimeOffset? End, string User, string Note,
    List<DeployedDevice> Devices);

/// <summary>Current-state snapshot of policies/objects. Timestamps only reflect the latest change.</summary>
public sealed class PolicySnapshot
{
    public DateTimeOffset FetchedAt { get; set; }
    public List<PolicyInfo> Policies { get; set; } = [];
    public List<RuleInfo> Rules { get; set; } = [];
    public List<ObjectInfo> ChangedObjects { get; set; } = [];
    public List<DeploymentJob> Deployments { get; set; } = [];

    public const string DefaultFile = "policy-cache.json";
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(this, Options));

    public static PolicySnapshot? TryLoad(string path) =>
        File.Exists(path) ? JsonSerializer.Deserialize<PolicySnapshot>(File.ReadAllText(path), Options) : null;
}

/// <summary>Builds a <see cref="PolicySnapshot"/> using GET requests only.</summary>
public static class PolicyExtractor
{
    private const string Cfg = "/api/fmc_config/v1/domain/{domain}";

    private static readonly string[] ObjectTypes =
    [
        "hosts", "networks", "networkgroups", "ranges", "fqdns", "protocolportobjects", "portobjectgroups",
        "urls", "urlgroups", "securityzones"
    ];

    public static async Task<PolicySnapshot> FetchAsync(FmcClient fmc, DateTimeOffset since, CancellationToken ct = default)
    {
        var snap = new PolicySnapshot { FetchedAt = DateTimeOffset.Now };

        Console.WriteLine("  access policies + regler ...");
        foreach (var p in await fmc.GetAllItemsAsync($"{Cfg}/policy/accesspolicies", ct))
        {
            var name = Str(p, "name");
            var rules = await fmc.GetAllItemsAsync($"{Cfg}/policy/accesspolicies/{Str(p, "id")}/accessrules", ct);
            snap.Rules.AddRange(rules.Select(r => ParseRule(name, r)));
            snap.Policies.Add(ParsePolicy("Access Control", p, rules.Count));
        }

        foreach (var (type, path) in new[]
                 {
                     ("NAT", "policy/ftdnatpolicies"), ("Prefilter", "policy/prefilterpolicies"),
                     ("Intrusion", "policy/intrusionpolicies"), ("Platform settings", "policy/ftdplatformsettingspolicies")
                 })
        {
            Console.WriteLine($"  {type} policies ...");
            try
            {
                foreach (var p in await fmc.GetAllItemsAsync($"{Cfg}/{path}", ct))
                    snap.Policies.Add(ParsePolicy(type, p, 0));
            }
            catch (InvalidOperationException e) { Console.WriteLine($"    sprunget over: {e.Message.Split('\n')[0]}"); }
        }

        foreach (var type in ObjectTypes)
        {
            Console.WriteLine($"  objekter: {type} ...");
            try
            {
                foreach (var o in await fmc.GetAllItemsAsync($"{Cfg}/object/{type}", ct))
                {
                    var obj = ParseObject(o);
                    if (obj.Modified >= since) snap.ChangedObjects.Add(obj);
                }
            }
            catch (InvalidOperationException e) { Console.WriteLine($"    sprunget over: {e.Message.Split('\n')[0]}"); }
        }

        Console.WriteLine("  deployment-historik ...");
        try
        {
            foreach (var j in await fmc.GetAllItemsAsync($"{Cfg}/deployment/jobhistories", ct))
            {
                var job = ParseJob(j);
                if (job.Start is null || job.Start >= since) snap.Deployments.Add(job);
            }
        }
        catch (InvalidOperationException e) { Console.WriteLine($"    sprunget over: {e.Message.Split('\n')[0]}"); }

        return snap;
    }

    private static PolicyInfo ParsePolicy(string type, JsonElement p, int ruleCount)
    {
        var (user, ts) = Meta(p);
        return new PolicyInfo(type, Str(p, "name"), user, ts, ruleCount);
    }

    private static RuleInfo ParseRule(string policy, JsonElement r)
    {
        var meta = r.TryGetProperty("metadata", out var m) ? m : default;
        var (_, ts) = Meta(r);
        var comments = new List<string>();
        if (r.TryGetProperty("commentHistoryList", out var ch) && ch.ValueKind == JsonValueKind.Array)
            foreach (var c in ch.EnumerateArray())
                comments.Add($"{Str(c, "comment")} ({(c.TryGetProperty("user", out var u) ? Str(u, "name") : "")})");

        return new RuleInfo(
            policy,
            meta.ValueKind == JsonValueKind.Object && meta.TryGetProperty("ruleIndex", out var idx) ? idx.GetInt32() : 0,
            Str(r, "name"),
            meta.ValueKind == JsonValueKind.Object ? Str(meta, "category") : "",
            meta.ValueKind == JsonValueKind.Object ? Str(meta, "section") : "",
            Str(r, "action"),
            !r.TryGetProperty("enabled", out var en) || en.ValueKind != JsonValueKind.False,
            Refs(r, "sourceZones"), Refs(r, "destinationZones"),
            Refs(r, "sourceNetworks"), Refs(r, "destinationNetworks"),
            Refs(r, "destinationPorts"), Refs(r, "applications"),
            r.TryGetProperty("ipsPolicy", out var ips) ? Str(ips, "name") : "",
            ts, comments);
    }

    private static ObjectInfo ParseObject(JsonElement o)
    {
        var (user, ts) = Meta(o);
        var value = Str(o, "value");
        if (value.Length == 0 && Str(o, "port").Length > 0) value = $"{Proto(Str(o, "protocol"))}/{Str(o, "port")}";
        if (value.Length == 0 && Str(o, "url").Length > 0) value = Str(o, "url");
        if (value.Length == 0)
        {
            var members = Refs(o, "objects").Concat(Refs(o, "literals")).ToList();
            if (members.Count > 0) value = $"{members.Count} medlemmer: " + string.Join(", ", members.Take(6)) + (members.Count > 6 ? " …" : "");
        }
        return new ObjectInfo(Str(o, "type"), Str(o, "name"), value, user, ts);
    }

    private static DeploymentJob ParseJob(JsonElement j)
    {
        var devices = new List<DeployedDevice>();
        if (j.TryGetProperty("deviceList", out var dl) && dl.ValueKind == JsonValueKind.Array)
            foreach (var d in dl.EnumerateArray())
                devices.Add(new DeployedDevice(Str(d, "deviceName"), Str(d, "containerName"), Str(d, "deploymentStatus"),
                    d.TryGetProperty("deployedVersion", out var v) && v.TryGetInt32(out var vi) ? vi : null));
        return new DeploymentJob(Str(j, "jobName"), Str(j, "jobStatus"), Date(Str(j, "startTime")), Date(Str(j, "endTime")),
            Str(j, "user"), Str(j, "deploymentNote"), devices);
    }

    private static DateTimeOffset? Date(string s) =>
        DateTimeOffset.TryParse(s, System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d.ToLocalTime() : null;

    private static (string User, DateTimeOffset? Modified) Meta(JsonElement e)
    {
        if (!e.TryGetProperty("metadata", out var m) || m.ValueKind != JsonValueKind.Object) return ("", null);
        var user = m.TryGetProperty("lastUser", out var lu) ? Str(lu, "name") : "";
        DateTimeOffset? ts = m.TryGetProperty("timestamp", out var t) && t.TryGetInt64(out var ms) && ms > 0
            ? DateTimeOffset.FromUnixTimeMilliseconds(ms).ToLocalTime() : null;
        return (user, ts);
    }

    /// <summary>Names from {"objects":[{name}], "literals":[{value}]} style references.</summary>
    private static List<string> Refs(JsonElement e, string prop)
    {
        var list = new List<string>();
        if (!e.TryGetProperty(prop, out var p)) return list;
        if (p.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in p.EnumerateArray())
                list.Add(x.ValueKind == JsonValueKind.Object ? (Str(x, "name") is { Length: > 0 } n ? n : Str(x, "value")) : x.ToString());
            return list;
        }
        if (p.ValueKind != JsonValueKind.Object) return list;
        if (p.TryGetProperty("objects", out var objs) && objs.ValueKind == JsonValueKind.Array)
            list.AddRange(objs.EnumerateArray().Select(o => Str(o, "name")));
        if (p.TryGetProperty("literals", out var lits) && lits.ValueKind == JsonValueKind.Array)
            list.AddRange(lits.EnumerateArray().Select(l =>
                Str(l, "value") is { Length: > 0 } v ? v : $"{Proto(Str(l, "protocol"))}/{Str(l, "port")}".Trim('/')));
        if (p.TryGetProperty("applications", out var apps) && apps.ValueKind == JsonValueKind.Array)
            list.AddRange(apps.EnumerateArray().Select(a => Str(a, "name")));
        return list.Where(x => x.Length > 0).ToList();
    }

    private static string Proto(string p) => p switch { "6" => "TCP", "17" => "UDP", "1" => "ICMP", "58" => "ICMPv6", _ => p };

    private static string Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Null
            ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString()
            : "";
}
