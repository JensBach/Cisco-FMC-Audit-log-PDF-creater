using System.Text.RegularExpressions;

namespace FmcAuditLog;

/// <summary>
/// Consistent pseudonymisation: the same real value always maps to the same fake value,
/// so statistics and charts stay meaningful while people, IPs, devices, objects and the
/// customer name are hidden. Built-in FMC service accounts are kept as-is.
/// </summary>
public sealed partial class Anonymizer
{
    private readonly Dictionary<string, string> _users = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _ips = new();
    private readonly Dictionary<string, string> _objects = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _devices = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _terms;
    private List<(Regex Re, string Fake)> _userPatterns = [];
    private int _userCount;
    private readonly Dictionary<string, string> _policies = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _named = new(StringComparer.OrdinalIgnoreCase);

    // Generic FMC UI vocabulary; path segments made only of these words are kept as-is.
    private static readonly HashSet<string> GenericWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "policies","policy","access","control","intrusion","network","discovery","nat","prefilter","ssl","dns",
        "identity","file","malware","platform","settings","flexconfig","health","monitor","devices","device",
        "management","objects","object","manager","system","configuration","users","user","login","logout",
        "save","saved","deploy","deployment","delete","deleted","create","created","modify","modified","edit","update",
        "updates","updated","add","added","remove","removed","rule","rules","editor","group","groups","port",
        "ports","url","urls","application","applications","filter","filters","list","lists","variable","set","sets",
        "security","zone","zones","interface","interfaces","routing","static","route","vpn","site","to","remote",
        "tools","backup","restore","scheduling","integration","analysis","overview","dashboards","dashboard",
        "reporting","report","reports","audit","log","logs","task","tasks","status","message","center","domain",
        "domains","local","global","default","high","availability","ha","cluster","import","export","ui","page",
        "view","views","copy","lock","unlock","enable","enabled","disable","disabled","and","or","of","the","for",
        "in","on","with","a","an","ldap","realm","realms","certificate","certificates","pki","sla","prefix","time",
        "range","ranges","host","hosts","fqdn","tunnel","geolocation","vlan","tag","tags","community","key",
        "chain","sgt","snmp","syslog","ntp","dhcp","ddns","ospf","bgp","eigrp","rip","multicast","hit","counts",
        "analyzer","threat","defense","defence","ftd","fmc","firepower","secure","firewall","api","rest","explorer",
        "smart","license","licenses","licensing","classic","base","upgrade","install","download","packages",
        "snort","vdb","geodb","sru","lsp","changes","change","pending","preview","history","compare",
        "revision","revisions","category","categories","insert","move","moved","bulk","search","result","results",
        "session","sessions","expired","failed","success","successful","succeeded","attempt","password","account",
        "accounts","role","roles","permissions","external","authentication","authorization","config","configs",
        "general","advanced","inspection","inspector","transport","layer","variables","decryption","attributes",
        "server","servers","service","services","intelligence","director","event","events","alert",
        "alerts","correlation","compliance","context","logging","connection","connections",
        "summary","details","new","entry","entries","item","items","none","any","mode","insights","unified",
        "troubleshooting","administration","extended","standard","map","managed","contextual","cross","launch",
        "templates","template","risk","cli","dap","sso","saml","workflow","expiration","queue","step","packet",
        "tracer","capture","file","files","download","downloads","prefilters","sgt","trustsec","cisco","umbrella",
        "sources","source","threats","feeds","feed","incidents","rule_configs","hitcounts","operational",
    };

    [GeneratedRegex(@"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")]
    private static partial Regex Ipv6Regex();

    [GeneratedRegex(@"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")]
    private static partial Regex EmailRegex();

    [GeneratedRegex(@"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")]
    private static partial Regex UuidRegex();

    [GeneratedRegex(@"[A-Za-z]+")]
    private static partial Regex WordRegex();

    // Device-like names such as HQ01-EDGE-FW; underscores are treated as separators (backup job names).
    [GeneratedRegex(@"(?<![A-Za-z0-9-])[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*-(?:FW|FTD|NGFW|ASA|FPR)\d*(?![A-Za-z0-9-])", RegexOptions.IgnoreCase)]
    private static partial Regex DeviceNameRegex();

    // Free-text tokens mixing letters and digits (object names like PNP-01-A:96213).
    [GeneratedRegex(@"(?<![A-Za-z0-9.:-])[A-Za-z0-9][A-Za-z0-9.:-]*(?<![.:-])")]
    private static partial Regex TokenRegex();

    [GeneratedRegex(@"(?:Policy Deployment to|Device Configuration for|Threat Defen[cs]e(?: HA)? -|device|Device)\s+'?([A-Za-z0-9][A-Za-z0-9_.-]{2,})'?")]
    private static partial Regex DeviceContextRegex();

    [GeneratedRegex(@"^(GET|POST|PUT|DELETE|PATCH)\s+\S+")]
    private static partial Regex ApiRegex();

    public Anonymizer(IEnumerable<string>? extraTerms = null)
    {
        _terms = (extraTerms ?? []).Where(t => !string.IsNullOrWhiteSpace(t)).ToList();
    }

    public List<AuditRecord> Apply(IEnumerable<AuditRecord> records)
    {
        var list = records.ToList();
        Learn(list);

        return list.Select(r => r with
        {
            Username = User(r.Username),
            Source = Text(r.Source),
            Domain = "",
            Subsystem = Path(Text(r.Subsystem)),
            Message = AnonymizeMessage(r.Message),
        }).ToList();
    }

    private void Learn(List<AuditRecord> list)
    {
        var domains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in list)
        {
            if (!Classifier.IsSystemAccount(r.Username)) User(r.Username);
            foreach (Match m in EmailRegex().Matches(r.Username + " " + r.Message))
                domains.Add(m.Value[(m.Value.IndexOf('@') + 1)..]);
            foreach (Match m in DeviceNameRegex().Matches(r.Message + " " + r.Subsystem))
                if (m.Value.Any(char.IsDigit) || m.Value.Count(ch => ch == '-') >= 2) Device(m.Value);
            foreach (Match m in DeviceContextRegex().Matches(r.Message))
            {
                var name = m.Groups[1].Value.TrimEnd('.', '-');
                if (!GenericWords.Contains(name) && name.Any(char.IsLetter)) Device(name);
            }
        }

        // Derive customer name terms from e-mail domains, e.g. "acme1000.dk" -> "acme1000", "acme".
        foreach (var d in domains)
        {
            var label = d.Split('.')[0];
            if (label.Length >= 3) _terms.Add(label);
            var alpha = new string(label.TakeWhile(char.IsLetter).ToArray());
            if (alpha.Length >= 4 && alpha.Length < label.Length) _terms.Add(alpha);
        }
        _terms.Sort((a, b) => b.Length.CompareTo(a.Length));

        _userPatterns = _users
            .OrderByDescending(kv => kv.Key.Length)
            .Select(kv => (new Regex($@"(?<![\w.@-]){Regex.Escape(kv.Key)}(?:@[\w-]+(?:\.[\w-]+)+)?(?![\w@-])",
                RegexOptions.IgnoreCase), kv.Value))
            .ToList();
    }

    /// <summary>Registers policy names so audit messages and the snapshot use the same pseudonyms.</summary>
    public void Register(PolicySnapshot snap)
    {
        foreach (var p in snap.Policies.Select(p => p.Name).Concat(snap.Rules.Select(r => r.Policy)).Distinct())
            if (!_policies.ContainsKey(p) && p.Length > 0 && !BuiltInPolicies.Contains(p))
                _policies[p] = $"Policy-{_policies.Count + 1:D2}";
    }

    private static readonly HashSet<string> BuiltInPolicies = new(StringComparer.OrdinalIgnoreCase)
    {
        "Balanced Security and Connectivity", "Connectivity Over Security", "Security Over Connectivity",
        "Maximum Detection", "No Rules Active", "Default Prefilter Policy", "Blank policy"
    };

    public PolicySnapshot Apply(PolicySnapshot snap)
    {
        Register(snap);
        string Pol(string n) => _policies.GetValueOrDefault(n, n);
        string Net(string n) => Ipv4Regex().IsMatch(n) || n.Contains(':') && Ipv6Regex().IsMatch(n) ? Text(n) : Object(n);
        string Free(string n) => MixedTokens(Text(n));
        string Cat(string n) => n.Length == 0 || IsGeneric(n) ? n : Named("Kategori", n);
        List<string> Map(List<string> l, Func<string, string> f) => l.Select(f).ToList();

        return new PolicySnapshot
        {
            FetchedAt = snap.FetchedAt,
            Policies = snap.Policies.Select(p => p with { Name = Pol(p.Name), LastUser = User(p.LastUser) }).ToList(),
            Rules = snap.Rules.Select(r => r with
            {
                Policy = Pol(r.Policy),
                Name = Named("Rule", $"{r.Policy}\u0001{r.Name}"),
                Category = Cat(r.Category),
                SourceZones = Map(r.SourceZones, z => Named("Zone", z)),
                DestinationZones = Map(r.DestinationZones, z => Named("Zone", z)),
                SourceNetworks = Map(r.SourceNetworks, Net),
                DestinationNetworks = Map(r.DestinationNetworks, Net),
                Ports = Map(r.Ports, Free),
                IpsPolicy = Free(r.IpsPolicy),
                Comments = r.Comments.Count == 0 ? [] : ["(kommentar skjult)"],
            }).ToList(),
            ChangedObjects = snap.ChangedObjects.Select(o => o with
            {
                Name = o.Type.Equals("SecurityZone", StringComparison.OrdinalIgnoreCase) ? Named("Zone", o.Name) : Object(o.Name),
                Value = AnonymizeValue(o.Value),
                LastUser = User(o.LastUser),
            }).ToList(),
            Deployments = snap.Deployments.Select(j => j with
            {
                Name = Free(j.Name),
                User = User(j.User),
                Note = Free(j.Note),
                Devices = j.Devices.Select(dv => dv with { Device = Device(dv.Device), Container = dv.Container.Length == 0 ? "" : Device(dv.Container) }).ToList(),
            }).ToList(),
        };
    }

    private string AnonymizeValue(string v)
    {
        var colon = v.IndexOf(" medlemmer: ", StringComparison.Ordinal);
        if (colon < 0) return Text(v).Contains("://") ? "https://www.example.com/" : MixedTokens(Text(v));
        var head = v[..(colon + 12)];
        var members = v[(colon + 12)..].TrimEnd(' ', '…').Split(", ")
            .Select(m => Ipv4Regex().IsMatch(m) ? Text(m) : Object(m));
        return head + string.Join(", ", members) + (v.EndsWith('…') ? " …" : "");
    }

    private string Named(string kind, string real)
    {
        var key = kind + "\u0002" + real;
        if (!_named.TryGetValue(key, out var fake))
            _named[key] = fake = $"{kind}-{_named.Keys.Count(k => k.StartsWith(kind + "\u0002")) + 1:D2}";
        return fake;
    }

    private string User(string name)
    {
        if (Classifier.IsSystemAccount(name)) return name;
        var key = name.Contains('@') ? name[..name.IndexOf('@')] : name;
        if (!_users.TryGetValue(key, out var fake))
        {
            var i = _userCount++;
            fake = $"user-{(char)('A' + i % 26)}{(i >= 26 ? (i / 26).ToString() : "")}";
            _users[key] = fake;
        }
        return fake;
    }

    private string Device(string name)
    {
        if (!_devices.TryGetValue(name, out var fake))
            _devices[name] = fake = $"FW-{_devices.Count + 1:D2}";
        return fake;
    }

    private string Ip(string ip)
    {
        if (!_ips.TryGetValue(ip, out var fake))
        {
            var n = _ips.Count + 1;
            var suffix = ip.Contains('/') ? ip[ip.IndexOf('/')..] : "";
            // RFC 5737 documentation ranges.
            fake = n <= 254 ? $"192.0.2.{n}{suffix}" : $"198.51.100.{(n - 255) % 254 + 1}{suffix}";
            _ips[ip] = fake;
        }
        return fake;
    }

    private string Object(string name)
    {
        if (!_objects.TryGetValue(name, out var fake))
            _objects[name] = fake = $"Object-{_objects.Count + 1:D3}";
        return fake;
    }

    private string AnonymizeMessage(string msg)
    {
        if (ApiRegex().IsMatch(msg))
        {
            // Query strings may contain object names/filters; drop them.
            var q = msg.IndexOf('?');
            if (q >= 0)
            {
                var end = msg.IndexOf(' ', q);
                msg = msg[..q] + (end >= 0 ? msg[end..] : "");
            }
            return Text(msg);
        }
        msg = Text(msg);
        return msg.Contains(" > ") ? Path(msg) : MixedTokens(msg);
    }

    private static readonly string[] PublicPrefixes = ["VDB-", "CVE-", "SRU-", "LSP-", "TLS", "SSL", "IPv", "HTTP", "SHA", "MD5", "X509"];

    private string MixedTokens(string s) => TokenRegex().Replace(s, m =>
    {
        var t = m.Value;
        if (!t.Any(char.IsLetter) || !t.Any(char.IsDigit) || IsPseudonym(t) ||
            PublicPrefixes.Any(p => t.StartsWith(p, StringComparison.OrdinalIgnoreCase)))
            return t;
        return Object(t);
    });

    private string Text(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        // Short names (e.g. "ADM", "test") are too ambiguous for free-text replacement.
        foreach (var (real, fake) in _policies.Where(kv => kv.Key.Length >= 6).OrderByDescending(kv => kv.Key.Length))
            s = Regex.Replace(s, $@"(?<![\w-]){Regex.Escape(real)}(?![\w-])", fake, RegexOptions.IgnoreCase);
        foreach (var (re, fake) in _userPatterns) s = re.Replace(s, fake);
        s = EmailRegex().Replace(s, _ => "user@example.com");
        foreach (var (real, fake) in _devices.OrderByDescending(kv => kv.Key.Length))
            s = Regex.Replace(s, $@"(?<![A-Za-z0-9-]){Regex.Escape(real)}(?![A-Za-z0-9-])", fake, RegexOptions.IgnoreCase);
        s = UuidRegex().Replace(s, "00000000-0000-0000-0000-000000000000");
        s = Ipv4Regex().Replace(s, m => Ip(m.Value));
        s = Ipv6Regex().Replace(s, m => Ip(m.Value));
        foreach (var term in _terms)
            s = Regex.Replace(s, Regex.Escape(term), "Kunde", RegexOptions.IgnoreCase);
        return s;
    }

    private string Path(string path)
    {
        if (!path.Contains('>')) return MixedTokens(path);
        var segments = path.Split('>');
        for (var i = 0; i < segments.Length; i++)
        {
            var seg = segments[i];
            var trimmed = seg.Trim();
            if (trimmed.Length == 0 || IsGeneric(trimmed)) continue;
            var lead = seg[..(seg.Length - seg.TrimStart().Length)];
            var trail = seg[seg.TrimEnd().Length..];
            segments[i] = lead + AnonymizeSegment(trimmed) + trail;
        }
        return string.Join('>', segments);
    }

    private string AnonymizeSegment(string seg)
    {
        // Keep leading generic words ("Save Policy XYZ" -> "Save Policy Object-001").
        var words = seg.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var keep = 0;
        while (keep < words.Length && IsGeneric(words[keep])) keep++;
        if (keep == words.Length) return seg;
        var prefix = string.Join(' ', words[..keep]);
        return (prefix.Length > 0 ? prefix + " " : "") + Object(string.Join(' ', words[keep..]));
    }

    private static bool IsPseudonym(string t) =>
        t.StartsWith("user-") || t.StartsWith("Object-") || t.StartsWith("Policy-") || t.StartsWith("Rule-") ||
        t.StartsWith("Zone-") || t.StartsWith("Kategori-") || t.StartsWith("FW-") || t.StartsWith("192.0.2.") ||
        t.StartsWith("198.51.100.") || t.StartsWith("/") || Classifier.SystemAccounts.Contains(t);

    private static bool IsGeneric(string text)
    {
        if (IsPseudonym(text)) return true;
        // Tokens mixing letters and digits (Host-51, test2) are treated as customer object names.
        if (text.Split(' ').Any(t => t.Any(char.IsLetter) && t.Any(char.IsDigit))) return false;
        var words = WordRegex().Matches(text).Select(m => m.Value).ToList();
        return words.Count == 0 || words.All(GenericWords.Contains);
    }
}
