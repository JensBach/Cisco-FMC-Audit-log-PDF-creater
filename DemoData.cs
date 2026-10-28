namespace FmcAuditLog;

/// <summary>Realistic-looking sample data for testing the report layout without an FMC.</summary>
public static class DemoData
{
    public static List<AuditRecord> Generate(DateTimeOffset from, DateTimeOffset to)
    {
        var rnd = new Random(42);
        string[] users = ["api-user", "admin", "mhansen", "lpetersen", "soc-automation"];
        string[] policies = ["ACP-Datacenter", "ACP-Branch-Offices", "IPS-Balanced-Custom", "NAT-Internet-Edge"];
        string[] templates =
        [
            "Policies > Access Control > Access Control Policy > {0} > Save",
            "Policies > Access Control > Access Control Policy > {0} > Rule Editor > Add Rule",
            "Policies > Access Control > Intrusion > {0} > Save",
            "Policies > NAT > {0} > Save",
            "Deploy > Deployment > FTD-{1} > Deploy",
            "Objects > Object Management > Network > Host-{2} > Edit",
            "System > Users > Login",
            "System > Users > Logout",
        ];

        var list = new List<AuditRecord>();
        var span = (to - from).TotalSeconds;
        for (var i = 0; i < 420; i++)
        {
            var t = from.AddSeconds(rnd.NextDouble() * span);
            // Push most events into working hours.
            if (rnd.NextDouble() < 0.8) t = new DateTimeOffset(t.Date.AddHours(7 + rnd.Next(10)).AddMinutes(rnd.Next(60)), t.Offset);
            var tpl = templates[rnd.Next(templates.Length)];
            var msg = string.Format(tpl, policies[rnd.Next(policies.Length)], rnd.Next(1, 5), rnd.Next(10, 99));
            var subsystem = msg.Split(" > ")[0] switch { "Deploy" => "Deployment", var s => s };
            list.Add(new AuditRecord(t, users[rnd.Next(users.Length)], subsystem, msg,
                $"10.16.{rnd.Next(1, 4)}.{rnd.Next(10, 200)}", "Global"));
        }
        return list.OrderBy(r => r.Time).ToList();
    }
}
