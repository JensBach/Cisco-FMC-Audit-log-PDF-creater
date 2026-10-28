using System.Text.Json;

namespace FmcAuditLog;

/// <summary>Local JSON cache of fetched audit records so the PDF can be iterated on without hitting the FMC.</summary>
public static class AuditCache
{
    public const string DefaultFile = "auditlog-cache.json";

    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static void Save(IEnumerable<AuditRecord> records, string path) =>
        File.WriteAllText(path, JsonSerializer.Serialize(records.OrderBy(r => r.Time).ToList(), Options));

    public static List<AuditRecord> Load(string path) =>
        JsonSerializer.Deserialize<List<AuditRecord>>(File.ReadAllText(path), Options) ?? [];

    public static List<AuditRecord> LoadDump(string dir)
    {
        var byId = new Dictionary<string, AuditRecord>();
        foreach (var file in Directory.GetFiles(dir, "auditrecords-*.json"))
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(file));
            if (!doc.RootElement.TryGetProperty("items", out var items)) continue;
            foreach (var item in items.EnumerateArray())
            {
                var (rec, _) = FmcClient.Parse(item);
                byId.TryAdd(rec.Id, rec);
            }
        }
        return byId.Values.OrderBy(r => r.Time).ToList();
    }
}
