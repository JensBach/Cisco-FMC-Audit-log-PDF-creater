using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace FmcAuditLog;

/// <summary>
/// Read-only FMC client. The only non-GET call is the token generation/revocation,
/// which does not change any configuration on the FMC.
/// </summary>
public sealed class FmcClient : IDisposable
{
    private const int PageSize = 1000;
    private readonly HttpClient _http;
    private readonly string _username;
    private readonly string _password;
    private string? _token;
    private string? _domainUuid;

    public FmcClient(string host, string username, string password, bool ignoreCertificate)
    {
        _username = username;
        _password = password;
        var handler = new HttpClientHandler();
        if (ignoreCertificate)
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        _http = new HttpClient(handler)
        {
            BaseAddress = new Uri(host.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? host : $"https://{host}"),
            Timeout = TimeSpan.FromMinutes(2)
        };
    }

    public string? DomainUuid => _domainUuid;

    /// <summary>When set, raw JSON pages are written to this directory for troubleshooting.</summary>
    public string? DumpDirectory { get; set; }

    public async Task AuthenticateAsync(CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, "/api/fmc_platform/v1/auth/generatetoken");
        req.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_username}:{_password}")));
        using var resp = await _http.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException($"Login fejlede: {(int)resp.StatusCode} {resp.ReasonPhrase}");

        _token = resp.Headers.GetValues("X-auth-access-token").First();
        _domainUuid = resp.Headers.TryGetValues("DOMAIN_UUID", out var d) ? d.First() : null;
        if (_domainUuid is null)
            throw new InvalidOperationException("FMC returnerede ikke DOMAIN_UUID header.");
    }

    public async Task<List<AuditRecord>> GetAuditRecordsAsync(DateTimeOffset start, string? subsystem,
        string? domainUuid = null, CancellationToken ct = default)
    {
        if (_token is null) await AuthenticateAsync(ct);
        var domain = domainUuid ?? _domainUuid!;
        var startSec = start.ToUnixTimeSeconds();
        var byId = new Dictionary<string, AuditRecord>();
        long? endSec = null;
        var page = 0;

        // FMC caps each query at a fixed number of the newest records, so walk backwards
        // in time using endtime until we pass the requested start time.
        while (true)
        {
            var batch = new List<(AuditRecord Rec, long Sec)>();
            var offset = 0;
            while (true)
            {
                var url = $"/api/fmc_platform/v1/domain/{domain}/audit/auditrecords" +
                          $"?offset={offset}&limit={PageSize}&starttime={startSec}&expanded=true";
                if (endSec is not null) url += $"&endtime={endSec}";
                if (!string.IsNullOrWhiteSpace(subsystem))
                    url += $"&subsystem={Uri.EscapeDataString(subsystem)}";

                using var doc = await GetJsonAsync(url, ct);
                var root = doc.RootElement;
                if (DumpDirectory is not null)
                {
                    Directory.CreateDirectory(DumpDirectory);
                    await File.WriteAllTextAsync(Path.Combine(DumpDirectory, $"auditrecords-{page++:D4}.json"), root.GetRawText(), ct);
                }

                var count = 0;
                if (root.TryGetProperty("items", out var items))
                    foreach (var item in items.EnumerateArray())
                    {
                        batch.Add(Parse(item));
                        count++;
                    }

                var total = root.TryGetProperty("paging", out var paging) && paging.TryGetProperty("count", out var c)
                    ? c.GetInt32() : count;
                offset += count;
                if (count == 0 || offset >= total) break;
            }

            var added = 0;
            foreach (var (rec, _) in batch)
                if (byId.TryAdd(rec.Id, rec)) added++;
            Console.WriteLine($"  hentet {byId.Count} records (ned til {(batch.Count > 0 ? DateTimeOffset.FromUnixTimeSeconds(batch.Min(b => b.Sec)).ToLocalTime().ToString("yyyy-MM-dd HH:mm") : "-")})");

            if (batch.Count == 0) break;
            var oldest = batch.Min(b => b.Sec);
            if (oldest <= startSec) break;
            // Records sharing the oldest second may be cut off; re-query including it, dedupe handles overlap.
            var next = added == 0 ? oldest - 1 : oldest;
            if (endSec is not null && next >= endSec) next = endSec.Value - 1;
            endSec = next;
        }

        return byId.Values.OrderBy(r => r.Time).ToList();
    }

    /// <summary>Read-only GET of a config API path; "{domain}" is replaced with the domain UUID.</summary>
    public async Task<JsonDocument> GetAsync(string path, CancellationToken ct = default)
    {
        if (_token is null) await AuthenticateAsync(ct);
        return await GetJsonAsync(path.Replace("{domain}", _domainUuid), ct);
    }

    /// <summary>GETs all pages of a collection with expanded=true.</summary>
    public async Task<List<JsonElement>> GetAllItemsAsync(string path, CancellationToken ct = default)
    {
        var result = new List<JsonElement>();
        var offset = 0;
        while (true)
        {
            var sep = path.Contains('?') ? '&' : '?';
            using var doc = await GetAsync($"{path}{sep}offset={offset}&limit={PageSize}&expanded=true", ct);
            var root = doc.RootElement;
            var count = 0;
            if (root.TryGetProperty("items", out var items))
                foreach (var item in items.EnumerateArray())
                {
                    result.Add(item.Clone());
                    count++;
                }
            var total = root.TryGetProperty("paging", out var paging) && paging.TryGetProperty("count", out var c)
                ? c.GetInt32() : count;
            offset += count;
            if (count == 0 || offset >= total) return result;
        }
    }

    private async Task<JsonDocument> GetJsonAsync(string url, CancellationToken ct)
    {
        for (var attempt = 1; ; attempt++)
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Add("X-auth-access-token", _token);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var resp = await _http.SendAsync(req, ct);

            if (resp.StatusCode == HttpStatusCode.TooManyRequests && attempt <= 5)
            {
                // FMC is rate limited to 120 requests/minute.
                await Task.Delay(TimeSpan.FromSeconds(10 * attempt), ct);
                continue;
            }
            if (resp.StatusCode == HttpStatusCode.Unauthorized && attempt <= 2)
            {
                await AuthenticateAsync(ct);
                continue;
            }
            if (!resp.IsSuccessStatusCode)
            {
                var body = await resp.Content.ReadAsStringAsync(ct);
                throw new InvalidOperationException($"GET {url} fejlede: {(int)resp.StatusCode} {body}");
            }
            return await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        }
    }

    internal static (AuditRecord, long) Parse(JsonElement e)
    {
        JsonElement? P(string name)
        {
            foreach (var p in e.EnumerateObject())
                if (p.NameEquals(name) || string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))
                    return p.Value.ValueKind == JsonValueKind.Null ? null : p.Value;
            return null;
        }
        string S(string name) => P(name) is { } v
            ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString()
            : "";

        long sec = 0;
        if (P("time") is { } t)
        {
            if (t.ValueKind == JsonValueKind.Number && t.TryGetInt64(out var n)) sec = n;
            else if (t.ValueKind == JsonValueKind.String && long.TryParse(t.GetString(), out var ns)) sec = ns;
            if (sec > 100_000_000_000) sec /= 1000;
        }

        var domain = S("domain");
        if (P("domain") is { ValueKind: JsonValueKind.Object } dEl)
            domain = dEl.TryGetProperty("name", out var dn) ? dn.GetString() ?? "" : "";

        var id = S("auditId");
        if (id.Length == 0) id = $"{sec}|{S("username")}|{S("message")}";

        var rec = new AuditRecord(DateTimeOffset.FromUnixTimeSeconds(sec).ToLocalTime(), S("username"),
            S("subsystem"), S("message"), S("source"), domain) { Id = id };
        return (rec, sec);
    }

    public void Dispose() => _http.Dispose();
}
