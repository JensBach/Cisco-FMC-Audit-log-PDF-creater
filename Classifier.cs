using System.Text.RegularExpressions;

namespace FmcAuditLog;

public enum Category
{
    Config,
    Deploy,
    ApiChange,
    Security,
    Login,
    System,
    Navigation,
    ApiRead,
}

public static partial class Classifier
{
    // Built-in FMC service accounts; they are not people and are kept as-is when anonymizing.
    public static readonly HashSet<string> SystemAccounts = new(StringComparer.OrdinalIgnoreCase)
    {
        "@ANUBIS:system-user", "internaladmin", "csm_processes", "System", "Default User", "admin",
        LocalSystem, SamlPrelogin
    };

    public const string LocalSystem = "Local System";
    public const string SamlPrelogin = "SAML Prelogin";

    /// <summary>FMC logs both scheduled tasks and unauthenticated SAML steps as "Default User"; split them.</summary>
    public static AuditRecord RenameDefaultUser(AuditRecord r)
    {
        if (r.Source.Contains("Default User", StringComparison.OrdinalIgnoreCase))
            r = r with { Source = r.Source.Replace("Default User", LocalSystem, StringComparison.OrdinalIgnoreCase) };
        if (!r.Username.Equals("Default User", StringComparison.OrdinalIgnoreCase)) return r;
        var saml = r.Subsystem.Equals("SSO", StringComparison.OrdinalIgnoreCase) ||
                   r.Message.Contains("SAML", StringComparison.OrdinalIgnoreCase);
        return r with { Username = saml ? SamlPrelogin : LocalSystem };
    }

    public static bool IsSystemAccount(string user) => string.IsNullOrWhiteSpace(user) || SystemAccounts.Contains(user);

    public static string Label(Category c) => c switch
    {
        Category.Config => "Konfiguration",
        Category.Deploy => "Deployment",
        Category.ApiChange => "API-ændring",
        Category.Security => "Sikkerhed",
        Category.Login => "Login/session",
        Category.System => "Drift/system",
        Category.Navigation => "Navigation",
        Category.ApiRead => "API-læsning",
        _ => c.ToString()
    };

    public static string Color(Category c) => c switch
    {
        Category.Config => "#E2231A",
        Category.Deploy => "#F26B1D",
        Category.ApiChange => "#FBAB18",
        Category.Security => "#7B1FA2",
        Category.Login => "#6CC04A",
        Category.System => "#0D274D",
        Category.Navigation => "#00BCEB",
        Category.ApiRead => "#90A4AE",
        _ => "#888888"
    };

    public static bool IsChange(Category c) => c is Category.Config or Category.Deploy or Category.ApiChange;

    [GeneratedRegex(@"^(GET|POST|PUT|DELETE|PATCH)\s+(\S+)")]
    private static partial Regex ApiRegex();

    [GeneratedRegex(@"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")]
    private static partial Regex UuidRegex();

    public static Category Classify(AuditRecord r)
    {
        var msg = r.Message;
        var sub = r.Subsystem;
        var api = ApiRegex().Match(msg);
        if (api.Success)
            return api.Groups[1].Value == "GET" ? Category.ApiRead : Category.ApiChange;

        if (msg.Contains("Login Failed", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("Authentication Failed", StringComparison.OrdinalIgnoreCase))
            return Category.Security;

        if (sub is "Login" or "Logout" or "SSO" or "Session Expiration" ||
            msg.StartsWith("Login", StringComparison.OrdinalIgnoreCase) ||
            msg.StartsWith("Logout", StringComparison.OrdinalIgnoreCase))
            return Category.Login;

        if (msg.Equals("Page View", StringComparison.OrdinalIgnoreCase) ||
            sub.StartsWith("Contextual Cross-launch", StringComparison.OrdinalIgnoreCase))
            return Category.Navigation;

        if (msg.Contains("deploy", StringComparison.OrdinalIgnoreCase) ||
            sub.StartsWith("Deploy", StringComparison.OrdinalIgnoreCase))
            return Category.Deploy;

        if (sub is "Task Queue" or "Rule Update Install" or "SRU Install" or "VDB Install" or "GeoDB Install" ||
            sub.Contains("Backup", StringComparison.OrdinalIgnoreCase) ||
            msg.Equals("Generate Report", StringComparison.OrdinalIgnoreCase) ||
            msg.StartsWith("Exported Policy", StringComparison.OrdinalIgnoreCase))
            return Category.System;

        return Category.Config;
    }

    /// <summary>"GET /api/.../object/hosts" with ids and query removed, for grouping API traffic.</summary>
    public static (string Method, string Endpoint) ApiEndpoint(string message)
    {
        var m = ApiRegex().Match(message);
        if (!m.Success) return ("", message);
        var url = System.Text.RegularExpressions.Regex.Replace(m.Groups[2].Value, @"^https?://[^/]+", "");
        var q = url.IndexOf('?');
        if (q >= 0) url = url[..q];
        url = UuidRegex().Replace(url, "{id}");
        url = url.Replace("/api/local/", "/api/");
        return (m.Groups[1].Value, url);
    }
}
