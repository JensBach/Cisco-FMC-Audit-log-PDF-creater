using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Configuration.UserSecrets;

namespace FmcAuditLog;

/// <summary>
/// Moves the clear-text .password file into the .NET user-secrets store and deletes the file.
/// </summary>
public static class SecretsImporter
{
    public static int Import(string? explicitPath)
    {
        var file = explicitPath ?? FindPasswordFile();
        if (file is null || !File.Exists(file))
        {
            Console.Error.WriteLine("Kunne ikke finde .password filen.");
            return 1;
        }

        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in File.ReadAllLines(file))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith("---")) continue;
            var idx = line.IndexOf(':');
            if (idx <= 0) continue;
            values[line[..idx].Trim()] = line[(idx + 1)..].Trim();
        }

        foreach (var key in new[] { "host", "username", "password" })
        {
            if (!values.ContainsKey(key))
            {
                Console.Error.WriteLine($"Mangler '{key}' i {file}");
                return 1;
            }
        }

        var id = typeof(SecretsImporter).Assembly.GetCustomAttribute<UserSecretsIdAttribute>()!.UserSecretsId;
        var secretsPath = PathHelper.GetSecretsPathFromSecretsId(id);
        Directory.CreateDirectory(Path.GetDirectoryName(secretsPath)!);

        var json = File.Exists(secretsPath)
            ? JsonNode.Parse(File.ReadAllText(secretsPath)) as JsonObject ?? new JsonObject()
            : new JsonObject();
        json["Fmc:Host"] = values["host"];
        json["Fmc:Username"] = values["username"];
        json["Fmc:Password"] = values["password"];
        File.WriteAllText(secretsPath, json.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(secretsPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        // Overwrite before delete so the clear-text content does not linger.
        var len = new FileInfo(file).Length;
        File.WriteAllBytes(file, new byte[len]);
        File.Delete(file);

        Console.WriteLine($"Credentials gemt i user-secrets ({secretsPath}).");
        Console.WriteLine($"Clear-text fil slettet: {file}");
        return 0;
    }

    private static string? FindPasswordFile()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            var dir = new DirectoryInfo(start);
            while (dir is not null)
            {
                var candidate = Path.Combine(dir.FullName, ".password");
                if (File.Exists(candidate)) return candidate;
                dir = dir.Parent;
            }
        }
        return null;
    }
}
