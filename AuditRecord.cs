namespace FmcAuditLog;

public sealed record AuditRecord(
    DateTimeOffset Time,
    string Username,
    string Subsystem,
    string Message,
    string Source,
    string Domain)
{
    public string Id { get; init; } = "";
}
