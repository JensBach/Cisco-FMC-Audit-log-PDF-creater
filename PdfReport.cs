using System.Globalization;
using System.Text;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace FmcAuditLog;

public sealed class ReportOptions
{
    public required string Title { get; init; }
    public required string FmcName { get; init; }
    public required DateTimeOffset From { get; init; }
    public required DateTimeOffset To { get; init; }
    public string? Subsystem { get; init; }
    public bool Anonymized { get; init; }
    public IReadOnlyList<string> ExcludedUsers { get; init; } = [];
    public int ExcludedCount { get; init; }
    public PolicySnapshot? Policy { get; init; }
}

public static partial class PdfReport
{
    private const string Primary = "#049FD9"; // Cisco blue
    private const string Dark = "#0D274D";
    private const string Zebra = "#F3F7FB";
    private static readonly string[] Palette =
        ["#049FD9", "#0D274D", "#6CC04A", "#FBAB18", "#E2231A", "#7B61FF", "#00BCEB", "#8E9AAF", "#F26B1D", "#2EC4B6"];

    private static readonly CultureInfo Da = CultureInfo.GetCultureInfo("da-DK");

    private const int MinApiCallsForAppendix = 20;

    private sealed record Item(AuditRecord R, Category C);

    public static void Generate(IReadOnlyList<AuditRecord> records, ReportOptions opt, string path)
    {
        QuestPDF.Settings.License = LicenseType.Community;
        var items = records.Select(r => new Item(r, Classifier.Classify(r))).OrderBy(i => i.R.Time).ToList();

        Document.Create(doc =>
        {
            doc.Page(page =>
            {
                Setup(page, opt, landscape: false);
                page.Content().PaddingTop(10).Element(c => Overview(c, items, opt));
            });
            doc.Page(page =>
            {
                Setup(page, opt, landscape: true);
                page.Content().PaddingTop(8).Element(c => ChangesSection(c, items));
            });
            doc.Page(page =>
            {
                Setup(page, opt, landscape: true);
                page.Content().PaddingTop(8).Element(c => LoginSection(c, items));
            });
            doc.Page(page =>
            {
                Setup(page, opt, landscape: true);
                page.Content().PaddingTop(8).Element(c => OperationsSection(c, items));
            });
            if (opt.Policy is not null) PolicySections(doc, opt.Policy, items, opt);
            if (items.Count(i => i.C is Category.ApiRead or Category.ApiChange) >= MinApiCallsForAppendix)
                doc.Page(page =>
                {
                    Setup(page, opt, landscape: true);
                    page.Content().PaddingTop(8).Element(c => ApiSection(c, items));
                });
        }).GeneratePdf(path);
    }

    private static void Setup(PageDescriptor page, ReportOptions opt, bool landscape)
    {
        page.Size(landscape ? PageSizes.A4.Landscape() : PageSizes.A4);
        page.Margin(landscape ? 24 : 28);
        page.DefaultTextStyle(x => x.FontSize(landscape ? 7.5f : 9).FontColor(Colors.Grey.Darken4));
        page.Header().Element(h => Header(h, opt));
        page.Footer().Element(f => Footer(f));
    }

    // ---------- Sections ----------

    private static void Overview(IContainer c, List<Item> items, ReportOptions opt)
    {
        var human = items.Where(i => i.C != Category.ApiRead).ToList();
        var apiReads = items.Count - human.Count;
        var people = human.Where(i => !Classifier.IsSystemAccount(i.R.Username)).ToList();

        var byCategory = Enum.GetValues<Category>().Where(cat => cat != Category.ApiRead)
            .Select(cat => (Classifier.Label(cat), human.Count(i => i.C == cat), Classifier.Color(cat)))
            .Where(x => x.Item2 > 0).ToList();
        var byPerson = Top(people.GroupBy(i => Blank(i.R.Username)).Select(g => (g.Key, g.Count())), 8);
        var changesByUser = Top(items.Where(i => Classifier.IsChange(i.C))
            .GroupBy(i => Blank(i.R.Username)).Select(g => (g.Key, g.Count())), 8);
        var byHour = Enumerable.Range(0, 24).Select(h => (h, people.Count(i => i.R.Time.Hour == h))).ToList();

        c.Column(col =>
        {
            col.Spacing(12);
            col.Item().Row(row =>
            {
                row.Spacing(8);
                Kpi(row.RelativeItem(), "Hændelser i alt", items.Count.ToString("N0", Da), Primary);
                Kpi(row.RelativeItem(), "Ændringer", items.Count(i => i.C is Category.Config or Category.ApiChange).ToString("N0", Da),
                    Classifier.Color(Category.Config));
                Kpi(row.RelativeItem(), "Deployments", items.Count(i => i.C == Category.Deploy).ToString("N0", Da),
                    Classifier.Color(Category.Deploy));
                Kpi(row.RelativeItem(), "Sikkerhed", items.Count(i => i.C == Category.Security).ToString("N0", Da),
                    Classifier.Color(Category.Security));
                Kpi(row.RelativeItem(), "Aktive personer", people.Select(i => i.R.Username).Distinct().Count().ToString(),
                    Classifier.Color(Category.Login));
            });

            col.Item().Row(row =>
            {
                row.Spacing(12);
                row.RelativeItem().Element(x => Card(x, "Fordeling pr. kategori (ekskl. API-læsning)", b => Donut(b, byCategory)));
                row.RelativeItem().Element(x => Card(x, "Mest aktive personer", b => BarChart(b, byPerson)));
            });

            col.Item().Element(x => Card(x, "Aktivitet pr. dag (ekskl. automatiske API-læsninger)",
                b => StackedDays(b, human)));

            col.Item().Row(row =>
            {
                row.Spacing(12);
                row.RelativeItem().Element(x => Card(x, "Personers aktivitet pr. time", b => HourChart(b, byHour)));
                row.RelativeItem().Element(x => Card(x, "Ændringer & deployments pr. bruger", b => BarChart(b, changesByUser)));
            });

            if (apiReads > 0 || opt.ExcludedCount > 0)
                col.Item().Background("#EEF6FB").BorderLeft(3).BorderColor(Primary).Padding(8).Text(t =>
                {
                    if (opt.ExcludedCount > 0)
                    {
                        t.Span($"{opt.ExcludedCount:N0} ").Bold();
                        t.Span($"hændelser fra interne systemkonti ({string.Join(", ", opt.ExcludedUsers)}) er udeladt af rapporten. ");
                    }
                    if (apiReads > 0)
                    {
                        t.Span($"{apiReads:N0} ").Bold();
                        var apiTotal = items.Count(i => i.C is Category.ApiRead or Category.ApiChange);
                        t.Span(apiTotal >= MinApiCallsForAppendix
                            ? "automatiske API-læsninger (GET) er opsummeret i bilaget \"API-trafik\"."
                            : "API-læsninger (GET) i perioden.");
                    }
                });
        });
    }

    private static void ChangesSection(IContainer c, List<Item> items)
    {
        var personal = items.Where(i => i.C is Category.Config or Category.ApiChange && !Classifier.IsSystemAccount(i.R.Username))
            .OrderByDescending(i => i.R.Time).ToList();
        var deployments = items.Where(i => i.R.Message.StartsWith("Policy Deployment to", StringComparison.OrdinalIgnoreCase)
                                           || (i.C == Category.Deploy && !i.R.Message.StartsWith("Successful task completion", StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(i => i.R.Time).ToList();
        var deploySet = deployments.ToHashSet();
        var automatic = items.Where(i => i.C is Category.Config or Category.ApiChange && Classifier.IsSystemAccount(i.R.Username)
                                         && !deploySet.Contains(i))
            .GroupBy(i => (i.R.Username, i.C, Msg: Normalize(i.C == Category.ApiChange ? ApiShort(i.R.Message) : i.R.Message)))
            .Select(g => (g.Key.Username, g.Key.C, g.Key.Msg, Count: g.Count(), First: g.Min(i => i.R.Time), Last: g.Max(i => i.R.Time)))
            .OrderByDescending(x => x.Count).ToList();

        c.Column(col =>
        {
            SectionTitle(col, "Ændringer foretaget af personer",
                $"{personal.Count:N0} ændringer af konfiguration og policies udført af navngivne brugere (deployments: se næste afsnit).");
            if (personal.Count == 0) col.Item().Text("Ingen ændringer foretaget af personer i perioden.").Italic();
            else
                col.Item().Table(t =>
                {
                    t.ColumnsDefinition(cols =>
                    {
                        cols.ConstantColumn(88);
                        cols.ConstantColumn(105);
                        cols.ConstantColumn(66);
                        cols.RelativeColumn(2);
                        cols.RelativeColumn(4);
                    });
                    TableHeader(t, "Tidspunkt", "Bruger", "Kategori", "Subsystem", "Hændelse");
                    var n = 0;
                    foreach (var i in personal)
                    {
                        var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                        var msg = i.C == Category.ApiChange ? ApiShort(i.R.Message) : i.R.Message;
                        t.Cell().Background(bg).Padding(3).Text(Time(i.R.Time));
                        t.Cell().Background(bg).Padding(3).Text(i.R.Username).SemiBold();
                        t.Cell().Background(bg).Padding(3).Element(x => Pill(x, i.C));
                        t.Cell().Background(bg).Padding(3).Text(i.R.Subsystem);
                        t.Cell().Background(bg).Padding(3).Text(msg);
                    }
                });

            col.Item().PageBreak();
            SectionTitle(col, "Deployments", $"{deployments.Count:N0} udrulninger af policies til enheder.");
            if (deployments.Count == 0) col.Item().Text("Ingen deployments i perioden.").Italic();
            else
            {
                var perDevice = Top(deployments.GroupBy(i => DeployTarget(i.R.Message)).Select(g => (g.Key, g.Count())), 8);
                col.Item().Width(380).Element(x => Card(x, "Deployments pr. enhed", b => BarChart(b, perDevice)));
                col.Item().PaddingTop(8).Table(t =>
                {
                    t.ColumnsDefinition(cols =>
                    {
                        cols.ConstantColumn(88);
                        cols.ConstantColumn(105);
                        cols.RelativeColumn(2);
                        cols.RelativeColumn(4);
                    });
                    TableHeader(t, "Tidspunkt", "Bruger", "Subsystem", "Hændelse");
                    var n = 0;
                    foreach (var i in deployments)
                    {
                        var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                        var ok = i.R.Message.Contains("SUCCESS", StringComparison.OrdinalIgnoreCase);
                        var failed = i.R.Message.Contains("FAIL", StringComparison.OrdinalIgnoreCase);
                        t.Cell().Background(bg).Padding(3).Text(Time(i.R.Time));
                        t.Cell().Background(bg).Padding(3).Text(i.R.Username).SemiBold();
                        t.Cell().Background(bg).Padding(3).Text(i.R.Subsystem);
                        t.Cell().Background(bg).Padding(3).Text(i.R.Message)
                            .FontColor(failed ? "#E2231A" : ok ? "#2E7D32" : Colors.Grey.Darken4);
                    }
                });
            }

            col.Item().PageBreak();
            SectionTitle(col, "Automatiske ændringer (systemkonti)",
                "Ændringer udført af FMC'ens interne konti og integrationer, grupperet efter type.");
            if (automatic.Count == 0) { col.Item().Text("Ingen automatiske ændringer.").Italic(); return; }
            col.Item().Table(t =>
            {
                t.ColumnsDefinition(cols =>
                {
                    cols.ConstantColumn(105);
                    cols.ConstantColumn(66);
                    cols.RelativeColumn(5);
                    cols.ConstantColumn(45);
                    cols.ConstantColumn(88);
                    cols.ConstantColumn(88);
                });
                TableHeader(t, "Konto", "Kategori", "Hændelse", "Antal", "Første", "Seneste");
                var n = 0;
                foreach (var a in automatic)
                {
                    var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                    t.Cell().Background(bg).Padding(3).Text(a.Username).SemiBold();
                    t.Cell().Background(bg).Padding(3).Element(x => Pill(x, a.C));
                    t.Cell().Background(bg).Padding(3).Text(a.Msg);
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(a.Count.ToString("N0", Da)).SemiBold();
                    t.Cell().Background(bg).Padding(3).Text(Time(a.First));
                    t.Cell().Background(bg).Padding(3).Text(Time(a.Last));
                }
            });
        });
    }

    private static string DeployTarget(string message)
    {
        var m = System.Text.RegularExpressions.Regex.Match(message, @"Policy Deployment to (.+?) - ");
        return m.Success ? m.Groups[1].Value : "(andet)";
    }

    /// <summary>Collapses ids, timestamps and transaction numbers so recurring jobs group together.</summary>
    private static string Normalize(string message)
    {
        message = System.Text.RegularExpressions.Regex.Replace(message, @"^(Added|Removed|Changed|Deleted) (""[^""]+"") (to|from) .*$", "$1 $2 $3 Snort-regler");
        message = System.Text.RegularExpressions.Regex.Replace(message, @"\s*\(Transaction ID: \d+\)", "");
        message = System.Text.RegularExpressions.Regex.Replace(message, @"\d{6,}", "#");
        message = System.Text.RegularExpressions.Regex.Replace(message, @"\b\d{4} \d{2} \d{2} \d{3}\b", "#");
        return message;
    }

    private static void LoginSection(IContainer c, List<Item> items)
    {
        var relevant = items.Where(i => i.C is Category.Login or Category.Security).ToList();
        var users = relevant.GroupBy(i => Blank(i.R.Username))
            .Select(g => new
            {
                User = g.Key,
                Logins = g.Count(i => i.R.Message.StartsWith("Login Success", StringComparison.OrdinalIgnoreCase)
                                      || i.R.Message.Contains("SSO Login Success", StringComparison.OrdinalIgnoreCase)),
                Logouts = g.Count(i => i.R.Message.StartsWith("Logout", StringComparison.OrdinalIgnoreCase)),
                Expired = g.Count(i => i.R.Message.Contains("expired", StringComparison.OrdinalIgnoreCase)),
                Failed = g.Count(i => i.C == Category.Security),
                Last = g.Max(i => i.R.Time),
                Sources = g.Select(i => i.R.Source).Where(s => s.Length > 0).Distinct().ToList()
            })
            .OrderBy(u => Classifier.IsSystemAccount(u.User)).ThenByDescending(u => u.Logins).ToList();
        var security = items.Where(i => i.C == Category.Security).OrderByDescending(i => i.R.Time).ToList();

        c.Column(col =>
        {
            SectionTitle(col, "Login & sikkerhed", "Logins, sessioner og fejlede/uautoriserede adgangsforsøg pr. bruger.");
            col.Item().Table(t =>
            {
                t.ColumnsDefinition(cols =>
                {
                    cols.RelativeColumn(3);
                    cols.ConstantColumn(50);
                    cols.ConstantColumn(50);
                    cols.ConstantColumn(50);
                    cols.ConstantColumn(60);
                    cols.ConstantColumn(60);
                    cols.ConstantColumn(88);
                    cols.RelativeColumn(4);
                });
                TableHeader(t, "Bruger", "Type", "Logins", "Logouts", "Udløbne sess.", "Fejlede", "Seneste", "Kilde-IP'er");
                var n = 0;
                foreach (var u in users)
                {
                    var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                    var sys = Classifier.IsSystemAccount(u.User);
                    t.Cell().Background(bg).Padding(3).Text(u.User).SemiBold();
                    t.Cell().Background(bg).Padding(3).Text(sys ? "System" : "Person").FontColor(sys ? Colors.Grey.Darken1 : Dark);
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(u.Logins.ToString());
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(u.Logouts.ToString());
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(u.Expired.ToString());
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(u.Failed.ToString())
                        .FontColor(u.Failed > 0 ? Classifier.Color(Category.Security) : Colors.Grey.Darken4).Bold();
                    t.Cell().Background(bg).Padding(3).Text(Time(u.Last));
                    t.Cell().Background(bg).Padding(3).Text(string.Join(", ", u.Sources.Take(4)) +
                                                              (u.Sources.Count > 4 ? $" (+{u.Sources.Count - 4})" : ""));
                }
            });

            col.Item().PaddingTop(14).Text("Sikkerhedshændelser").FontSize(12).Bold().FontColor(Dark);
            if (security.Count == 0) { col.Item().Text("Ingen fejlede logins eller uautoriserede forsøg.").Italic(); return; }
            col.Item().PaddingTop(4).Table(t =>
            {
                t.ColumnsDefinition(cols =>
                {
                    cols.ConstantColumn(88);
                    cols.ConstantColumn(110);
                    cols.RelativeColumn(2);
                    cols.RelativeColumn(3);
                    cols.ConstantColumn(90);
                });
                TableHeader(t, "Tidspunkt", "Bruger", "Subsystem", "Hændelse", "Kilde");
                var n = 0;
                foreach (var i in security)
                {
                    var bg = n++ % 2 == 0 ? "#FFFFFF" : "#FBF3FC";
                    t.Cell().Background(bg).Padding(3).Text(Time(i.R.Time));
                    t.Cell().Background(bg).Padding(3).Text(Blank(i.R.Username)).SemiBold();
                    t.Cell().Background(bg).Padding(3).Text(i.R.Subsystem);
                    t.Cell().Background(bg).Padding(3).Text(i.R.Message);
                    t.Cell().Background(bg).Padding(3).Text(i.R.Source);
                }
            });
        });
    }

    private static void OperationsSection(IContainer c, List<Item> items)
    {
        var ops = items.Where(i => i.C == Category.System)
            .GroupBy(i => (Subsystem: Normalize(i.R.Subsystem), Message: Normalize(i.R.Message)))
            .Select(g => (g.Key.Subsystem, g.Key.Message, Count: g.Count(), First: g.Min(i => i.R.Time), Last: g.Max(i => i.R.Time)))
            .OrderByDescending(x => x.Last).ToList();
        var nav = items.Where(i => i.C == Category.Navigation)
            .GroupBy(i => i.R.Subsystem)
            .Select(g => (Page: g.Key, Count: g.Count(), Users: g.Select(i => i.R.Username).Distinct().ToList(), Last: g.Max(i => i.R.Time)))
            .OrderByDescending(x => x.Count).Take(30).ToList();

        c.Column(col =>
        {
            SectionTitle(col, "Drift & system", "Planlagte opgaver, backups, regelopdateringer og rapporter (grupperet).");
            if (ops.Count == 0) col.Item().Text("Ingen drifts-hændelser.").Italic();
            else
                col.Item().Table(t =>
                {
                    t.ColumnsDefinition(cols =>
                    {
                        cols.RelativeColumn(3);
                        cols.RelativeColumn(5);
                        cols.ConstantColumn(45);
                        cols.ConstantColumn(88);
                        cols.ConstantColumn(88);
                    });
                    TableHeader(t, "Subsystem", "Hændelse", "Antal", "Første", "Seneste");
                    var n = 0;
                    foreach (var o in ops)
                    {
                        var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                        t.Cell().Background(bg).Padding(3).Text(o.Subsystem);
                        t.Cell().Background(bg).Padding(3).Text(o.Message);
                        t.Cell().Background(bg).Padding(3).AlignRight().Text(o.Count.ToString()).SemiBold();
                        t.Cell().Background(bg).Padding(3).Text(Time(o.First));
                        t.Cell().Background(bg).Padding(3).Text(Time(o.Last));
                    }
                });

            col.Item().PaddingTop(14).Text("Navigation i FMC (mest besøgte sider)").FontSize(12).Bold().FontColor(Dark);
            if (nav.Count == 0) { col.Item().Text("Ingen sidevisninger.").Italic(); return; }
            col.Item().PaddingTop(4).Table(t =>
            {
                t.ColumnsDefinition(cols =>
                {
                    cols.RelativeColumn(5);
                    cols.ConstantColumn(45);
                    cols.RelativeColumn(3);
                    cols.ConstantColumn(88);
                });
                TableHeader(t, "Side", "Visninger", "Brugere", "Seneste");
                var n = 0;
                foreach (var p in nav)
                {
                    var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                    t.Cell().Background(bg).Padding(3).Text(p.Page);
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(p.Count.ToString()).SemiBold();
                    t.Cell().Background(bg).Padding(3).Text(string.Join(", ", p.Users));
                    t.Cell().Background(bg).Padding(3).Text(Time(p.Last));
                }
            });
        });
    }

    private static void ApiSection(IContainer c, List<Item> items)
    {
        var api = items.Where(i => i.C is Category.ApiRead or Category.ApiChange)
            .Select(i => (i.R, Ep: Classifier.ApiEndpoint(i.R.Message))).ToList();
        var endpoints = api.GroupBy(a => a.Ep)
            .Select(g => (g.Key.Method, g.Key.Endpoint, Count: g.Count(), Users: g.Select(a => a.R.Username).Distinct().ToList()))
            .OrderByDescending(x => x.Count).Take(25).ToList();
        var byUser = Top(api.GroupBy(a => Blank(a.R.Username)).Select(g => (g.Key, g.Count())), 6);
        c.Column(col =>
        {
            SectionTitle(col, "Bilag: API-trafik", $"{api.Count:N0} REST API-kald i perioden, primært automatiske integrationer.");
            col.Item().Row(row =>
            {
                row.Spacing(12);
                row.RelativeItem().Element(x => Card(x, "API-kald pr. dag", b => StackedDays(b, items.Where(i => i.C is Category.ApiRead or Category.ApiChange).ToList(), 110)));
                row.RelativeItem().Element(x => Card(x, "Kald pr. konto", b => BarChart(b, byUser)));
            });
            col.Item().PaddingTop(10).Table(t =>
            {
                t.ColumnsDefinition(cols =>
                {
                    cols.ConstantColumn(45);
                    cols.RelativeColumn(6);
                    cols.ConstantColumn(55);
                    cols.RelativeColumn(2);
                });
                TableHeader(t, "Metode", "Endpoint (top 25)", "Antal", "Konti");
                var n = 0;
                foreach (var e in endpoints)
                {
                    var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                    t.Cell().Background(bg).Padding(3).Text(e.Method).Bold()
                        .FontColor(e.Method == "GET" ? Colors.Grey.Darken2 : Classifier.Color(Category.ApiChange));
                    t.Cell().Background(bg).Padding(3).Text(e.Endpoint).FontSize(7);
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(e.Count.ToString("N0", Da)).SemiBold();
                    t.Cell().Background(bg).Padding(3).Text(string.Join(", ", e.Users));
                }
            });
        });
    }

    // ---------- Building blocks ----------

    private static string Time(DateTimeOffset t) => t.ToString(@"dd-MM-yyyy HH\:mm\:ss", Da);

    private static string Blank(string s) => string.IsNullOrWhiteSpace(s) ? "(ukendt)" : s;

    private static string ApiShort(string message)
    {
        var (method, ep) = Classifier.ApiEndpoint(message);
        return $"{method} {ep}";
    }

    private static List<(string Label, int Count)> Top(IEnumerable<(string, int)> data, int n)
    {
        var ordered = data.OrderByDescending(x => x.Item2).ToList();
        if (ordered.Count <= n) return ordered;
        var top = ordered.Take(n - 1).ToList();
        top.Add(("Øvrige", ordered.Skip(n - 1).Sum(x => x.Item2)));
        return top;
    }

    private static void Header(IContainer c, ReportOptions opt)
    {
        c.Background(Dark).Padding(12).Row(row =>
        {
            row.RelativeItem().Column(col =>
            {
                col.Item().Text(opt.Title).FontSize(18).Bold().FontColor(Colors.White);
                col.Item().Text($"{opt.FmcName}  •  {opt.From.ToString(@"dd-MM-yyyy HH\:mm", Da)} – {opt.To.ToString(@"dd-MM-yyyy HH\:mm", Da)}" +
                                (string.IsNullOrWhiteSpace(opt.Subsystem) ? "" : $"  •  Subsystem: {opt.Subsystem}"))
                    .FontSize(9).FontColor("#B7C9E2");
            });
            if (opt.Anonymized)
                row.AutoItem().AlignMiddle().Background("#FBAB18").PaddingVertical(4).PaddingHorizontal(8)
                    .Text("ANONYMISERET").FontSize(9).Bold().FontColor(Dark);
        });
    }

    private static void Footer(IContainer c)
    {
        c.BorderTop(0.5f).BorderColor(Colors.Grey.Lighten1).PaddingTop(4).Row(row =>
        {
            row.RelativeItem().Text($"Genereret {DateTimeOffset.Now.ToString(@"dd-MM-yyyy HH\:mm", Da)} • Kilde: Cisco FMC REST API (read-only)")
                .FontSize(7).FontColor(Colors.Grey.Darken1);
            row.AutoItem().Text(t =>
            {
                t.DefaultTextStyle(x => x.FontSize(7).FontColor(Colors.Grey.Darken1));
                t.Span("Side ");
                t.CurrentPageNumber();
                t.Span(" af ");
                t.TotalPages();
            });
        });
    }

    private static void SectionTitle(ColumnDescriptor col, string title, string subtitle)
    {
        col.Item().Text(title).FontSize(15).Bold().FontColor(Dark);
        col.Item().PaddingBottom(6).Text(subtitle).FontSize(8.5f).FontColor(Colors.Grey.Darken1);
    }

    private static void TableHeader(TableDescriptor t, params string[] titles)
    {
        t.Header(h =>
        {
            foreach (var title in titles)
                h.Cell().Background(Dark).Padding(4).Text(title).FontColor(Colors.White).Bold();
        });
    }

    private static void Pill(IContainer c, Category cat) =>
        c.AlignTop().AlignLeft().Background(Classifier.Color(cat)).PaddingHorizontal(4).PaddingVertical(1)
            .Text(Classifier.Label(cat)).FontSize(6.5f).Bold().FontColor(Colors.White);

    private static void Kpi(IContainer c, string label, string value, string color)
    {
        c.Border(0.5f).BorderColor(Colors.Grey.Lighten2).Row(row =>
        {
            row.ConstantItem(4).Background(color);
            row.RelativeItem().Padding(7).Column(col =>
            {
                col.Item().Text(label.ToUpperInvariant()).FontSize(6.5f).FontColor(Colors.Grey.Darken1).SemiBold();
                col.Item().Text(value).FontSize(16).Bold().FontColor(Dark);
            });
        });
    }

    private static void Card(IContainer c, string title, Action<IContainer> body)
    {
        c.Border(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(10).Column(col =>
        {
            col.Item().Text(title).FontSize(11).Bold().FontColor(Dark);
            col.Item().PaddingTop(6).Element(body);
        });
    }

    private static string Trunc(string s, int n) => s.Length <= n ? s : s[..(n - 1)] + "…";

    private static void BarChart(IContainer c, List<(string Label, int Count)> data)
    {
        if (data.Count == 0) { c.Text("Ingen data").Italic(); return; }
        var max = data.Max(d => d.Count);
        c.Column(col =>
        {
            col.Spacing(3);
            for (var i = 0; i < data.Count; i++)
            {
                var (label, count) = data[i];
                var color = Palette[i % Palette.Length];
                col.Item().Row(row =>
                {
                    row.ConstantItem(95).AlignMiddle().Text(Trunc(label, 22)).FontSize(7.5f);
                    row.RelativeItem().Height(11).Svg(size =>
                    {
                        var w = Math.Max(size.Width * count / max, 2);
                        return Inv($"<svg xmlns='http://www.w3.org/2000/svg' width='{size.Width}' height='{size.Height}'>") +
                               Inv($"<rect x='0' y='1' width='{size.Width}' height='{size.Height - 2}' rx='2' fill='#EEF2F7'/>") +
                               Inv($"<rect x='0' y='1' width='{w}' height='{size.Height - 2}' rx='2' fill='{color}'/></svg>");
                    });
                    row.ConstantItem(38).AlignRight().AlignMiddle().Text(count.ToString("N0", Da)).FontSize(7.5f).SemiBold();
                });
            }
        });
    }

    private static void Donut(IContainer c, List<(string Label, int Count, string Color)> data, string unit = "hændelser")
    {
        if (data.Count == 0) { c.Text("Ingen data").Italic(); return; }
        var total = (double)data.Sum(d => d.Count);
        c.Row(row =>
        {
            row.ConstantItem(110).Height(110).Svg(size =>
            {
                double cx = size.Width / 2, cy = size.Height / 2, r = Math.Min(cx, cy) - 4, inner = r * 0.58;
                var svg = new StringBuilder(Inv($"<svg xmlns='http://www.w3.org/2000/svg' width='{size.Width}' height='{size.Height}'>"));
                var angle = -Math.PI / 2;
                foreach (var (_, count, color) in data)
                {
                    var sweep = count / total * Math.PI * 2;
                    if (sweep >= Math.PI * 2 - 1e-6)
                        svg.Append(Inv($"<circle cx='{cx}' cy='{cy}' r='{r}' fill='{color}'/>"));
                    else if (sweep > 0)
                    {
                        var (x1, y1) = (cx + r * Math.Cos(angle), cy + r * Math.Sin(angle));
                        var (x2, y2) = (cx + r * Math.Cos(angle + sweep), cy + r * Math.Sin(angle + sweep));
                        var large = sweep > Math.PI ? 1 : 0;
                        svg.Append(Inv($"<path d='M{cx},{cy} L{x1},{y1} A{r},{r} 0 {large} 1 {x2},{y2} Z' fill='{color}' stroke='white' stroke-width='1'/>"));
                    }
                    angle += sweep;
                }
                svg.Append(Inv($"<circle cx='{cx}' cy='{cy}' r='{inner}' fill='white'/>"));
                svg.Append(Inv($"<text x='{cx}' y='{cy + 3}' font-size='13' font-weight='bold' text-anchor='middle' fill='{Dark}' font-family='Arial'>{total.ToString("N0", Da)}</text>"));
                svg.Append(Inv($"<text x='{cx}' y='{cy + 13}' font-size='6' text-anchor='middle' fill='#666' font-family='Arial'>{unit}</text>"));
                svg.Append("</svg>");
                return svg.ToString();
            });
            row.RelativeItem().PaddingLeft(8).AlignMiddle().Column(col =>
            {
                col.Spacing(2);
                foreach (var (label, count, color) in data)
                {
                    col.Item().Row(l =>
                    {
                        l.ConstantItem(8).Height(8).AlignMiddle().Background(color);
                        l.RelativeItem().PaddingLeft(4).Text(Trunc(label, 22)).FontSize(7);
                        l.AutoItem().Text(Pct(count / total)).FontSize(7).SemiBold();
                    });
                }
            });
        });
    }

    private static string Pct(double v) => v is > 0 and < 0.01 ? "<1 %" : v.ToString("P0", Da);

    private static void Donut(IContainer c, List<(string Label, int Count)> data, string unit = "hændelser") =>
        Donut(c, data.Select((d, i) => (d.Label, d.Count, Palette[i % Palette.Length])).ToList(), unit);

    private static void StackedDays(IContainer c, List<Item> items, float height = 140)
    {
        if (items.Count == 0) { c.Text("Ingen data").Italic(); return; }
        var cats = Enum.GetValues<Category>().Where(cat => items.Any(i => i.C == cat)).ToList();
        var first = items.Min(i => i.R.Time.Date);
        var last = items.Max(i => i.R.Time.Date);
        var days = Enumerable.Range(0, (last - first).Days + 1).Select(d => first.AddDays(d)).ToList();
        var counts = items.GroupBy(i => (i.R.Time.Date, i.C)).ToDictionary(g => g.Key, g => g.Count());
        var totals = days.Select(d => cats.Sum(cat => counts.GetValueOrDefault((d, cat)))).ToList();
        var max = Math.Max(totals.Max(), 1);
        var niceMax = NiceCeiling(max);

        c.Column(col =>
        {
            col.Item().Height(height).Svg(size =>
            {
                double w = size.Width, h = size.Height, left = 26, bottom = 16, top = 4;
                double plotW = w - left - 4, plotH = h - bottom - top;
                var sb = new StringBuilder(Inv($"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}' font-family='Arial'>"));
                for (var g = 0; g <= 4; g++)
                {
                    var y = top + plotH - plotH * g / 4;
                    sb.Append(Inv($"<line x1='{left}' y1='{y}' x2='{w - 4}' y2='{y}' stroke='#E5E7EB' stroke-width='0.5'/>"));
                    sb.Append(Inv($"<text x='{left - 4}' y='{y + 2.5}' font-size='6.5' fill='#666' text-anchor='end'>{niceMax * g / 4}</text>"));
                }
                var slot = plotW / days.Count;
                var bw = Math.Max(slot * 0.7, 1);
                for (var d = 0; d < days.Count; d++)
                {
                    var x = left + d * slot + (slot - bw) / 2;
                    var y = top + plotH;
                    foreach (var cat in cats)
                    {
                        var v = counts.GetValueOrDefault((days[d], cat));
                        if (v == 0) continue;
                        var bh = plotH * v / niceMax;
                        y -= bh;
                        sb.Append(Inv($"<rect x='{x}' y='{y}' width='{bw}' height='{bh}' fill='{Classifier.Color(cat)}'/>"));
                    }
                    var every = Math.Max(1, (int)Math.Ceiling(days.Count / 15.0));
                    if (d % every == 0)
                        sb.Append(Inv($"<text x='{x + bw / 2}' y='{h - 4}' font-size='6.5' fill='#666' text-anchor='middle'>{days[d]:dd/MM}</text>"));
                }
                sb.Append("</svg>");
                return sb.ToString();
            });
            col.Item().PaddingTop(4).Row(row =>
            {
                foreach (var cat in cats)
                {
                    row.AutoItem().PaddingRight(10).Row(l =>
                    {
                        l.ConstantItem(8).Height(8).Background(Classifier.Color(cat));
                        l.AutoItem().PaddingLeft(3).Text(Classifier.Label(cat)).FontSize(7);
                    });
                }
            });
        });
    }

    private static int NiceCeiling(int max)
    {
        var mag = Math.Pow(10, Math.Floor(Math.Log10(max)));
        foreach (var f in new[] { 1, 2, 2.5, 4, 5, 10 })
            if (f * mag >= max) return (int)Math.Max(4, Math.Ceiling(f * mag / 4) * 4);
        return max;
    }

    private static void HourChart(IContainer c, List<(int Hour, int Count)> data)
    {
        var max = Math.Max(data.Max(d => d.Count), 1);
        c.Column(col =>
        {
            col.Item().Height(100).Svg(size =>
            {
                double w = size.Width, h = size.Height, bottom = 14, plotH = h - bottom - 4;
                var bw = w / 24;
                var sb = new StringBuilder(Inv($"<svg xmlns='http://www.w3.org/2000/svg' width='{w}' height='{h}' font-family='Arial'>"));
                foreach (var (hour, count) in data)
                {
                    var bh = plotH * count / max;
                    var work = hour is >= 7 and < 17;
                    sb.Append(Inv($"<rect x='{hour * bw + 1}' y='{4 + plotH - bh}' width='{bw - 2}' height='{bh}' rx='1' fill='{(work ? Primary : "#FBAB18")}'/>"));
                    if (hour % 3 == 0)
                        sb.Append(Inv($"<text x='{hour * bw + bw / 2}' y='{h - 3}' font-size='6.5' fill='#666' text-anchor='middle'>{hour:00}</text>"));
                }
                sb.Append("</svg>");
                return sb.ToString();
            });
            col.Item().PaddingTop(3).Row(row =>
            {
                row.AutoItem().Width(8).Height(8).Background(Primary);
                row.AutoItem().PaddingLeft(3).PaddingRight(10).Text("Arbejdstid 07–17").FontSize(7);
                row.AutoItem().Width(8).Height(8).Background("#FBAB18");
                row.AutoItem().PaddingLeft(3).Text("Udenfor arbejdstid").FontSize(7);
            });
        });
    }

    private static string Inv(FormattableString s) => s.ToString(CultureInfo.InvariantCulture);
}
