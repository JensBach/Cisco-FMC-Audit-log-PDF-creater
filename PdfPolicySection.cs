using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace FmcAuditLog;

public static partial class PdfReport
{
    private const int MaxRulesPerChange = 25;
    private const int MaxObjects = 250;
    private static readonly TimeSpan CorrelationWindow = TimeSpan.FromMinutes(5);

    private sealed record RuleChange(string Policy, DateTimeOffset Time, List<RuleInfo> Rules, AuditRecord? Audit);

    private static void PolicySections(IDocumentContainer doc, PolicySnapshot snap, List<Item> items, ReportOptions opt)
    {
        var inPeriod = (DateTimeOffset? t) => t >= opt.From && t <= opt.To;
        var changes = snap.Rules.Where(r => inPeriod(r.Modified))
            .GroupBy(r => (r.Policy, Time: r.Modified!.Value))
            .Select(g => new RuleChange(g.Key.Policy, g.Key.Time, g.OrderBy(r => r.Index).ToList(),
                Correlate(items, g.Key.Policy, g.Key.Time)))
            .OrderByDescending(c => c.Time).ToList();
        var objects = snap.ChangedObjects.Where(o => inPeriod(o.Modified)).OrderByDescending(o => o.Modified).ToList();
        var deployments = snap.Deployments.Where(j => j.Start is null || inPeriod(j.Start))
            .OrderByDescending(j => j.Start).ToList();

        doc.Page(page =>
        {
            Setup(page, opt, landscape: true);
            page.Content().PaddingTop(8).Column(col =>
            {
                PolicyOverview(col, snap, changes, objects, deployments);
                col.Item().PageBreak();
                RuleChanges(col, changes);
                col.Item().PageBreak();
                ObjectChanges(col, objects);
                col.Item().PageBreak();
                DeploymentHistory(col, deployments);
            });
        });
    }

    /// <summary>Finds the audit event (preferably "Save Policy &lt;name&gt;") that most likely caused the change.</summary>
    private static AuditRecord? Correlate(List<Item> items, string policy, DateTimeOffset time)
    {
        var near = items.Where(i => (i.R.Time - time).Duration() <= CorrelationWindow && Classifier.IsChange(i.C)).ToList();
        return near.Where(i => i.R.Message.Contains(policy, StringComparison.OrdinalIgnoreCase))
                   .OrderBy(i => (i.R.Time - time).Duration()).Select(i => i.R).FirstOrDefault()
               ?? near.Where(i => !Classifier.IsSystemAccount(i.R.Username))
                   .OrderBy(i => (i.R.Time - time).Duration()).Select(i => i.R).FirstOrDefault();
    }

    private static void PolicyOverview(ColumnDescriptor col, PolicySnapshot snap, List<RuleChange> changes,
        List<ObjectInfo> objects, List<DeploymentJob> deployments)
    {
        SectionTitle(col, "Policy-udtræk",
            $"Nuværende konfiguration hentet {snap.FetchedAt.ToString(@"dd-MM-yyyy HH\:mm", Da)} og sammenholdt med audit-loggen.");

        var changedRules = changes.Sum(c => c.Rules.Count);
        col.Item().Row(row =>
        {
            row.Spacing(8);
            row.RelativeItem().Element(x => Kpi(x, "Policies", snap.Policies.Count.ToString("N0", Da), Primary));
            row.RelativeItem().Element(x => Kpi(x, "Access-regler i alt", snap.Rules.Count.ToString("N0", Da), Dark));
            row.RelativeItem().Element(x => Kpi(x, "Regler ændret i perioden", changedRules.ToString("N0", Da), "#FBAB18"));
            row.RelativeItem().Element(x => Kpi(x, "Objekter ændret", objects.Count.ToString("N0", Da), "#6CC04A"));
            row.RelativeItem().Element(x => Kpi(x, "Deployment-jobs", deployments.Count.ToString("N0", Da), "#7B61FF"));
        });

        col.Item().PaddingTop(8).Background("#FFF8E1").Border(0.5f).BorderColor("#FBAB18").Padding(8).Column(info =>
        {
            info.Item().Text("Sådan skal udtrækket læses").Bold().FontColor(Dark);
            info.Item().Text("FMC'en gemmer kun tidspunkt og bruger for den seneste ændring af hver regel/objekt – ikke historiske " +
                             "versioner. Udtrækket viser derfor reglernes nuværende indhold, og hvornår de sidst blev ændret. " +
                             "Ændrer en bruger flere regler i ét gem, får de samme tidsstempel; de er grupperet og koblet til den " +
                             "nærmeste 'Save Policy'-hændelse i audit-loggen (±5 min) for at vise, hvem der stod bag.")
                .FontSize(7.5f);
        });
        col.Item().PaddingTop(10).Row(row =>
        {
            row.Spacing(10);
            row.RelativeItem(3).Table(t =>
            {
                t.ColumnsDefinition(cols =>
                {
                    cols.ConstantColumn(90);
                    cols.RelativeColumn(3);
                    cols.ConstantColumn(45);
                    cols.ConstantColumn(60);
                    cols.ConstantColumn(88);
                    cols.RelativeColumn(2);
                });
                TableHeader(t, "Type", "Policy", "Regler", "Ændret i per.", "Senest ændret", "Senest af");
                var n = 0;
                foreach (var p in snap.Policies.OrderBy(p => p.Type).ThenByDescending(p => p.Modified))
                {
                    var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                    var changed = changes.Where(c => c.Policy == p.Name).Sum(c => c.Rules.Count);
                    t.Cell().Background(bg).Padding(3).Text(p.Type);
                    t.Cell().Background(bg).Padding(3).Text(p.Name).SemiBold();
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(p.RuleCount > 0 ? p.RuleCount.ToString("N0", Da) : "–");
                    t.Cell().Background(bg).Padding(3).AlignRight().Text(changed > 0 ? changed.ToString("N0", Da) : "–")
                        .FontColor(changed > 0 ? "#B26A00" : Colors.Grey.Darken4).SemiBold();
                    t.Cell().Background(bg).Padding(3).Text(p.Modified is { } m ? Time(m) : "–");
                    t.Cell().Background(bg).Padding(3).Text(p.LastUser.Length > 0 ? p.LastUser : "–");
                }
            });

            row.RelativeItem(2).Column(right =>
            {
                right.Spacing(8);
                var perPolicy = Top(changes.GroupBy(c => c.Policy).Select(g => (g.Key, g.Sum(c => c.Rules.Count))), 6);
                if (perPolicy.Count > 0)
                    right.Item().Element(x => Card(x, "Ændrede regler pr. policy", b => BarChart(b, perPolicy)));
                var actions = Top(snap.Rules.GroupBy(r => r.Action.Length > 0 ? r.Action : "(ukendt)")
                    .Select(g => (g.Key, g.Count())), 6);
                if (actions.Count > 0)
                    right.Item().Element(x => Card(x, "Access-regler fordelt på action", b => Donut(b, actions, "regler")));
            });
        });

    }

    private static void RuleChanges(ColumnDescriptor col, List<RuleChange> changes)
    {
        SectionTitle(col, "Access-regler ændret i perioden",
            $"{changes.Sum(c => c.Rules.Count):N0} regler fordelt på {changes.Count:N0} gem – vist med nuværende indhold.");
        if (changes.Count == 0) { col.Item().Text("Ingen regler med ændringstidspunkt i perioden.").Italic(); return; }

        foreach (var change in changes)
        {
            var who = change.Audit is { } a
                ? $"{a.Username} – \"{Trunc(a.Message, 80)}\" kl. {a.Time.ToString(@"HH\:mm\:ss", Da)}"
                : "ingen matchende audit-hændelse";
            col.Item().PaddingTop(8).ShowEntire().Background("#E8F4FB").BorderLeft(3).BorderColor(Primary).Padding(5).Row(r =>
            {
                r.ConstantItem(95).Text(Time(change.Time)).Bold().FontColor(Dark);
                r.RelativeItem().Text(t =>
                {
                    t.Span(change.Policy).Bold().FontColor(Dark);
                    t.Span($"   {change.Rules.Count:N0} {(change.Rules.Count == 1 ? "regel" : "regler")}   ").FontColor(Colors.Grey.Darken1);
                    t.Span("Udført af: ").FontColor(Colors.Grey.Darken1);
                    t.Span(who).SemiBold();
                });
            });
            if (change.Rules.Count > 50)
                col.Item().PaddingLeft(6).PaddingTop(2)
                    .Text("Mange regler med samme tidsstempel – typisk et gem der har flyttet/omnummereret regler, ikke nødvendigvis ændret indhold.")
                    .FontSize(7).Italic().FontColor(Colors.Grey.Darken1);

            col.Item().Table(t =>
            {
                t.ColumnsDefinition(cols =>
                {
                    cols.ConstantColumn(28);
                    cols.RelativeColumn(3);
                    cols.ConstantColumn(58);
                    cols.RelativeColumn(2);
                    cols.RelativeColumn(3);
                    cols.RelativeColumn(2);
                    cols.RelativeColumn(3);
                    cols.RelativeColumn(2);
                    cols.RelativeColumn(2);
                });
                TableHeader(t, "#", "Regel", "Action", "Fra zone", "Fra netværk", "Til zone", "Til netværk", "Porte / apps", "Kategori");
                var n = 0;
                foreach (var r in change.Rules.Take(MaxRulesPerChange))
                {
                    var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                    t.Cell().Background(bg).Padding(2).AlignRight().Text(r.Index.ToString());
                    t.Cell().Background(bg).Padding(2).Text(x =>
                    {
                        x.Span(r.Name).SemiBold();
                        if (!r.Enabled) x.Span("  (deaktiveret)").FontColor("#E2231A").FontSize(6.5f);
                        if (r.Comments.Count > 0) x.Span($"\n{Trunc(r.Comments[^1], 90)}").FontSize(6.5f).Italic().FontColor(Colors.Grey.Darken1);
                    });
                    t.Cell().Background(bg).Padding(2).Element(x => ActionPill(x, r.Action));
                    t.Cell().Background(bg).Padding(2).Text(List(r.SourceZones));
                    t.Cell().Background(bg).Padding(2).Text(List(r.SourceNetworks));
                    t.Cell().Background(bg).Padding(2).Text(List(r.DestinationZones));
                    t.Cell().Background(bg).Padding(2).Text(List(r.DestinationNetworks));
                    t.Cell().Background(bg).Padding(2).Text(List(r.Ports.Concat(r.Applications).ToList()));
                    t.Cell().Background(bg).Padding(2).Text(r.Category.Length > 0 ? r.Category : r.Section).FontColor(Colors.Grey.Darken1);
                }
            });
            if (change.Rules.Count > MaxRulesPerChange)
                col.Item().PaddingLeft(6).Text($"+ {change.Rules.Count - MaxRulesPerChange:N0} regler mere med samme tidsstempel.")
                    .FontSize(7).Italic().FontColor(Colors.Grey.Darken1);
        }
    }

    private static void ObjectChanges(ColumnDescriptor col, List<ObjectInfo> objects)
    {
        SectionTitle(col, "Objekter ændret i perioden",
            $"{objects.Count:N0} netværks-, port-, URL- og zone-objekter oprettet eller ændret (nuværende værdi).");
        if (objects.Count == 0) { col.Item().Text("Ingen objekter ændret i perioden.").Italic(); return; }

        var byUser = Top(objects.GroupBy(o => Blank(o.LastUser)).Select(g => (g.Key, g.Count())), 6);
        var byType = Top(objects.GroupBy(o => o.Type).Select(g => (g.Key, g.Count())), 6);
        if (objects.Count >= 5)
            col.Item().Row(row =>
            {
                row.Spacing(10);
                row.RelativeItem().Element(x => Card(x, "Pr. bruger", b => BarChart(b, byUser)));
                row.RelativeItem().Element(x => Card(x, "Pr. type", b => Donut(b, byType, "objekter")));
            });

        col.Item().PaddingTop(8).Table(t =>
        {
            t.ColumnsDefinition(cols =>
            {
                cols.ConstantColumn(88);
                cols.ConstantColumn(85);
                cols.RelativeColumn(3);
                cols.RelativeColumn(5);
                cols.RelativeColumn(2);
            });
            TableHeader(t, "Senest ændret", "Type", "Navn", "Værdi", "Af");
            var n = 0;
            foreach (var o in objects.Take(MaxObjects))
            {
                var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                t.Cell().Background(bg).Padding(3).Text(Time(o.Modified!.Value));
                t.Cell().Background(bg).Padding(3).Text(o.Type);
                t.Cell().Background(bg).Padding(3).Text(o.Name).SemiBold();
                t.Cell().Background(bg).Padding(3).Text(o.Value);
                t.Cell().Background(bg).Padding(3).Text(Blank(o.LastUser));
            }
        });
        if (objects.Count > MaxObjects)
            col.Item().PaddingTop(3).Text($"+ {objects.Count - MaxObjects:N0} objekter mere (se policy-cache.json).")
                .FontSize(7).Italic().FontColor(Colors.Grey.Darken1);
    }

    private static void DeploymentHistory(ColumnDescriptor col, List<DeploymentJob> jobs)
    {
        SectionTitle(col, "Deployment-historik",
            $"{jobs.Count:N0} deployment-jobs fra FMC'ens jobhistorik med enheder, version og status.");
        if (jobs.Count == 0) { col.Item().Text("Ingen deployment-jobs i perioden.").Italic(); return; }

        var byUser = Top(jobs.GroupBy(j => Blank(j.User)).Select(g => (g.Key, g.Count())), 6);
        var byStatus = Top(jobs.GroupBy(j => Blank(j.Status)).Select(g => (g.Key, g.Count())), 6);
        col.Item().Row(row =>
        {
            row.Spacing(10);
            row.RelativeItem().Element(x => Card(x, "Jobs pr. bruger", b => BarChart(b, byUser)));
            row.RelativeItem().Element(x => Card(x, "Status", b => Donut(b, byStatus, "jobs")));
        });

        col.Item().PaddingTop(8).Table(t =>
        {
            t.ColumnsDefinition(cols =>
            {
                cols.ConstantColumn(88);
                cols.ConstantColumn(40);
                cols.RelativeColumn(2);
                cols.ConstantColumn(60);
                cols.RelativeColumn(4);
                cols.RelativeColumn(3);
            });
            TableHeader(t, "Start", "Varighed", "Bruger", "Status", "Enheder (version / status)", "Note");
            var n = 0;
            foreach (var j in jobs)
            {
                var bg = n++ % 2 == 0 ? "#FFFFFF" : Zebra;
                var ok = j.Status.Contains("SUCCE", StringComparison.OrdinalIgnoreCase);
                var dur = j.Start is { } s && j.End is { } e && e > s ? $"{(int)(e - s).TotalMinutes}:{(e - s).Seconds:D2}" : "–";
                t.Cell().Background(bg).Padding(3).Text(j.Start is { } st ? Time(st) : "–");
                t.Cell().Background(bg).Padding(3).AlignRight().Text(dur);
                t.Cell().Background(bg).Padding(3).Text(Blank(j.User)).SemiBold();
                t.Cell().Background(bg).Padding(3).Text(Blank(j.Status)).SemiBold()
                    .FontColor(ok ? "#2E7D32" : j.Status.Contains("FAIL", StringComparison.OrdinalIgnoreCase) ? "#E2231A" : "#B26A00");
                t.Cell().Background(bg).Padding(3).Text(string.Join(", ", j.Devices.Select(dv =>
                    $"{dv.Device}{(dv.Version is { } v ? $" v{v}" : "")}{(dv.Status.Length > 0 && !dv.Status.Contains("SUCCE", StringComparison.OrdinalIgnoreCase) ? $" ({dv.Status})" : "")}")));
                t.Cell().Background(bg).Padding(3).Text(j.Note).Italic();
            }
        });
    }

    private static void ActionPill(IContainer c, string action)
    {
        var color = action.ToUpperInvariant() switch
        {
            "ALLOW" or "TRUST" => "#2E7D32",
            "BLOCK" or "BLOCK_RESET" or "BLOCK_INTERACTIVE" or "BLOCK_RESET_INTERACTIVE" => "#E2231A",
            "MONITOR" => "#7B61FF",
            _ => "#8E9AAF"
        };
        c.AlignTop().AlignLeft().Background(color).PaddingHorizontal(4).PaddingVertical(1)
            .Text(action.Length > 0 ? action.Replace('_', ' ') : "–").FontSize(6).Bold().FontColor(Colors.White);
    }

    private static string List(List<string> values) =>
        values.Count == 0 ? "any" : values.Count <= 4 ? string.Join(", ", values) : string.Join(", ", values.Take(4)) + $" +{values.Count - 4}";
}
