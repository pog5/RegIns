using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Themes.Fluent;
using RegIns;
using System.Text.Json;

namespace RegIns.Gui;
internal static class Program
{
    [STAThread] public static void Main(string[] args) => AppBuilder.Configure<App>().UsePlatformDetect().StartWithClassicDesktopLifetime(args);
}
public sealed class App : Application
{
    public override void Initialize() => Styles.Add(new FluentTheme());
    public override void OnFrameworkInitializationCompleted() { if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop) desktop.MainWindow = new MainWindow(); base.OnFrameworkInitializationCompleted(); }
}
public sealed class MainWindow : Window
{
    private readonly TextBlock status = new() { Text = "Open a hive or recovery plan to begin.", TextWrapping = TextWrapping.Wrap };
    private readonly ListBox candidates = new();
    private readonly TreeView tree = new();
    private readonly TextBox details = new() { IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, FontFamily = FontFamily.Parse("monospace") };
    private readonly CheckBox replaceSecurity = new() { Content = "Replace missing security with an empty DACL" };
    private RecoveryPlan? plan;
    private string? sourcePath;
    private readonly List<string> snapshotRoots = [];
    private CancellationTokenSource? cancellation;
    private readonly JsonSerializerOptions json = new() { WriteIndented = true };
    public MainWindow()
    {
        Title = "RegIns — Registry recovery"; Width = 1200; Height = 800; MinWidth = 800; MinHeight = 500;
        var toolbar = new WrapPanel { Orientation = Orientation.Horizontal };
        Button Add(string title, Func<Task> action) { var b = new Button { Content = title, Margin = new Thickness(0,0,8,8) }; b.Click += async (_, _) => { if (cancellation is not null) { status.Text = "An operation is running. Cancel it first."; return; } try { await action(); } catch (OperationCanceledException) { status.Text = "Cancelled."; } catch (Exception e) { status.Text = e.Message; } }; toolbar.Children.Add(b); return b; }
        Add("Open hive", OpenHive); Add("Open plan", OpenPlan); Add("Save plan", SavePlan); Add("Carve image", Carve); Add("Analyze log", AnalyzeLog); Add("Export hive", Export);
        Add("Add backup/snapshot root", async () => { var folders = await StorageProvider.OpenFolderPickerAsync(new() { Title = "Select mounted snapshot or backup root", AllowMultiple = true }); foreach (var folder in folders) if (folder.TryGetLocalPath() is { } path) snapshotRoots.Add(path); status.Text = $"{snapshotRoots.Count} backup/snapshot roots selected; reopen the hive to search them."; });
        Add("Find host snapshots", async () => { var roots = await SnapshotDiscovery.EnumerateHostAsync(); foreach (var root in roots) snapshotRoots.Add(root.Path); details.Text = JsonSerializer.Serialize(roots, json); status.Text = $"Found {roots.Count} host snapshots. Reopen a hive to search these roots."; });
        Add("Include selected salvage", () => { if (plan is not null && tree.SelectedItem is TreeViewItem { Tag: RecoveredKey k }) { if (!plan.IncludedSalvageOffsets.Contains(k.Offset)) plan.IncludedSalvageOffsets.Add(k.Offset); status.Text = "Key explicitly included in export. Review orphans and naming conflicts before writing."; } return Task.CompletedTask; });
        var rename = new TextBox { Watermark = "New selected key/value name", Width = 240 }; toolbar.Children.Add(rename);
        Add("Rename selection", () => { if (tree.SelectedItem is TreeViewItem item) { if (item.Tag is RecoveredKey k) k.Name = rename.Text ?? ""; else if (item.Tag is RecoveredValue v) v.Name = rename.Text ?? ""; item.Header = rename.Text; status.Text = "Recovery model edited; original evidence bytes are preserved."; } return Task.CompletedTask; });
        var cancel = new Button { Content = "Cancel" }; cancel.Click += (_, _) => cancellation?.Cancel(); toolbar.Children.Add(cancel);
        var top = new StackPanel { Spacing = 8, Children = { toolbar, replaceSecurity, status } };
        var body = new Grid { ColumnDefinitions = new ColumnDefinitions("250,*,*"), Margin = new Thickness(0, 12, 0, 0) };
        body.Children.Add(candidates); Grid.SetColumn(tree, 1); body.Children.Add(tree); Grid.SetColumn(details, 2); body.Children.Add(details);
        var layout = new DockPanel { Margin = new Thickness(16) }; DockPanel.SetDock(top, Dock.Top); layout.Children.Add(top); layout.Children.Add(body); Content = layout;
        candidates.SelectionChanged += (_, _) => RefreshTree();
        tree.SelectionChanged += (_, _) => { if (tree.SelectedItem is TreeViewItem item) details.Text = JsonSerializer.Serialize(item.Tag, json); };
        Closing += (_, _) => cancellation?.Cancel();
    }
    private async Task<string?> Pick(bool save, string title)
    {
        if (save) { var f = await StorageProvider.SaveFilePickerAsync(new() { Title = title }); return f?.TryGetLocalPath(); }
        var files = await StorageProvider.OpenFilePickerAsync(new() { Title = title, AllowMultiple = false }); return files.FirstOrDefault()?.TryGetLocalPath();
    }
    private async Task OpenHive()
    {
        var path = await Pick(false, "Open registry hive"); if (path is null) return;
        cancellation = new(); var token = cancellation.Token;
        try
        {
            var progress = new Progress<ScanProgress>(p => status.Text = $"Scanned {p.BytesScanned:N0} / {p.TotalBytes:N0} bytes · {p.Records:N0} records");
            var recovered = await Task.Run(() => ArtifactDiscovery.RecoverFile(path, snapshotRoots, progress: progress, cancellationToken: token), token);
            sourcePath = path; plan = recovered; RefreshCandidates();
        }
        finally { cancellation.Dispose(); cancellation = null; }
    }
    private async Task OpenPlan() { var path = await Pick(false, "Open recovery plan JSON"); if (path is null) return; plan = JsonSerializer.Deserialize<RecoveryPlan>(await File.ReadAllTextAsync(path), json) ?? throw new InvalidDataException("Empty plan."); sourcePath = null; RefreshCandidates(); }
    private async Task SavePlan() { if (plan is null) return; var path = await Pick(true, "Save recovery plan"); if (path is null) return; using var f = new FileStream(path, FileMode.CreateNew); await JsonSerializer.SerializeAsync(f, plan, json); status.Text = "Plan saved."; }
    private async Task AnalyzeLog() { var path = await Pick(false, "Open registry transaction log"); if (path is null) return; cancellation = new(); try { var token = cancellation.Token; var analysis = await Task.Run(() => { using var source = new FileByteSource(path); return TransactionLogs.Analyze(source, cancellationToken: token); }, token); details.Text = JsonSerializer.Serialize(analysis, json); status.Text = $"{analysis.Format}: {analysis.Entries.Count} validated entries. Use CLI to select and replay a history."; } finally { cancellation.Dispose(); cancellation = null; } }
    private async Task Carve() { var path = await Pick(false, "Open raw image"); if (path is null) return; cancellation = new(); try { var token = cancellation.Token; var regions = await Task.Run(() => { using var source = new FileByteSource(path); return HiveCarver.Scan(source, 1L << 30, token).Take(250000).ToList(); }, token); details.Text = JsonSerializer.Serialize(regions, json); status.Text = $"Found {regions.Count} candidate regions within the first 1 GiB. Associations are unverified."; } finally { cancellation.Dispose(); cancellation = null; } }
    private async Task Export()
    {
        if (plan is null) return; var path = await Pick(true, "Export recovered hive to a new file"); if (path is null) return;
        if (sourcePath is not null && Path.GetFullPath(path).Equals(Path.GetFullPath(sourcePath), StringComparison.OrdinalIgnoreCase)) throw new IOException("Source cannot be overwritten.");
        if (File.Exists(path) || File.Exists(path + ".report.json")) throw new IOException("Output or report already exists.");
        bool replace = replaceSecurity.IsChecked == true; cancellation = new();
        try { var token = cancellation.Token; var output = await Task.Run(() => HiveWriter.Export(plan, new(replace), token), token); using (var f = new FileStream(path, FileMode.CreateNew)) await f.WriteAsync(output.Bytes, token); using (var f = new FileStream(path + ".report.json", FileMode.CreateNew)) await JsonSerializer.SerializeAsync(f, output.Report, json, token); status.Text = $"Exported {output.Report.KeysWritten} keys; complete: {output.Report.Complete}. Review the report."; }
        finally { cancellation.Dispose(); cancellation = null; }
    }
    private void RefreshCandidates()
    {
        if (plan is null) return;
        candidates.ItemsSource = plan.Candidates.Select(c => $"{c.Id} · {c.KeyOffsets.Count} keys · {c.Reason}").ToList();
        candidates.SelectedIndex = Math.Max(0, plan.Candidates.FindIndex(c => c.Id == plan.SelectedCandidateId));
        status.Text = $"{plan.Inspection.Keys.Count} keys · {plan.Inspection.Findings.Count} findings · scan complete: {plan.Inspection.ScanComplete}";
        details.Text = JsonSerializer.Serialize(plan.Inspection.Findings, json);
    }
    private void RefreshTree()
    {
        tree.SelectedItem = null;
        tree.Items.Clear();
        if (plan is null || candidates.SelectedIndex < 0 || candidates.SelectedIndex >= plan.Candidates.Count) return;
        var candidate = plan.Candidates[candidates.SelectedIndex]; plan.SelectedCandidateId = candidate.Id;
        var ids = candidate.KeyOffsets.ToHashSet(); var nodes = new Dictionary<long, TreeViewItem>();
        foreach (var k in plan.Inspection.Keys.Where(k => ids.Contains(k.Offset)))
        {
            var node = new TreeViewItem { Header = k.Name, Tag = k }; foreach (var v in k.Values) node.Items.Add(new TreeViewItem { Header = $"{(v.Name == "" ? "(Default)" : v.Name)} [{v.Type}] · {(v.Complete ? "complete" : "partial")}", Tag = v }); nodes[k.Offset] = node;
        }
        var byId = plan.Inspection.Keys.ToDictionary(x => x.Offset);
        long Parent(RecoveredKey key) => plan.ParentOverrides.GetValueOrDefault(key.Offset, key.ParentOffset);
        foreach (var k in plan.Inspection.Keys.Where(k => ids.Contains(k.Offset)))
        {
            var seen = new HashSet<long> { k.Offset }; long p = Parent(k); bool cycle = false;
            while (byId.TryGetValue(p, out var parent)) { if (!seen.Add(p)) { cycle = true; break; } p = Parent(parent); }
            if (k.Offset != candidate.RootOffset && !cycle && nodes.TryGetValue(Parent(k), out var node)) node.Items.Add(nodes[k.Offset]); else tree.Items.Add(nodes[k.Offset]);
        }
        var salvage = new TreeViewItem { Header = "Unselected / salvage" };
        foreach (var k in plan.Inspection.Keys.Where(k => !ids.Contains(k.Offset))) salvage.Items.Add(new TreeViewItem { Header = $"{k.Name} @ {k.Offset:x}", Tag = k });
        foreach (var v in plan.Inspection.UnownedValues) salvage.Items.Add(new TreeViewItem { Header = $"Unowned value: {v.Name}", Tag = v });
        tree.Items.Add(salvage);
    }
}
