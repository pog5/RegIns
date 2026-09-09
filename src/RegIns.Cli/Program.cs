using System.Text.Json;
using RegIns;

var json = new JsonSerializerOptions { WriteIndented = true };
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cancellation.Cancel(); };
try
{
    if (args.Length > 0 && args[0] == "snapshots") { Console.WriteLine(JsonSerializer.Serialize(await SnapshotDiscovery.EnumerateHostAsync(cancellation.Token), json)); return 0; }
    if (args.Length < 2 || args[0] is "help" or "--help")
    {
        Console.WriteLine("RegIns: inspect|validate|carve|recover|export|logs|discover <input> [--out <new-file>] [--candidate <id>] [--replace-missing-security] [--max-bytes <n>] [--bins-offset <n>] [--log <file>] [--snapshot-root <directory>] [--allow-unverified-association]\nrecover writes a reviewable plan JSON; empty/missing hives trigger companion/RegBack/snapshot discovery. export consumes a plan JSON and writes a new hive plus report. Exit: 0 complete, 2 partial/invalid, 1 failure, 130 cancelled. Existing output files are never overwritten."); return 0;
    }
    string? Option(string name) { int p = Array.IndexOf(args, name); if (p < 0) return null; if (p + 1 == args.Length) throw new ArgumentException($"Missing value for {name}."); return args[p + 1]; }
    long Number(string name, long fallback) => Option(name) is { } n ? long.Parse(n, System.Globalization.CultureInfo.InvariantCulture) : fallback;
    var options = new RecoveryOptions(MaxScanBytes: Number("--max-bytes", 1L << 30), HiveBinsOffset: Number("--bins-offset", 4096));
    var snapshotRoots = new List<string>();
    for (int i = 2; i < args.Length; i++) if (args[i] == "--snapshot-root") { if (++i == args.Length) throw new ArgumentException("Missing snapshot root."); snapshotRoots.Add(args[i]); }
    void Emit(object value)
    {
        string text = JsonSerializer.Serialize(value, json);
        if (Option("--out") is { } path) { using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write); using var writer = new StreamWriter(file); writer.Write(text); }
        else Console.WriteLine(text);
    }
    if (args[0] == "export")
    {
        var plan = JsonSerializer.Deserialize<RecoveryPlan>(File.ReadAllText(args[1]), json) ?? throw new InvalidDataException("Empty plan.");
        if (Option("--candidate") is { } id) plan.SelectedCandidateId = id;
        string output = Option("--out") ?? throw new ArgumentException("export requires --out.");
        if (File.Exists(output) || File.Exists(output + ".report.json")) throw new IOException("Output or report already exists.");
        var exported = HiveWriter.Export(plan, new(args.Contains("--replace-missing-security")), cancellation.Token);
        using (var file = new FileStream(output, FileMode.CreateNew, FileAccess.Write)) file.Write(exported.Bytes);
        using (var file = new FileStream(output + ".report.json", FileMode.CreateNew, FileAccess.Write)) JsonSerializer.Serialize(file, exported.Report, json);
        Console.Error.WriteLine($"Wrote {exported.Report.KeysWritten} keys and {exported.Report.ValuesWritten} values. Complete: {exported.Report.Complete}");
        return exported.Report.Complete ? 0 : 2;
    }
    if (args[0] == "discover") { var search = ArtifactDiscovery.Discover(args[1], snapshotRoots, cancellationToken: cancellation.Token); Emit(search); return search.Findings.Count == 0 ? 0 : 2; }
    if (args[0] == "recover" && !args.Contains("--log"))
    {
        var plan = ArtifactDiscovery.RecoverFile(args[1], snapshotRoots, options, cancellationToken: cancellation.Token);
        if (Option("--candidate") is { } id) plan.SelectedCandidateId = id;
        Emit(plan); return plan.Candidates.Count > 0 && plan.Inspection.Findings.Count == 0 ? 0 : 2;
    }
    using var primary = new FileByteSource(args[1]);
    if (args[0] == "carve") { Emit(HiveCarver.Scan(primary, options.MaxScanBytes, cancellation.Token).ToList()); return primary.Length <= options.MaxScanBytes ? 0 : 2; }
    if (args[0] == "logs") { var log = TransactionLogs.Analyze(primary, options, cancellation.Token); Emit(log); return log.HeaderValid && log.Findings.Count == 0 ? 0 : 2; }
    IByteSource source = primary; var logAnalyses = new List<LogAnalysis>();
    for (int i = 2; i < args.Length; i++) if (args[i] == "--log") { if (++i == args.Length) throw new ArgumentException("Missing log path."); using var logSource = new FileByteSource(args[i]); logAnalyses.Add(TransactionLogs.Analyze(logSource, options, cancellation.Token)); }
    if (logAnalyses.Count > 0) source = TransactionLogs.Replay(primary, logAnalyses, args.Contains("--allow-unverified-association"), cancellation.Token);
    var inspection = new HiveInspector().Inspect(source, options, cancellationToken: cancellation.Token);
    foreach (var log in logAnalyses) { inspection.Findings.AddRange(log.Findings); inspection.Findings.Add(new("SelectedLogHistory", 0, $"Replayed explicitly selected log: {log.Source}. Association override: {args.Contains("--allow-unverified-association")}.")); }
    switch (args[0])
    {
        case "inspect": Emit(inspection); break;
        case "recover": var plan = Recovery.Plan(inspection, cancellation.Token); if (Option("--candidate") is { } id) plan.SelectedCandidateId = id; Emit(plan); break;
        case "validate": Emit(new { inspection.HeaderValid, inspection.Dirty, inspection.ScanComplete, Keys = inspection.Keys.Count, inspection.Findings }); break;
        default: throw new ArgumentException("Unknown command. Use --help.");
    }
    return inspection.HeaderValid && !inspection.Dirty && inspection.ScanComplete && inspection.Findings.Count == 0 ? 0 : 2;
}
catch (OperationCanceledException) { Console.Error.WriteLine("Cancelled."); return 130; }
catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or InvalidOperationException or JsonException or FormatException or OverflowException or PlatformNotSupportedException)
{ Console.Error.WriteLine(e.Message); return 1; }
