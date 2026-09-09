namespace RegIns;

public sealed record RecoveryArtifact(string Path, long Length, string Kind, string Origin);
public sealed record ArtifactSearchResult(List<RecoveryArtifact> Artifacts, List<Finding> Findings);

public static class ArtifactDiscovery
{
    // Snapshot roots are ordinary mounted/extracted directories on every platform.
    // No snapshot creation, mounting, filesystem repair or OS registry access occurs here.
    public static ArtifactSearchResult Discover(string primaryPath, IEnumerable<string>? snapshotRoots = null, int maxEntries = 100000, CancellationToken cancellationToken = default)
    {
        if (maxEntries < 1) throw new ArgumentOutOfRangeException(nameof(maxEntries));
        string full = Path.GetFullPath(primaryPath), name = Path.GetFileName(full), directory = Path.GetDirectoryName(full)!;
        var artifacts = new List<RecoveryArtifact>(); var findings = new List<Finding>();
        var seen = new HashSet<string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        var roots = new List<(string Path, string Origin, bool Recursive)> { (directory, "adjacent", false), (Path.Combine(directory, "RegBack"), "RegBack", false) };
        if (snapshotRoots is not null) roots.AddRange(snapshotRoots.Select(p => (Path.GetFullPath(p), "snapshot-or-backup-root", true)));
        int visited = 0;
        foreach (var root in roots)
        {
            var pending = new Stack<string>(); pending.Push(root.Path);
            while (pending.TryPop(out string? current))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!Directory.Exists(current)) { if (root.Origin == "snapshot-or-backup-root") findings.Add(new("UnavailableSearchRoot", 0, current)); continue; }
                try
                {
                    foreach (var entry in new DirectoryInfo(current).EnumerateFileSystemInfos())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        if (++visited > maxEntries) { findings.Add(new("DiscoveryLimit", 0, "Directory-entry budget exhausted.")); return new(artifacts, findings); }
                        if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                        if (entry is DirectoryInfo) { if (root.Recursive) pending.Push(entry.FullName); continue; }
                        bool exact = entry.Name.Equals(name, StringComparison.OrdinalIgnoreCase);
                        bool companion = entry.Name.StartsWith(name + ".", StringComparison.OrdinalIgnoreCase) || entry.Name.StartsWith(name + "{", StringComparison.OrdinalIgnoreCase);
                        if (!exact && !companion || !seen.Add(entry.FullName)) continue;
                        string kind = exact ? (entry.FullName.Equals(full, OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) ? "primary" : "backup") : entry.Name.EndsWith(".regtrans-ms", StringComparison.OrdinalIgnoreCase) || entry.Name.EndsWith(".blf", StringComparison.OrdinalIgnoreCase) ? "TxR/CLFS" : entry.Name.Contains(".LOG", StringComparison.OrdinalIgnoreCase) ? "hive-log" : "backup";
                        long length = ((FileInfo)entry).Length; artifacts.Add(new(entry.FullName, length, kind, root.Origin));
                        if (length == 0) findings.Add(new("EmptyArtifact", 0, $"{entry.FullName}: zero bytes; cannot recover data from this artifact alone."));
                    }
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { findings.Add(new("DiscoveryAccess", 0, $"{current}: {e.Message}")); }
            }
        }
        artifacts.Sort((a, b) => StringComparer.Ordinal.Compare(a.Path, b.Path)); return new(artifacts, findings);
    }

    public static RecoveryPlan RecoverFile(string path, IEnumerable<string>? snapshotRoots = null, RecoveryOptions? options = null, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var search = Discover(path, snapshotRoots, cancellationToken: cancellationToken);
        InspectionResult inspection;
        if (File.Exists(path)) { using var source = new FileByteSource(path); inspection = new HiveInspector().Inspect(source, options, progress, cancellationToken); }
        else inspection = new InspectionResult { Source = Path.GetFullPath(path), Findings = [new("MissingPrimary", 0, "Primary file missing; searching companion artifacts.")] };
        var plan = Recovery.Plan(inspection, cancellationToken);
        if (plan.Candidates.Count == 0)
        {
            // Do not merge generations. Rank complete backup candidates by recovered active-key count.
            foreach (var artifact in search.Artifacts.Where(a => a.Kind == "backup" && a.Length > 0))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    using var backup = new FileByteSource(artifact.Path); var alternate = new HiveInspector().Inspect(backup, options, progress, cancellationToken); var candidatePlan = Recovery.Plan(alternate, cancellationToken);
                    search.Findings.Add(new("BackupCandidate", 0, $"{artifact.Path}: {alternate.Keys.Count} records; header valid: {alternate.HeaderValid}."));
                    if (candidatePlan.Candidates.Count != 0 && (plan.Candidates.Count == 0 || alternate.HeaderValid && !plan.Inspection.HeaderValid || alternate.HeaderValid == plan.Inspection.HeaderValid && alternate.Keys.Count > plan.Inspection.Keys.Count)) plan = candidatePlan;
                }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { search.Findings.Add(new("BackupUnreadable", 0, $"{artifact.Path}: {e.Message}")); }
            }
            foreach (var artifact in search.Artifacts.Where(a => a.Kind is "hive-log" or "TxR/CLFS" && a.Length > 0))
            {
                using var logSource = new FileByteSource(artifact.Path); var log = TransactionLogs.Analyze(logSource, options, cancellationToken); search.Findings.AddRange(log.Findings);
                if (!log.HeaderValid || log.Entries.Count == 0) continue;
                try
                {
                    using var empty = new MemoryByteSource([], "missing-primary:" + Path.GetFullPath(path)); using var reconstructed = TransactionLogs.Replay(empty, [log], true, cancellationToken);
                    var alternate = new HiveInspector().Inspect(reconstructed, options, progress, cancellationToken); var candidatePlan = Recovery.Plan(alternate, cancellationToken);
                    search.Findings.Add(new("LogOnlyCandidate", 0, $"{artifact.Path}: {alternate.Keys.Count} keys; unreadable untouched pages preserved. Association inferred from filename only."));
                    if (plan.Candidates.Count == 0 && candidatePlan.Candidates.Count != 0) plan = candidatePlan;
                }
                catch (InvalidOperationException e) { search.Findings.Add(new("LogOnlyRecoveryRejected", 0, $"{artifact.Path}: {e.Message}")); }
            }
        }
        plan.Inspection.Findings.AddRange(search.Findings);
        if (plan.Inspection.Source != inspection.Source) plan.Inspection.Findings.Add(new("AlternateSourceSelected", 0, $"Primary {inspection.Source} had no recoverable tree. Selected {plan.Inspection.Source}; other generations were not merged."));
        return plan;
    }
}
