namespace RegIns;

public sealed record RecoveryOptions(long MaxScanBytes = 1L << 30, int MaxRecords = 250_000, int MaxValueBytes = 16 << 20, long MaxEvidenceBytes = 256L << 20, long HiveBinsOffset = 4096);
public sealed record ScanProgress(long BytesScanned, long TotalBytes, int Records);
public sealed record Finding(string Code, long Offset, string Message);
public sealed record Evidence(string Source, long Offset, int Length, string Strength, byte[] Raw);
public sealed record DataExtent(int LogicalOffset, byte[] Bytes);
public sealed class RecoveredValue
{
    public long Offset { get; set; }
    public string Name { get; set; } = "";
    public uint Type { get; set; }
    public uint DeclaredLength { get; set; }
    public bool Complete { get; set; }
    public List<DataExtent> Extents { get; set; } = [];
    public Evidence Evidence { get; set; } = new("", 0, 0, "", []);
}
public sealed class RecoveredKey
{
    public long Offset { get; set; }
    public string Name { get; set; } = "";
    public long ParentOffset { get; set; } = -1;
    public ushort Flags { get; set; }
    public long Timestamp { get; set; }
    public byte[] ClassData { get; set; } = [];
    public byte[]? SecurityDescriptor { get; set; }
    public bool Deleted { get; set; }
    public List<RecoveredValue> Values { get; set; } = [];
    public Evidence Evidence { get; set; } = new("", 0, 0, "", []);
}
public sealed record Relationship(long Parent, long Child, string Evidence);
public sealed class InspectionResult
{
    public string Source { get; set; } = "";
    public bool HeaderValid { get; set; }
    public bool Dirty { get; set; }
    public bool ScanComplete { get; set; } = true;
    public long RootOffset { get; set; } = -1;
    public List<RecoveredKey> Keys { get; set; } = [];
    public List<RecoveredValue> UnownedValues { get; set; } = [];
    public List<Relationship> Relationships { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
}
public sealed record RecoveryCandidate(string Id, long RootOffset, List<long> KeyOffsets, string Reason);
public sealed class RecoveryPlan
{
    public InspectionResult Inspection { get; set; } = new();
    public List<RecoveryCandidate> Candidates { get; set; } = [];
    public string? SelectedCandidateId { get; set; }
    public List<long> IncludedSalvageOffsets { get; set; } = [];
    public Dictionary<long, long> ParentOverrides { get; set; } = [];
}
public sealed record RecoveryReport(bool StructuralValidationPassed, bool Complete, int KeysWritten, int ValuesWritten, List<Finding> Findings);
public sealed record CarvedRegion(long Offset, long Length, string Kind, string Evidence);
