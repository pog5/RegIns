using RegIns;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

if (args.Length == 3 && args[0] == "--corpus") { Environment.ExitCode = CorpusChecks.Run(args[1], args[2]) == 0 ? 0 : 1; return; }

if (args.Length == 3 && args[0] == "--diagnose-export")
{
    using var input = new FileByteSource(args[1]); var state = new HiveInspector().Inspect(input); var plan = Recovery.Plan(state); var chosen = plan.Candidates.Single(c => c.Id == plan.SelectedCandidateId);
    foreach (int count in new[] { 1, 2, 3, 5, 10, 100, 1000, 10000, 40000 })
    {
        var offsets = chosen.KeyOffsets.Take(count).Append(chosen.RootOffset).Distinct().ToList();
        plan.Candidates = [chosen with { KeyOffsets = offsets }]; var output = HiveWriter.Export(plan); File.WriteAllBytes(args[2] + count + ".hive", output.Bytes);
    }
    var rootSecurity = state.Keys.Single(k => k.Offset == chosen.RootOffset).SecurityDescriptor;
    foreach (var k in state.Keys) k.SecurityDescriptor = rootSecurity;
    plan.Candidates = [chosen]; File.WriteAllBytes(args[2] + "uniform-security.hive", HiveWriter.Export(plan).Bytes);
    return;
}

int passed = 0;
void Check(bool ok, string message) { if (!ok) throw new Exception(message); }
void Test(string name, Action test) { test(); passed++; Console.WriteLine($"PASS {name}"); }
RecoveredValue Value(string name, byte[] data) => new() { Name = name, Type = 3, Complete = true, DeclaredLength = (uint)data.Length, Extents = [new(0, data)] };
byte[] Security() { var b = new byte[20]; b[0] = 1; BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(2), 0x8004); return b; }
var root = new RecoveredKey { Offset = 4128, Name = "ROOT", Flags = 12, SecurityDescriptor = Security(), Values = [Value("inline", [1, 2, 3]), Value("large", Enumerable.Range(0, 50000).Select(i => (byte)i).ToArray())] };
var child = new RecoveredKey { Offset = 4256, Name = "Child", ParentOffset = root.Offset, SecurityDescriptor = Security(), ClassData = Encoding.Unicode.GetBytes("class"), Values = [Value("", [0, 0, 0, 0])] };
var inspection = new InspectionResult { HeaderValid = true, RootOffset = root.Offset, Keys = [root, child] };
byte[] fixture = HiveWriter.Export(Recovery.Plan(inspection)).Bytes;
var inspector = new HiveInspector();
InspectionResult Read(byte[] bytes, byte[]? mask = null) { using var source = new MemoryByteSource(bytes, readability: mask); return inspector.Inspect(source); }
Test("clean round trip, inline and segmented data", () => { var i = Read(fixture); Check(i.HeaderValid && i.Keys.Count == 2 && i.Keys.Sum(k => k.Values.Count) == 3, "counts"); Check(i.Keys.SelectMany(k => k.Values).All(v => v.Complete), "complete"); Check(i.Keys.Single(k => k.Name == "Child").ClassData.SequenceEqual(child.ClassData), "class"); Check(HiveWriter.Export(Recovery.Plan(i)).Bytes.SequenceEqual(HiveWriter.Export(Recovery.Plan(i)).Bytes), "determinism"); });
Test("destroyed base and bin headers", () => { var b = fixture.ToArray(); Array.Clear(b, 0, 4128); var i = Read(b); Check(!i.HeaderValid && i.Keys.Count == 2, "salvage without headers"); });
Test("destroyed key cell size", () => { var b = fixture.ToArray(); Array.Clear(b, 4128, 4); var i = Read(b); Check(i.Keys.Any(k => k.Name == "ROOT"), "root salvaged"); Check(i.Findings.Any(f => f.Code == "DamagedCellHeader"), "evidence"); });
Test("zero-byte source", () => Check(Read([]).Keys.Count == 0, "empty"));
Test("partial unreadable payload", () => { var i = Read(fixture); var v = i.Keys.SelectMany(k => k.Values).Single(v => v.Name == "large"); var b = fixture.ToArray(); var mask = Enumerable.Repeat((byte)1, b.Length).ToArray(); int db = 4096 + (int)BinaryPrimitives.ReadUInt32LittleEndian(v.Evidence.Raw.AsSpan(8)); int list = 4096 + (int)BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(db + 8)); int segment = 4096 + (int)BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(list + 4)); mask[segment + 100] = 0; var partial = Read(b, mask).Keys.SelectMany(k => k.Values).Single(v => v.Name == "large"); Check(!partial.Complete && partial.Extents.Count >= 2, "holes preserved"); });
Test("bounded scanning and cancellation", () => { using var s = new MemoryByteSource(fixture); Check(!inspector.Inspect(s, new(MaxScanBytes: 100)).ScanComplete, "byte budget"); using var c = new CancellationTokenSource(); c.Cancel(); try { inspector.Inspect(s, cancellationToken: c.Token); throw new Exception("not cancelled"); } catch (OperationCanceledException) { } });
Test("noise and malformed record fuzz", () => { var rng = new Random(719); for (int i = 0; i < 100; i++) { byte[] b = new byte[16384]; rng.NextBytes(b); for (int p = 0; p < b.Length - 100; p += 113) { b[p] = (byte)(i % 2 == 0 ? 'n' : 'v'); b[p + 1] = (byte)'k'; } using var s = new MemoryByteSource(b); var result = inspector.Inspect(s, new(MaxRecords: 100, MaxValueBytes: 1024, MaxEvidenceBytes: 4096)); Check(result.Keys.Count <= 100, "record budget"); } });
Test("carve misaligned image", () => { byte[] b = new byte[fixture.Length + 37]; fixture.CopyTo(b, 37); using var s = new MemoryByteSource(b); Check(HiveCarver.Scan(s).Any(c => c.Kind == "hive" && c.Offset == 37), "embedded hive"); using var slice = new SliceByteSource(s, 37, fixture.Length); Check(inspector.Inspect(slice).HeaderValid, "slice"); });
Test("untrusted sparse source differs from zero bytes", () => { using var source = new MemoryByteSource([0, 0], readability: [1, 0]); byte[] b = new byte[2], m = new byte[2]; source.Read(0, b, m); Check(b[0] == b[1] && m[0] != m[1], "readability"); });
Test("I/O fault skips unreadable page and preserves later data", () => { using var stream = new FaultingStream(Enumerable.Repeat((byte)7,8192).ToArray()); using (var source = new StreamByteSource(stream)) { byte[] b = new byte[8192], m = new byte[8192]; source.Read(0,b,m); Check(m[0]==0 && m[4096]==1 && b[4096]==7,"read continued after I/O fault"); } Check(stream.CanRead,"caller owns stream"); });
Test("reject cyclic export", () => { var i = Read(fixture); var p = Recovery.Plan(i); var c = i.Keys.Single(k => k.Name == "Child"); c.ParentOffset = c.Offset; try { HiveWriter.Export(p); throw new Exception("cycle accepted"); } catch (InvalidOperationException) { } });
Test("input bytes untouched", () => { var hash = SHA256.HashData(fixture); _ = HiveWriter.Export(Recovery.Plan(Read(fixture))); Check(hash.SequenceEqual(SHA256.HashData(fixture)), "input changed"); });
void W32(byte[] b, int p, uint n) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p), n);
void FixHeader(byte[] b) { uint sum = 0; for (int i = 0; i < 508; i += 4) sum ^= BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(i)); W32(b, 508, sum == 0 ? 1 : sum == uint.MaxValue ? sum - 1 : sum); }
byte[] ModernLog(uint sequence)
{
    byte[] log = new byte[1536]; fixture.AsSpan(0, 512).CopyTo(log); W32(log, 4, sequence); W32(log, 8, sequence); W32(log, 28, 6); FixHeader(log);
    "HvLE"u8.CopyTo(log.AsSpan(512)); W32(log, 516, 1024); W32(log, 524, sequence); W32(log, 528, (uint)(fixture.Length - 4096)); W32(log, 532, 1); W32(log, 552, 0); W32(log, 556, 512); fixture.AsSpan(4096, 512).CopyTo(log.AsSpan(560));
    BinaryPrimitives.WriteUInt64LittleEndian(log.AsSpan(536), TransactionLogs.Marvin(log.AsSpan(552, 984))); BinaryPrimitives.WriteUInt64LittleEndian(log.AsSpan(544), TransactionLogs.Marvin(log.AsSpan(512, 32))); return log;
}
Test("Marvin independent oracle vectors", () => { Check(TransactionLogs.Marvin([]) == 0xb39efca403966e08, "empty vector"); Check(TransactionLogs.Marvin([0,1,2,3]) == 0x2929e21ee85929f2, "four bytes"); Check(TransactionLogs.Marvin(Enumerable.Range(0,32).Select(i=>(byte)i).ToArray()) == 0xc64feee425c2e24c, "32 bytes"); });
Test("modern log integrity and isolated replay", () => { var bytes = ModernLog(2); using var s = new MemoryByteSource(bytes); var log = TransactionLogs.Analyze(s); Check(log.HeaderValid && log.Entries.Count == 1, "valid log"); byte[] dirty = fixture.ToArray(); W32(dirty,4,2); FixHeader(dirty); using var primary = new MemoryByteSource(dirty); using var replay = TransactionLogs.Replay(primary,[log],true); Check(!inspector.Inspect(replay).Dirty, "replayed"); bytes[600] ^= 1; using var corrupt = new MemoryByteSource(bytes); Check(TransactionLogs.Analyze(corrupt).Entries.Count == 0, "hash rejection"); });
Test("headerless log entry recovery", () => { var bytes = ModernLog(2); Array.Clear(bytes,0,512); using var s = new MemoryByteSource(bytes); var log = TransactionLogs.Analyze(s); Check(!log.HeaderValid && log.Entries.Count == 1, "headerless entry"); });
Test("duplicate and discontinuous histories rejected", () => { using var s = new MemoryByteSource(ModernLog(2)); using var t = new MemoryByteSource(ModernLog(4)); var l = TransactionLogs.Analyze(s); var l4 = TransactionLogs.Analyze(t); byte[] dirty = fixture.ToArray(); W32(dirty,4,2); FixHeader(dirty); using var primary = new MemoryByteSource(dirty); foreach (var logs in new[] { new[] { l,l },new[] { l,l4 } }) { try { using var replay = TransactionLogs.Replay(primary,logs,true); throw new Exception("invalid history accepted"); } catch (InvalidOperationException) { } } });
Test("legacy bitmap replay", () => { byte[] log = new byte[1536]; fixture.AsSpan(0,512).CopyTo(log); W32(log,4,2); W32(log,8,2); W32(log,28,1); FixHeader(log); "DIRT"u8.CopyTo(log.AsSpan(512)); log[516]=1; fixture.AsSpan(4096,512).CopyTo(log.AsSpan(1024)); using var s = new MemoryByteSource(log); var a = TransactionLogs.Analyze(s); Check(a.HeaderValid && a.Entries.Count==1 && a.Entries[0].Pages.Count==1,"legacy"); });
Test("zero primary discovers RegBack and snapshots", () => { string folder = Path.Combine(Path.GetTempPath(),"RegIns-tests-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(Path.Combine(folder,"RegBack")); File.WriteAllBytes(Path.Combine(folder,"SYSTEM"),[]); File.WriteAllBytes(Path.Combine(folder,"RegBack","SYSTEM"),fixture); var p = ArtifactDiscovery.RecoverFile(Path.Combine(folder,"SYSTEM")); Check(p.Candidates.Count>0 && p.Inspection.Findings.Any(f=>f.Code=="AlternateSourceSelected"),"backup fallback"); Check(ArtifactDiscovery.Discover(Path.Combine(folder,"SYSTEM"),[folder]).Artifacts.Any(a=>a.Kind=="backup"),"snapshot roots"); });
if (args.Length == 2 && args[0] == "--fixture") File.WriteAllBytes(args[1], fixture);
Console.WriteLine($"{passed} tests passed.");

sealed class FaultingStream(byte[] bytes) : MemoryStream(bytes)
{
    public override int Read(Span<byte> buffer) { if (Position < 4096) throw new IOException("Synthetic unreadable page"); return base.Read(buffer); }
}
