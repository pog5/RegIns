using System.Text;
using static RegIns.Binary;
namespace RegIns;

public sealed class HiveInspector
{
    public InspectionResult Inspect(IByteSource source, RecoveryOptions? options = null, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var o = options ?? new();
        if (o.MaxScanBytes < 1 || o.MaxRecords < 1 || o.MaxValueBytes < 0 || o.MaxEvidenceBytes < 0 || o.HiveBinsOffset < 0) throw new ArgumentOutOfRangeException(nameof(options));
        var r = new Reader(source); var result = new InspectionResult { Source = source.Id };
        if (source.Length == 0) result.Findings.Add(new("EmptyHive", 0, "Zero-byte hive. Search companion logs, RegBack and supplied snapshot roots."));
        var keyRecords = new Dictionary<long, byte[]>(); var values = new Dictionary<long, RecoveredValue>();
        long evidenceBytes = 0; int cellHeader = 4; uint minor = 5;
        long references = 0;
        const long maxReferences = 2_000_000;
        void Report(Finding finding) { if (result.Findings.Count < 10000) result.Findings.Add(finding); else result.ScanComplete = false; }
        var header = r.Get(0, 512);
        if (header is not null && header.AsSpan(0, 4).SequenceEqual("regf"u8))
        {
            minor = U32(header, 24); cellHeader = minor == 1 ? 8 : 4;
            result.HeaderValid = Checksum(header) == U32(header, 508) && U32(header, 20) == 1 && minor is >= 1 and <= 6 && U32(header, 28) == 0 && U32(header, 32) == 1;
            result.RootOffset = Ref(U32(header, 36)); result.Dirty = U32(header, 4) != U32(header, 8);
            if (minor is < 1 or > 6) Report(new("UnsupportedVersion", 24, $"Hive version 1.{minor}; records are heuristic only."));
            if (result.Dirty) Report(new("DirtyHive", 4, "Sequence numbers differ; transaction recovery may be required."));
        }
        if (!result.HeaderValid) Report(new("DamagedHeader", 0, "Header absent, unsupported or invalid; independent record scanning enabled."));
        long end = Math.Min(source.Length, o.MaxScanBytes);
        // Allocation ownership suppresses false signatures embedded in intact value data.
        // Once an allocation chain breaks, independent scanning still covers the remaining bytes.
        var allocations = new List<(long Start, long End, bool Free)>();
        for (long bin = o.HiveBinsOffset; bin + 32 <= end; bin += 4096)
        {
            cancellationToken.ThrowIfCancellationRequested(); var bh = r.Get(bin, 32);
            if (bh is null || !bh.AsSpan(0, 4).SequenceEqual("hbin"u8) || U32(bh, 4) != bin - o.HiveBinsOffset) continue;
            long binSize = U32(bh, 8); if (binSize < 4096 || binSize % 4096 != 0 || binSize > end - bin) continue;
            for (long cell = bin + 32; cell + cellHeader <= bin + binSize;)
            {
                var sz = r.Get(cell, 4); if (sz is null) break; int signed = unchecked((int)U32(sz, 0)); long size = Math.Abs((long)signed);
                if (size < cellHeader + 4 || size % (minor == 1 ? 16 : 8) != 0 || size > bin + binSize - cell) { Report(new("BrokenAllocationChain", cell, "Cell chain invalid; independent scanning continues.")); break; }
                allocations.Add((cell, cell + size, signed > 0)); cell += size;
                if (allocations.Count >= o.MaxRecords * 4L) break;
            }
            bin += binSize - 4096;
        }
        int allocationIndex = 0;
        byte[] block = new byte[65538], readable = new byte[65538];
        for (long baseOffset = 0; baseOffset < end; baseOffset += 65536)
        {
            cancellationToken.ThrowIfCancellationRequested(); int count = (int)Math.Min(block.Length, end - baseOffset);
            source.Read(baseOffset, block.AsSpan(0, count), readable.AsSpan(0, count));
            if (readable.AsSpan(0, Math.Min(65536, count)).Contains((byte)0)) Report(new("UnreadableSourceRange", baseOffset, "Scan block includes unreadable bytes; independent readable regions are still scanned."));
            for (int p = 0; p < Math.Min(65536, count - 1); p++)
            {
                if ((p & 4095) == 0) cancellationToken.ThrowIfCancellationRequested();
                if (readable[p] == 0 || readable[p + 1] == 0) continue;
                bool nk = block[p] == 'n' && block[p + 1] == 'k'; bool vk = block[p] == 'v' && block[p + 1] == 'k';
                if (!nk && !vk) continue;
                long pos = baseOffset + p, cell = pos - cellHeader;
                if (cell < 0) continue;
                while (allocationIndex < allocations.Count && allocations[allocationIndex].End <= cell) allocationIndex++;
                bool insideFree = false;
                if (allocationIndex < allocations.Count && allocations[allocationIndex].Start <= cell && cell < allocations[allocationIndex].End)
                {
                    var owner = allocations[allocationIndex]; insideFree = owner.Free;
                    if (!owner.Free && owner.Start != cell) continue;
                }
                int fixedLength = nk ? 76 : 20;
                var b = r.Get(pos, fixedLength); if (b is null) continue;
                int nameLength = U16(b, nk ? 72 : 2);
                bool compressed = minor != 1 && (U16(b, nk ? 2 : 16) & (nk ? 32 : 1)) != 0;
                if (nameLength > 32766 || (nk && nameLength == 0) || (!compressed && nameLength % 2 != 0)) continue;
                var raw = r.Get(pos, fixedLength + nameLength); if (raw is null) continue;
                string name;
                try { name = (compressed ? Encoding.Latin1 : new UnicodeEncoding(false, false, true)).GetString(raw, fixedLength, nameLength); }
                catch (DecoderFallbackException) { continue; }
                if (name.Contains('\0') || (nk && name.Contains('\\'))) continue;
                var sizeBytes = r.Get(cell, 4); int size = sizeBytes is null ? 0 : unchecked((int)U32(sizeBytes, 0));
                long absolute = Math.Abs((long)size);
                bool validCell = absolute >= fixedLength + nameLength + cellHeader && absolute % (minor == 1 ? 16 : 8) == 0 && absolute <= source.Length - cell;
                // A damaged cell header is allowed, but record-specific metadata must still be plausible.
                if (!validCell && nk && (U16(b, 2) & 0x0043) != 0) continue;
                if (evidenceBytes + raw.Length > o.MaxEvidenceBytes || keyRecords.Count + values.Count >= o.MaxRecords) { result.ScanComplete = false; goto DoneScan; }
                evidenceBytes += raw.Length;
                var ev = new Evidence(source.Id, pos, raw.Length, validCell ? "record-and-cell" : "record-only", raw);
                if (!validCell) Report(new("DamagedCellHeader", cell, "Record recognized independently of its cell size; allocation state is uncertain."));
                if (nk)
                {
                    var key = new RecoveredKey { Offset = cell, Name = name, Flags = U16(b, 2), Timestamp = I64(b, 4), ParentOffset = Ref(U32(b, 16)), Deleted = insideFree || validCell && size > 0, Evidence = ev };
                    result.Keys.Add(key); keyRecords[cell] = b;
                }
                else values[cell] = new RecoveredValue { Offset = cell, Name = name, Type = U32(b, 12), DeclaredLength = U32(b, 4) & 0x7fffffff, Evidence = ev };
            }
            progress?.Report(new(Math.Min(baseOffset + 65536, end), end, keyRecords.Count + values.Count));
        }
        DoneScan:
        if (end < source.Length) result.ScanComplete = false;
        if (!result.ScanComplete) Report(new("ResourceLimit", end, "Scan stopped at configured byte, record, or evidence budget."));
        // References can identify records whose type signature itself was destroyed.
        // Preserve the original bytes; never patch the input to make it look valid.
        var pendingKeys = new Queue<long>(); var attemptedKeys = new HashSet<long>();
        foreach (var key in result.Keys) { pendingKeys.Enqueue(key.ParentOffset); foreach (long child in ReadIndex(Ref(U32(keyRecords[key.Offset], 28)), new())) pendingKeys.Enqueue(child); }
        pendingKeys.Enqueue(result.RootOffset);
        while (pendingKeys.TryDequeue(out long target) && keyRecords.Count + values.Count < o.MaxRecords && attemptedKeys.Count < o.MaxRecords)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (target < 0 || target >= end || keyRecords.ContainsKey(target) || !attemptedKeys.Add(target)) continue;
            var b = r.Get(target + cellHeader, 76); var sizeBytes = r.Get(target, 4);
            if (b is null || sizeBytes is null) continue;
            int signed = unchecked((int)U32(sizeBytes, 0)); long size = Math.Abs((long)signed);
            int length = U16(b, 72); bool compressed = minor != 1 && (U16(b, 2) & 32) != 0;
            if (length == 0 || length > 510 || !compressed && length % 2 != 0 || signed >= 0 || size < cellHeader + 76 + length || size % (minor == 1 ? 16 : 8) != 0 || size > source.Length - target) continue;
            var raw = r.Get(target + cellHeader, 76 + length); if (raw is null || evidenceBytes + raw.Length > o.MaxEvidenceBytes) continue;
            string name;
            try { name = (compressed ? Encoding.Latin1 : new UnicodeEncoding(false, false, true)).GetString(raw, 76, length); } catch (DecoderFallbackException) { continue; }
            if (name.Contains('\0') || name.Contains('\\')) continue;
            evidenceBytes += raw.Length;
            var key = new RecoveredKey { Offset = target, Name = name, Flags = U16(b, 2), Timestamp = I64(b, 4), ParentOffset = Ref(U32(b, 16)), Evidence = new(source.Id, target + cellHeader, raw.Length, "reference-and-cell-with-damaged-signature", raw) };
            result.Keys.Add(key); keyRecords[target] = b; pendingKeys.Enqueue(key.ParentOffset);
            foreach (long child in ReadIndex(Ref(U32(b, 28)), new())) pendingKeys.Enqueue(child);
            Report(new("ReconstructedKeySignature", target, "Key recognized from incoming references, valid cell bounds and surviving key fields."));
        }
        var owned = new HashSet<long>(); var keys = result.Keys.ToDictionary(k => k.Offset);
        foreach (var key in result.Keys)
        {
            cancellationToken.ThrowIfCancellationRequested(); var b = keyRecords[key.Offset];
            if (keys.ContainsKey(key.ParentOffset)) result.Relationships.Add(new(key.ParentOffset, key.Offset, "parent-pointer"));
            var children = ReadIndex(Ref(U32(b, 28)), new HashSet<long>());
            foreach (long child in children) if (keys.ContainsKey(child)) result.Relationships.Add(new(key.Offset, child, "subkey-index"));
            if ((uint)children.Count != U32(b, 20)) Report(new("SubkeyCountMismatch", key.Offset, "Subkey index is missing, damaged or inconsistent."));
            uint valueCount = U32(b, 36); long listOffset = Ref(U32(b, 40));
            if (valueCount > o.MaxRecords) { Report(new("ValueCountLimit", key.Offset, "Value count exceeds resource limit.")); valueCount = (uint)o.MaxRecords; }
            for (int i = 0; i < valueCount; i++)
            {
                if (++references > maxReferences) { result.ScanComplete = false; Report(new("ReferenceBudget", key.Offset, "Reference traversal budget exhausted.")); break; }
                cancellationToken.ThrowIfCancellationRequested(); var link = r.Get(listOffset < 0 ? -1 : listOffset + cellHeader + i * 4L, 4);
                if (link is null || !values.TryGetValue(Ref(U32(link, 0)), out var value)) { Report(new("MissingValue", key.Offset, $"Value list entry {i} unavailable.")); continue; }
                if (!owned.Add(value.Offset)) Report(new("SharedValue", value.Offset, "Value referenced by more than one key."));
                key.Values.Add(value);
            }
            ushort classLength = U16(b, 74);
            if (classLength > 0) { key.ClassData = ReadCellData(Ref(U32(b, 48)), classLength) ?? []; if (key.ClassData.Length != classLength) Report(new("MissingClass", key.Offset, "Class bytes are unavailable.")); }
            long sk = Ref(U32(b, 44)); var security = r.Get(sk < 0 ? -1 : sk + cellHeader, 20);
            if (security is not null && security.AsSpan(0, 2).SequenceEqual("sk"u8) && U32(security, 16) is >= 20 and <= 65536)
                key.SecurityDescriptor = ReadCellData(sk, checked(20 + (int)U32(security, 16)))?[20..];
            if (key.SecurityDescriptor is null) Report(new("MissingSecurity", key.Offset, "Security descriptor unavailable; export requires an explicit replacement policy."));
        }
        foreach (var v in values.Values)
        {
            cancellationToken.ThrowIfCancellationRequested(); var b = v.Evidence.Raw;
            if (v.DeclaredLength > o.MaxValueBytes || evidenceBytes + v.DeclaredLength > o.MaxEvidenceBytes) { Report(new("ValueDataLimit", v.Offset, "Payload exceeds configured resource budget.")); continue; }
            evidenceBytes += v.DeclaredLength;
            if ((U32(b, 4) & 0x80000000) != 0)
            {
                if (v.DeclaredLength <= 4) { v.Extents.Add(new(0, b.AsSpan(8, (int)v.DeclaredLength).ToArray())); v.Complete = true; }
            }
            else if (v.DeclaredLength == 0) v.Complete = true;
            else
            {
                long dataCell = Ref(U32(b, 8)); var db = r.Get(dataCell < 0 ? -1 : dataCell + cellHeader, 8);
                if (minor >= 5 && v.DeclaredLength > 16344 && db is not null && db.AsSpan(0, 2).SequenceEqual("db"u8))
                {
                    int segments = U16(db, 2); long segList = Ref(U32(db, 4));
                    for (int i = 0; i < segments && (long)i * 16344 < v.DeclaredLength; i++)
                    {
                        cancellationToken.ThrowIfCancellationRequested(); var link = r.Get(segList < 0 ? -1 : segList + cellHeader + i * 4L, 4);
                        if (link is not null) AddData(v, Ref(U32(link, 0)), i * 16344, (int)Math.Min(16344, v.DeclaredLength - (long)i * 16344));
                    }
                }
                else AddData(v, dataCell, 0, (int)v.DeclaredLength);
                v.Complete = v.Extents.Sum(e => (long)e.Bytes.Length) == v.DeclaredLength;
            }
            if (!v.Complete) Report(new("IncompleteValue", v.Offset, "Some payload bytes are unavailable or structurally unverified; available extents retained."));
        }
        result.UnownedValues = values.Values.Where(v => !owned.Contains(v.Offset)).OrderBy(v => v.Offset).ToList();
        return result;

        long Ref(uint offset) => offset == uint.MaxValue ? -1 : checked(o.HiveBinsOffset + offset);
        byte[]? ReadCellData(long cell, int length)
        {
            var s = r.Get(cell, 4); if (s is null) return null; long size = Math.Abs((long)unchecked((int)U32(s, 0)));
            return size >= (long)length + cellHeader && size % (minor == 1 ? 16 : 8) == 0 ? r.Get(cell + cellHeader, length) : null;
        }
        void AddData(RecoveredValue v, long cell, int logical, int length)
        {
            var s = r.Get(cell, 4); if (s is null) return; long size = Math.Abs((long)unchecked((int)U32(s, 0)));
            if (size < cellHeader || size % (minor == 1 ? 16 : 8) != 0) return;
            int take = (int)Math.Min(length, size - cellHeader);
            // Preserve readable runs without inventing bytes across holes.
            byte[] bytes = new byte[take], mask = new byte[take]; source.Read(cell + cellHeader, bytes, mask);
            for (int i = 0; i < take;) { if (mask[i] == 0) { i++; continue; } int begin = i++; while (i < take && mask[i] != 0) i++; v.Extents.Add(new(logical + begin, bytes.AsSpan(begin, i - begin).ToArray())); }
        }
        List<long> ReadIndex(long cell, HashSet<long> visited)
        {
            var output = new List<long>(); var pending = new Stack<long>(); pending.Push(cell);
            while (pending.TryPop(out long current) && visited.Count < o.MaxRecords)
            {
                cancellationToken.ThrowIfCancellationRequested(); if (!visited.Add(current)) { Report(new("IndexCycle", current, "Repeated index reference.")); continue; }
                var b = r.Get(current < 0 ? -1 : current + cellHeader, 4); if (b is null) continue;
                string sig = Encoding.ASCII.GetString(b, 0, 2); if (sig is not ("li" or "lf" or "lh" or "ri")) continue;
                int stride = sig is "lf" or "lh" ? 8 : 4, n = U16(b, 2);
                for (int i = 0; i < n && output.Count + pending.Count < o.MaxRecords; i++)
                { if (++references > maxReferences) { result.ScanComplete = false; break; } var link = r.Get(current + cellHeader + 4 + i * (long)stride, 4); if (link is null) break; long target = Ref(U32(link, 0)); if (sig == "ri") pending.Push(target); else output.Add(target); }
            }
            return output;
        }
    }
}
