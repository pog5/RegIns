using System.Text;
using static RegIns.Binary;
namespace RegIns;

public sealed record ExportOptions(bool ReplaceMissingSecurity = false, int MaxOutputBytes = 512 << 20);
public sealed record HiveExport(byte[] Bytes, RecoveryReport Report);

public static class HiveWriter
{
    public static HiveExport Export(RecoveryPlan plan, ExportOptions? options = null, CancellationToken cancellationToken = default)
    {
        var o = options ?? new();
        var candidate = plan.Candidates.SingleOrDefault(c => c.Id == plan.SelectedCandidateId) ?? throw new InvalidOperationException("Select a recovery candidate before export.");
        var all = plan.Inspection.Keys.ToDictionary(k => k.Offset);
        var selected = candidate.KeyOffsets.Concat(plan.IncludedSalvageOffsets).Distinct().Select(id => all[id]).OrderBy(k => k.Offset).ToList();
        var root = all[candidate.RootOffset]; var findings = new List<Finding>(plan.Inspection.Findings);
        var selectedIds = selected.Select(k => k.Offset).ToHashSet();
        var parents = new Dictionary<long, long>();
        long Parent(RecoveredKey key) => plan.ParentOverrides.GetValueOrDefault(key.Offset, key.ParentOffset);
        foreach (var k in selected.Where(k => k != root))
        {
            long parent = selectedIds.Contains(Parent(k)) ? Parent(k) : root.Offset;
            var chain = new HashSet<long> { k.Offset }; long cursor = parent;
            while (cursor != root.Offset && selectedIds.Contains(cursor)) { if (!chain.Add(cursor)) throw new InvalidOperationException("Selected parent relationships contain a cycle; adjust selection before export."); cursor = Parent(all[cursor]); }
            parents[k.Offset] = parent;
            if (parent != k.ParentOffset) findings.Add(new("ReparentedSalvage", k.Offset, plan.ParentOverrides.ContainsKey(k.Offset) ? "Parent relationship reconstructed from index evidence or explicit override." : "Explicitly selected orphan attached to output root."));
        }
        var children = selected.Where(k => k != root).GroupBy(k => parents[k.Offset]).ToDictionary(g => g.Key, g => g.OrderBy(k => k.Name, StringComparer.OrdinalIgnoreCase).ToList());
        foreach (var group in children.Values) if (group.Select(k => k.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != group.Count) throw new InvalidOperationException("Conflicting sibling names: choose one candidate before export.");
        var cells = new List<(uint Offset, byte[] Data, int Size)>(); int used = 32;
        var bins = new List<(int Offset, int Size)>(); var free = new List<(int Offset, int Size)>();
        int binStart = 0, binSize = 4096;
        uint Add(byte[] data)
        {
            int size = checked((data.Length + 4 + 7) & ~7);
            if (size > binStart + binSize - used - 8)
            {
                free.Add((used, binStart + binSize - used)); bins.Add((binStart, binSize));
                binStart = checked(binStart + binSize); binSize = checked((size + 32 + 8 + 4095) & ~4095); used = checked(binStart + 32);
            }
            if ((long)used + size + 8192 > o.MaxOutputBytes) throw new InvalidOperationException("Output budget exceeded.");
            uint offset = (uint)used; used = checked(used + size); cells.Add((offset, data, size)); return offset;
        }
        var nodes = new Dictionary<long, (uint Offset, byte[] Data)>();
        foreach (var k in selected)
        {
            cancellationToken.ThrowIfCancellationRequested(); byte[] name = Encoding.Unicode.GetBytes(k.Name);
            if (name.Length is 0 or > 32766 || k.Name.Contains('\0') || k.Name.Contains('\\')) throw new InvalidOperationException("Invalid selected key name.");
            byte[] nk = new byte[76 + name.Length]; "nk"u8.CopyTo(nk); W16(nk, 2, (ushort)((k.Flags & 0x0398) | (k == root ? 4 : 0))); W64(nk, 4, k.Timestamp); W16(nk, 72, (ushort)name.Length); name.CopyTo(nk, 76);
            foreach (int p in new[] { 16, 28, 32, 40, 44, 48 }) W32(nk, p, uint.MaxValue);
            nodes[k.Offset] = (Add(nk), nk);
        }
        var securities = new List<(uint Offset, byte[] Data)>(); var securityByBytes = new Dictionary<string, (uint Offset, byte[] Data)>(); int valueTotal = 0;
        foreach (var k in selected)
        {
            cancellationToken.ThrowIfCancellationRequested(); var nk = nodes[k.Offset].Data;
            if (k != root) W32(nk, 16, nodes[parents[k.Offset]].Offset);
            if (children.TryGetValue(k.Offset, out var childList))
            {
                var leaves = new List<uint>();
                foreach (var chunk in childList.Chunk(1024))
                {
                    byte[] leaf = new byte[4 + chunk.Length * 8]; "lh"u8.CopyTo(leaf); W16(leaf, 2, (ushort)chunk.Length);
                    for (int i = 0; i < chunk.Length; i++) { W32(leaf, 4 + i * 8, nodes[chunk[i].Offset].Offset); uint hash = 0; foreach (char c in chunk[i].Name) hash = unchecked(hash * 37 + char.ToUpperInvariant(c)); W32(leaf, 8 + i * 8, hash); }
                    leaves.Add(Add(leaf));
                }
                uint index = leaves[0];
                if (leaves.Count > 1) { if (leaves.Count > ushort.MaxValue) throw new InvalidOperationException("Too many subkey index leaves."); byte[] ri = new byte[4 + leaves.Count * 4]; "ri"u8.CopyTo(ri); W16(ri, 2, (ushort)leaves.Count); for (int i = 0; i < leaves.Count; i++) W32(ri, 4 + 4 * i, leaves[i]); index = Add(ri); }
                W32(nk, 20, (uint)childList.Count); W32(nk, 28, index); W32(nk, 52, (uint)childList.Max(c => Encoding.Unicode.GetByteCount(c.Name))); W32(nk, 56, (uint)childList.Max(c => c.ClassData.Length));
            }
            if (k.ClassData.Length != 0) { if (k.ClassData.Length > ushort.MaxValue) throw new InvalidOperationException("Class data too large."); W32(nk, 48, Add(k.ClassData)); W16(nk, 74, (ushort)k.ClassData.Length); }
            byte[]? descriptor = k.SecurityDescriptor;
            if (!ValidSecurity(descriptor))
            {
                if (!o.ReplaceMissingSecurity) throw new InvalidOperationException($"Key {k.Name} lacks a valid security descriptor. Explicit replacement policy required.");
                // Self-relative descriptor with an empty DACL: no implicit access grant.
                descriptor = new byte[28]; descriptor[0] = 1; W16(descriptor, 2, 0x8004); W32(descriptor, 16, 20); descriptor[20] = 2; W16(descriptor, 22, 8);
                findings.Add(new("SecurityReplaced", k.Offset, "Missing/invalid descriptor replaced with an empty DACL; permissions require review."));
            }
            string securityId = Convert.ToBase64String(descriptor!);
            if (!securityByBytes.TryGetValue(securityId, out var sharedSecurity))
            {
                byte[] sk = new byte[20 + descriptor!.Length]; "sk"u8.CopyTo(sk); W32(sk, 16, (uint)descriptor.Length); descriptor.CopyTo(sk, 20); sharedSecurity = (Add(sk), sk); securities.Add(sharedSecurity); securityByBytes[securityId] = sharedSecurity;
            }
            W32(sharedSecurity.Data, 12, U32(sharedSecurity.Data, 12) + 1); W32(nk, 44, sharedSecurity.Offset);
            var valueOffsets = new List<uint>(); var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var v in k.Values)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!v.Complete) { findings.Add(new("ValueOmitted", v.Offset, "Incomplete value retained in report, omitted from hive.")); continue; }
                if (!names.Add(v.Name)) throw new InvalidOperationException("Conflicting value names: choose one before export.");
                if (v.DeclaredLength > o.MaxOutputBytes) throw new InvalidOperationException("Value exceeds output budget.");
                byte[] payload = new byte[(int)v.DeclaredLength]; int next = 0;
                foreach (var extent in v.Extents.OrderBy(e => e.LogicalOffset)) { if (extent.LogicalOffset != next || extent.Bytes.Length > payload.Length - next) throw new InvalidOperationException("Invalid or overlapping value extents."); extent.Bytes.CopyTo(payload, next); next += extent.Bytes.Length; }
                if (next != payload.Length) throw new InvalidOperationException("Value marked complete has missing bytes.");
                byte[] name = Encoding.Unicode.GetBytes(v.Name); if (name.Length > ushort.MaxValue || v.Name.Contains('\0')) throw new InvalidOperationException("Invalid value name.");
                byte[] vk = new byte[20 + name.Length]; "vk"u8.CopyTo(vk); W16(vk, 2, (ushort)name.Length); W32(vk, 4, (uint)payload.Length); W32(vk, 12, v.Type); name.CopyTo(vk, 20);
                if (payload.Length <= 4) { W32(vk, 4, (uint)payload.Length | 0x80000000); payload.CopyTo(vk, 8); }
                else if (payload.Length <= 16344) W32(vk, 8, Add(payload));
                else
                {
                    int count = (payload.Length + 16343) / 16344; if (count > ushort.MaxValue) throw new InvalidOperationException("Too many data segments.");
                    byte[] list = new byte[count * 4]; for (int i = 0; i < count; i++) W32(list, i * 4, Add(payload.AsSpan(i * 16344, Math.Min(16344, payload.Length - i * 16344)).ToArray()));
                    byte[] db = new byte[8]; "db"u8.CopyTo(db); W16(db, 2, (ushort)count); W32(db, 4, Add(list)); W32(vk, 8, Add(db));
                }
                valueOffsets.Add(Add(vk)); valueTotal++; W32(nk, 60, Math.Max(U32(nk, 60), (uint)name.Length)); W32(nk, 64, Math.Max(U32(nk, 64), (uint)payload.Length));
            }
            if (valueOffsets.Count > 0) { byte[] list = new byte[valueOffsets.Count * 4]; for (int i = 0; i < valueOffsets.Count; i++) W32(list, 4 * i, valueOffsets[i]); W32(nk, 36, (uint)valueOffsets.Count); W32(nk, 40, Add(list)); }
        }
        for (int i = 0; i < securities.Count; i++) { W32(securities[i].Data, 4, securities[(i + 1) % securities.Count].Offset); W32(securities[i].Data, 8, securities[(i + securities.Count - 1) % securities.Count].Offset); }
        free.Add((used, binStart + binSize - used)); bins.Add((binStart, binSize));
        int binsSize = checked(binStart + binSize); byte[] output = new byte[checked(4096 + binsSize)];
        "regf"u8.CopyTo(output); W32(output, 4, 1); W32(output, 8, 1); W64(output, 12, root.Timestamp); W32(output, 20, 1); W32(output, 24, 5); W32(output, 32, 1); W32(output, 36, nodes[root.Offset].Offset); W32(output, 40, (uint)binsSize); W32(output, 44, 1);
        foreach (var bin in bins) { int p = 4096 + bin.Offset; "hbin"u8.CopyTo(output.AsSpan(p)); W32(output, p + 4, (uint)bin.Offset); W32(output, p + 8, (uint)bin.Size); }
        foreach (var cell in cells) { int p = checked(4096 + (int)cell.Offset); W32(output, p, unchecked((uint)-cell.Size)); cell.Data.CopyTo(output, p + 4); }
        foreach (var hole in free) W32(output, 4096 + hole.Offset, (uint)hole.Size); W32(output, 508, Checksum(output));
        using var source = new MemoryByteSource(output); var validation = new HiveInspector().Inspect(source, new(MaxScanBytes: output.Length, MaxRecords: Math.Max(250000, selected.Count + valueTotal + 1), MaxEvidenceBytes: Math.Max(256L << 20, output.Length * 2L)), cancellationToken: cancellationToken);
        bool valid = validation.HeaderValid && validation.Keys.Count(k => !k.Deleted) == selected.Count && validation.Keys.Sum(k => k.Values.Count) == valueTotal && !validation.Keys.SelectMany(k => k.Values).Any(v => !v.Complete);
        if (!valid) throw new InvalidDataException("Export failed internal round-trip validation.");
        bool complete = plan.Inspection.ScanComplete && findings.Count == 0 && selected.Count == plan.Inspection.Keys.Count && plan.Inspection.UnownedValues.Count == 0;
        return new(output, new(true, complete, selected.Count, valueTotal, findings));
    }

    private static bool ValidSecurity(byte[]? d)
    {
        if (d is null || d.Length < 20 || d[0] != 1 || (U16(d, 2) & 0x8000) == 0) return false;
        foreach (int field in new[] { 4, 8, 12, 16 }) { uint p = U32(d, field); if (p == 0) continue; if (p < 20 || p > d.Length - 8) return false; int size = field <= 8 ? 8 + d[(int)p + 1] * 4 : U16(d, (int)p + 2); if (size < 8 || size > d.Length - p) return false; }
        return true;
    }
}
