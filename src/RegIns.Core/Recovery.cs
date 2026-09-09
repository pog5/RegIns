namespace RegIns;

public static class Recovery
{
    public static RecoveryPlan Plan(InspectionResult inspection, CancellationToken cancellationToken = default)
    {
        var plan = new RecoveryPlan { Inspection = inspection };
        var keys = inspection.Keys.Where(k => !k.Deleted).ToDictionary(k => k.Offset);
        foreach (var links in inspection.Relationships.Where(r => r.Evidence == "subkey-index" && keys.ContainsKey(r.Parent) && keys.ContainsKey(r.Child)).GroupBy(r => r.Child))
        {
            var parents = links.Select(r => r.Parent).Distinct().ToArray();
            if (parents.Length == 1 && keys[links.Key].ParentOffset != parents[0]) plan.ParentOverrides[links.Key] = parents[0];
        }
        long Parent(RecoveredKey key) => plan.ParentOverrides.GetValueOrDefault(key.Offset, key.ParentOffset);
        var roots = keys.Values.Where(k => k.Offset == inspection.RootOffset || (k.Flags & 4) != 0 || !keys.ContainsKey(Parent(k))).OrderByDescending(k => k.Offset == inspection.RootOffset).ThenByDescending(k => (k.Flags & 4) != 0).ThenBy(k => k.Offset).ToList();
        if (roots.Count == 0 && keys.Count != 0) roots.Add(keys.Values.OrderBy(k => k.Offset).First());
        var children = keys.Values.GroupBy(Parent).ToDictionary(g => g.Key, g => g.Select(k => k.Offset).Order().ToArray());
        foreach (var root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested(); var seen = new HashSet<long>(); var pending = new Stack<long>(); pending.Push(root.Offset);
            while (pending.TryPop(out long current))
            {
                cancellationToken.ThrowIfCancellationRequested(); if (!seen.Add(current)) continue;
                if (children.TryGetValue(current, out var list)) foreach (long child in list) pending.Push(child);
            }
            plan.Candidates.Add(new($"root-{root.Offset:x}", root.Offset, seen.Order().ToList(), root.Offset == inspection.RootOffset && inspection.HeaderValid ? "header-root" : "inferred-root"));
        }
        plan.SelectedCandidateId = plan.Candidates.FirstOrDefault()?.Id;
        return plan;
    }
}

public static class HiveCarver
{
    public static IEnumerable<CarvedRegion> Scan(IByteSource source, long maxBytes = long.MaxValue, CancellationToken cancellationToken = default)
    {
        if (maxBytes < 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        long end = Math.Min(source.Length, maxBytes); byte[] data = new byte[65584], mask = new byte[65584];
        for (long start = 0; start < end; start += 65536)
        {
            cancellationToken.ThrowIfCancellationRequested(); int n = (int)Math.Min(data.Length, end - start); source.Read(start, data.AsSpan(0, n), mask.AsSpan(0, n));
            for (int i = 0; i < Math.Min(65536, n - 4); i++)
            {
                if ((i & 4095) == 0) cancellationToken.ThrowIfCancellationRequested();
                if (mask.AsSpan(i, Math.Min(44, n - i)).Contains((byte)0)) continue;
                if (i + 44 <= n && data.AsSpan(i, 4).SequenceEqual("regf"u8))
                {
                    long length = 4096L + Binary.U32(data, i + 40);
                    if (Binary.U32(data, i + 20) == 1 && length >= 8192 && length % 4096 == 0) yield return new(start + i, Math.Min(length, source.Length - start - i), "hive", "signature, version and aligned declared size; validate before association");
                }
                else if (i + 12 <= n && data.AsSpan(i, 4).SequenceEqual("hbin"u8))
                {
                    uint length = Binary.U32(data, i + 8);
                    if (length >= 4096 && length % 4096 == 0) yield return new(start + i, Math.Min(length, source.Length - start - i), "bin", $"declared relative offset {Binary.U32(data, i + 4):x}; association not established");
                }
            }
        }
    }
}
