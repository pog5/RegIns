using System.Numerics;
using static RegIns.Binary;
namespace RegIns;

public sealed record DirtyPage(uint Offset, byte[] Bytes);
public sealed record LogEntry(long Offset, uint Sequence, uint HiveBinsSize, uint Flags, List<DirtyPage> Pages);
public sealed class LogAnalysis
{
    public string Source { get; set; } = "";
    public string Format { get; set; } = "unsupported";
    public byte[] Header { get; set; } = [];
    public bool HeaderValid { get; set; }
    public List<LogEntry> Entries { get; set; } = [];
    public List<Finding> Findings { get; set; } = [];
}

public static class TransactionLogs
{
    public static LogAnalysis Analyze(IByteSource source, RecoveryOptions? options = null, CancellationToken cancellationToken = default)
    {
        var o = options ?? new(); var r = new Reader(source); var a = new LogAnalysis { Source = source.Id }; var h = r.Get(0, 512);
        bool recognizable = h is not null && h.AsSpan(0, 4).SequenceEqual("regf"u8);
        h ??= new byte[512];
        a.Header = h; uint type = recognizable ? U32(h, 28) : 6, size = U32(h, 40);
        a.HeaderValid = recognizable && Checksum(h) == U32(h, 508) && U32(h, 4) == U32(h, 8) && U32(h, 20) == 1 && U32(h, 24) is >= 1 and <= 6 && U32(h, 32) == 1 && size > 0 && size % 4096 == 0;
        a.Format = type == 6 ? "HvLE" : type is 1 or 2 ? "DIRT" : "unsupported";
        if (!a.HeaderValid) a.Findings.Add(new("InvalidLogHeader", 0, "Invalid header; entries may be inspected but cannot be automatically replayed."));
        if (a.Format == "unsupported") { a.Findings.Add(new("UnsupportedLog", 28, $"Unsupported log file type {type}.")); return a; }
        long budget = 0;
        if (type is 1 or 2)
        {
            uint factor = U32(h, 44); if (factor is not (1 or 8)) { a.Findings.Add(new("UnsupportedSector", 44, "Unsupported clustering factor.")); return a; }
            int sector = (int)factor * 512; long bitmapBytes = size / 4096L;
            if (bitmapBytes > o.MaxEvidenceBytes || bitmapBytes > int.MaxValue - 4 || size > o.MaxEvidenceBytes) { a.Findings.Add(new("LogLimit", sector, "Legacy log exceeds evidence budget.")); return a; }
            var vector = r.Get(sector, (int)bitmapBytes + 4);
            if (vector is null || !vector.AsSpan(0, 4).SequenceEqual("DIRT"u8)) { a.Findings.Add(new("InvalidDirtyVector", sector, "Missing or truncated dirty bitmap.")); return a; }
            long pageOffset = ((sector + bitmapBytes + 4 + sector - 1) / sector) * sector; var pages = new List<DirtyPage>();
            for (uint page = 0; page < size / 512; page++)
            {
                cancellationToken.ThrowIfCancellationRequested(); if ((vector[4 + page / 8] & (1 << (int)(page % 8))) == 0) continue;
                if (pageOffset + 512 > o.MaxScanBytes) { a.Findings.Add(new("LogLimit", pageOffset, "Legacy page scan budget exhausted.")); return a; }
                var data = r.Get(pageOffset, 512); if (data is null) { a.Findings.Add(new("TruncatedLog", pageOffset, "Legacy transaction incomplete; no replay entry emitted.")); return a; }
                pages.Add(new(page * 512, data)); pageOffset += 512;
            }
            a.Entries.Add(new(sector, U32(h, 4), size, 0, pages)); return a;
        }
        // Independent sector scanning retains later valid entries after damaged entries, but replay still requires continuity.
        long end = Math.Min(source.Length, o.MaxScanBytes);
        for (long pos = 512; pos + 40 <= end; pos += 512)
        {
            cancellationToken.ThrowIfCancellationRequested(); var head = r.Get(pos, 40); if (head is null || !head.AsSpan(0, 4).SequenceEqual("HvLE"u8)) continue;
            uint length = U32(head, 4), count = U32(head, 20), bins = U32(head, 16);
            if (length < 512 || length % 512 != 0 || length > end - pos || length > int.MaxValue || bins == 0 || bins % 4096 != 0 || 40L + count * 8L > length) { a.Findings.Add(new("InvalidLogEntry", pos, "Invalid entry sizes or truncated entry.")); continue; }
            if (budget + length > o.MaxEvidenceBytes || a.Entries.Count >= o.MaxRecords) { a.Findings.Add(new("LogLimit", pos, "Log evidence budget exhausted.")); break; }
            var data = r.Get(pos, (int)length); if (data is null) { a.Findings.Add(new("UnreadableLogEntry", pos, "Entry includes unreadable bytes.")); continue; }
            if (Marvin(data.AsSpan(40)) != unchecked((ulong)I64(data, 24)) || Marvin(data.AsSpan(0, 32)) != unchecked((ulong)I64(data, 32))) { a.Findings.Add(new("LogHashMismatch", pos, "Entry integrity check failed.")); continue; }
            var pages = new List<DirtyPage>(); long cursor = 40L + count * 8L; bool valid = true;
            for (int i = 0; i < count; i++)
            {
                cancellationToken.ThrowIfCancellationRequested(); uint offset = U32(data, 40 + i * 8), n = U32(data, 44 + i * 8);
                if (n == 0 || offset % 512 != 0 || n % 512 != 0 || (ulong)offset + n > bins || cursor + n > length) { valid = false; break; }
                pages.Add(new(offset, data.AsSpan((int)cursor, (int)n).ToArray())); cursor += n;
            }
            var sorted = pages.OrderBy(p => p.Offset).ToArray();
            for (int i = 1; i < sorted.Length; i++) if ((ulong)sorted[i - 1].Offset + (uint)sorted[i - 1].Bytes.Length > sorted[i].Offset) valid = false;
            if (!valid) { a.Findings.Add(new("InvalidDirtyPages", pos, "Invalid, overlapping or truncated page references.")); continue; }
            budget += length; a.Entries.Add(new(pos, U32(data, 12), bins, U32(data, 8), pages)); pos += length - 512;
        }
        if (!recognizable && a.Entries.Count == 0) { a.Format = "unsupported"; a.Findings.Add(new("UnsupportedLog", 0, "No supported header or integrity-checked HvLE entries. TxR/CLFS decoding is not implemented.")); }
        return a;
    }

    // Caller supplies a single explicitly selected history. Ambiguous duplicate sequences are rejected.
    public static IByteSource Replay(IByteSource primary, IReadOnlyList<LogAnalysis> logs, bool allowUnverifiedAssociation = false, CancellationToken cancellationToken = default)
    {
        if (logs.Count == 0) throw new ArgumentException("No logs selected.");
        var h = new Reader(primary).Get(0, 512); bool valid = h is not null && h.AsSpan(0, 4).SequenceEqual("regf"u8) && Checksum(h) == U32(h, 508);
        if (valid && U32(h!, 4) == U32(h!, 8)) throw new InvalidOperationException("Clean hive: subsequent logs must not be replayed.");
        foreach (var log in logs)
        {
            if (log.Format == "unsupported" || !log.HeaderValid && !(valid && allowUnverifiedAssociation && log.Format == "HvLE" && log.Entries.Count > 0)) throw new InvalidOperationException("Selected log has no valid supported header; headerless HvLE replay requires a valid primary and explicit association override.");
            bool identity = valid && h!.AsSpan(112, 16).ContainsAnyExcept((byte)0) && h.AsSpan(112, 16).SequenceEqual(log.Header.AsSpan(112, 16));
            bool timestamp = valid && I64(h!, 12) != 0 && I64(h!, 12) == I64(log.Header, 12);
            if (!identity && !timestamp && !allowUnverifiedAssociation) throw new InvalidOperationException("Hive/log association unverified; explicit association override required.");
            if (valid && h!.AsSpan(112, 16).ContainsAnyExcept((byte)0) && log.Header.AsSpan(112, 16).ContainsAnyExcept((byte)0) && !h.AsSpan(112, 16).SequenceEqual(log.Header.AsSpan(112, 16))) throw new InvalidOperationException("Conflicting resource-manager identities.");
        }
        bool legacy = logs[0].Format == "DIRT";
        if (logs.Any(l => (l.Format == "DIRT") != legacy) || legacy && logs.Count != 1) throw new InvalidOperationException("Select one legacy log or one compatible modern history.");
        uint expected = legacy ? U32(logs[0].Header, 4) : logs.Select(l => l.HeaderValid ? U32(l.Header, 4) : l.Entries[0].Sequence).Min();
        if (valid && unchecked((int)(expected - U32(h!, 8))) < 0) throw new InvalidOperationException("Log history starts before the primary hive sequence; select a subsequent history.");
        var entries = logs.SelectMany(l => l.Entries).Where(e => unchecked((int)(e.Sequence - expected)) >= 0).OrderBy(e => unchecked(e.Sequence - expected)).ToList();
        if (entries.GroupBy(e => e.Sequence).Any(g => g.Count() > 1)) throw new InvalidOperationException("Duplicate/conflicting sequences: select one history before replay.");
        if (entries.Count == 0) throw new InvalidOperationException("No applicable entries.");
        var overlays = new List<(long Offset, byte[] Bytes)>(); long length = primary.Length;
        byte[] header = valid ? h!.ToArray() : logs[0].Header.ToArray();
        foreach (var entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested(); if (entry.Sequence != expected) throw new InvalidOperationException("Discontinuous log history; select a contiguous prefix.");
            foreach (var page in entry.Pages) overlays.Add((4096L + page.Offset, page.Bytes));
            length = Math.Max(length, 4096L + entry.HiveBinsSize); W32(header, 4, entry.Sequence); W32(header, 8, entry.Sequence); W32(header, 40, entry.HiveBinsSize); W32(header, 144, (U32(header, 144) & ~1u) | (entry.Flags & 1)); expected = unchecked(expected + 1);
        }
        W32(header, 28, 0); W32(header, 508, Checksum(header)); overlays.Add((0, header));
        return new OverlaySource(primary, overlays, length);
    }

    public static ulong Marvin(ReadOnlySpan<byte> bytes)
    {
        uint a = 0x7a4e55c5, b = 0x82ef4d88; int p = 0;
        while (p + 4 <= bytes.Length) { a = unchecked(a + U32(bytes, p)); Mix(); p += 4; }
        uint tail = 0x80u << ((bytes.Length - p) * 8); for (int i = 0; p + i < bytes.Length; i++) tail |= (uint)bytes[p + i] << (8 * i);
        a = unchecked(a + tail); Mix(); Mix(); return ((ulong)b << 32) | a;
        void Mix() { b ^= a; a = BitOperations.RotateLeft(a, 20); a = unchecked(a + b); b = BitOperations.RotateLeft(b, 9); b ^= a; a = BitOperations.RotateLeft(a, 27); a = unchecked(a + b); b = BitOperations.RotateLeft(b, 19); }
    }

    private sealed class OverlaySource(IByteSource source, List<(long Offset, byte[] Bytes)> patches, long length) : IByteSource
    {
        public string Id => source.Id + "+selected-log-history";
        public long Length => length;
        public int Read(long offset, Span<byte> bytes, Span<byte> readable)
        {
            if (offset < 0 || readable.Length < bytes.Length) throw new ArgumentOutOfRangeException(nameof(offset));
            bytes.Clear(); readable.Clear(); int n = (int)Math.Min(bytes.Length, Math.Max(0, Length - offset)); source.Read(offset, bytes[..n], readable[..n]);
            foreach (var patch in patches) { long begin = Math.Max(offset, patch.Offset), end = Math.Min(offset + n, patch.Offset + patch.Bytes.Length); if (end <= begin) continue; int count = (int)(end - begin); patch.Bytes.AsSpan((int)(begin - patch.Offset), count).CopyTo(bytes[(int)(begin - offset)..]); readable.Slice((int)(begin - offset), count).Fill(1); }
            return n;
        }
        public void Dispose() { }
    }
}
