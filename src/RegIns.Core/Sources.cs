namespace RegIns;

public interface IByteSource : IDisposable
{
    string Id { get; }
    long Length { get; }
    // Each byte has a separate readability flag. Unreadable bytes are never evidence of zeroes.
    int Read(long offset, Span<byte> bytes, Span<byte> readable);
}

public sealed class FileByteSource : IByteSource
{
    private readonly FileStream file;
    public string Id { get; }
    public long Length => file.Length;
    public FileByteSource(string path) { Id = Path.GetFullPath(path); file = new(path, FileMode.Open, FileAccess.Read, FileShare.Read); }
    public int Read(long offset, Span<byte> bytes, Span<byte> readable)
    {
        if (offset < 0 || readable.Length < bytes.Length) throw new ArgumentOutOfRangeException(nameof(offset));
        readable.Clear(); bytes.Clear();
        int limit = (int)Math.Min(bytes.Length, Math.Max(0, Length - offset));
        for (int begin = 0; begin < limit;)
        {
            int take = Math.Min(limit - begin, 4096 - (int)((offset + begin) % 4096)); int done = 0;
            try { while (done < take) { int n = RandomAccess.Read(file.SafeFileHandle, bytes.Slice(begin + done, take - done), checked(offset + begin + done)); if (n == 0) break; readable.Slice(begin + done, n).Fill(1); done += n; } }
            catch (IOException) { /* Failed page remains unreadable; continue beyond the hole. */ }
            begin += take;
        }
        return limit;
    }
    public void Dispose() => file.Dispose();
}

public sealed class StreamByteSource : IByteSource
{
    private readonly Stream stream;
    private readonly bool leaveOpen;
    private readonly object gate = new();
    public string Id { get; }
    public long Length => stream.Length;
    public StreamByteSource(Stream stream, string id = "stream", bool leaveOpen = true)
    {
        if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("A readable, seekable stream is required.", nameof(stream));
        this.stream = stream; this.leaveOpen = leaveOpen; Id = id;
    }
    public int Read(long offset, Span<byte> bytes, Span<byte> readable)
    {
        if (offset < 0 || readable.Length < bytes.Length) throw new ArgumentOutOfRangeException(nameof(offset));
        bytes.Clear(); readable.Clear();
        lock (gate)
        {
            int limit = (int)Math.Min(bytes.Length, Math.Max(0, Length - offset));
            for (int begin = 0; begin < limit;)
            {
                int take = Math.Min(limit - begin, 4096 - (int)((offset + begin) % 4096)); int done = 0;
                try { stream.Position = checked(offset + begin); while (done < take) { int n = stream.Read(bytes.Slice(begin + done, take - done)); if (n == 0) break; readable.Slice(begin + done, n).Fill(1); done += n; } }
                catch (IOException) { }
                begin += take;
            }
            return limit;
        }
    }
    public void Dispose() { if (!leaveOpen) stream.Dispose(); }
}

public sealed class MemoryByteSource(byte[] bytes, string id = "memory", byte[]? readability = null) : IByteSource
{
    public string Id => id;
    public long Length => bytes.LongLength;
    public int Read(long offset, Span<byte> target, Span<byte> readable)
    {
        if (offset < 0 || readable.Length < target.Length) throw new ArgumentOutOfRangeException(nameof(offset));
        target.Clear(); readable.Clear();
        int n = (int)Math.Min(target.Length, Math.Max(0, Length - offset));
        if (n == 0) return 0;
        bytes.AsSpan((int)offset, n).CopyTo(target);
        if (readability is null) readable[..n].Fill(1); else readability.AsSpan((int)offset, n).CopyTo(readable);
        return n;
    }
    public void Dispose() { }
}

public sealed class SliceByteSource : IByteSource
{
    private readonly IByteSource source;
    private readonly long start;
    public string Id => $"{source.Id}@{start:x}";
    public long Length { get; }
    public SliceByteSource(IByteSource source, long start, long length)
    {
        if (start < 0 || length < 0 || start > source.Length || length > source.Length - start) throw new ArgumentOutOfRangeException(nameof(start));
        this.source = source; this.start = start; Length = length;
    }
    public int Read(long offset, Span<byte> bytes, Span<byte> readable)
    {
        if (offset < 0 || readable.Length < bytes.Length) throw new ArgumentOutOfRangeException(nameof(offset));
        bytes.Clear(); readable.Clear();
        int n = (int)Math.Min(bytes.Length, Math.Max(0, Length - offset));
        return n == 0 ? 0 : source.Read(checked(start + offset), bytes[..n], readable[..n]);
    }
    public void Dispose() { } // caller owns the underlying source
}
