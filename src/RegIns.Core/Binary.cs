using System.Buffers.Binary;
namespace RegIns;

internal static class Binary
{
    internal static ushort U16(ReadOnlySpan<byte> b, int p) => BinaryPrimitives.ReadUInt16LittleEndian(b[p..]);
    internal static uint U32(ReadOnlySpan<byte> b, int p) => BinaryPrimitives.ReadUInt32LittleEndian(b[p..]);
    internal static long I64(ReadOnlySpan<byte> b, int p) => BinaryPrimitives.ReadInt64LittleEndian(b[p..]);
    internal static void W16(Span<byte> b, int p, ushort x) => BinaryPrimitives.WriteUInt16LittleEndian(b[p..], x);
    internal static void W32(Span<byte> b, int p, uint x) => BinaryPrimitives.WriteUInt32LittleEndian(b[p..], x);
    internal static void W64(Span<byte> b, int p, long x) => BinaryPrimitives.WriteInt64LittleEndian(b[p..], x);
    internal static uint Checksum(ReadOnlySpan<byte> b) { uint c = 0; for (int p = 0; p < 508; p += 4) c ^= U32(b, p); return c == 0 ? 1 : c == uint.MaxValue ? uint.MaxValue - 1 : c; }
}

internal sealed class Reader(IByteSource source)
{
    private readonly byte[] cache = new byte[65536];
    private readonly byte[] mask = new byte[65536];
    private long start = -1;
    internal byte[]? Get(long offset, int count)
    {
        if (offset < 0 || count < 0 || offset > source.Length || count > source.Length - offset) return null;
        if (count <= cache.Length)
        {
            if (start < 0 || offset < start || offset + count > start + cache.Length) { start = offset; source.Read(start, cache, mask); }
            int p = (int)(offset - start);
            if (mask.AsSpan(p, count).Contains((byte)0)) return null;
            return cache.AsSpan(p, count).ToArray();
        }
        byte[] b = new byte[count], m = new byte[count]; source.Read(offset, b, m);
        return m.Contains((byte)0) ? null : b;
    }
}
