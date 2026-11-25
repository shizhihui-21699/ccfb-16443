using System.Text;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// 小端二进制读取器,带严格边界检查——诱饵文件可能被攻击者故意截断/畸形化,
/// 越界读取必须优雅失败而不是抛 IndexOutOfRange。
/// </summary>
internal ref struct SpanReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _position;

    public SpanReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    public int Position => _position;
    public int Remaining => _buffer.Length - _position;
    public bool CanRead(int count) => _position + count <= _buffer.Length;

    public byte ReadByte()
    {
        Ensure(1);
        return _buffer[_position++];
    }

    public ushort ReadUInt16()
    {
        Ensure(2);
        var v = BitConverter.ToUInt16(_buffer[_position..]);
        _position += 2;
        return v;
    }

    public uint ReadUInt32()
    {
        Ensure(4);
        var v = BitConverter.ToUInt32(_buffer[_position..]);
        _position += 4;
        return v;
    }

    public ulong ReadUInt64()
    {
        Ensure(8);
        var v = BitConverter.ToUInt64(_buffer[_position..]);
        _position += 8;
        return v;
    }

    public ReadOnlySpan<byte> ReadBytes(int count)
    {
        Ensure(count);
        var span = _buffer.Slice(_position, count);
        _position += count;
        return span;
    }

    public void Skip(int count)
    {
        Ensure(count);
        _position += count;
    }

    public void Seek(int position)
    {
        if (position < 0 || position > _buffer.Length)
            throw new BaitParseException($"读取位置越界:{position}");
        _position = position;
    }

    /// <summary>读取以 NUL 结尾的 ASCII 字符串(不保证存在终止符时使用 maxCount 兜底)。</summary>
    public string ReadNullTerminatedAscii(int maxCount)
    {
        var start = _position;
        var end = start;
        var limit = Math.Min(start + maxCount, _buffer.Length);
        while (end < limit && _buffer[end] != 0) end++;
        var s = Encoding.ASCII.GetString(_buffer[start..end]);
        _position = Math.Min(end + 1, limit);
        return s;
    }

    private void Ensure(int count)
    {
        if (!CanRead(count))
            throw new BaitParseException($"意外的文件结尾:需要 {count} 字节,剩余 {Remaining} 字节");
    }
}
