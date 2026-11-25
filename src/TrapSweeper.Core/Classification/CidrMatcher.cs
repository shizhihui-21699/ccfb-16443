using System.Buffers.Binary;
using System.Net;

namespace TrapSweeper.Core.Classification;

/// <summary>
/// CIDR 匹配器：IPv4 用 uint（32 位前缀）、IPv6 用两个 ulong（128 位前缀）分别比较，
/// 全部按网络字节序处理，避免有符号移位和字节序陷阱。
/// IPv4-mapped IPv6 地址(::ffff:a.b.c.d)同时参与 v4 规则匹配。
/// </summary>
public sealed class CidrMatcher
{
    private readonly List<(uint Base, int Prefix)> _v4 = new();
    private readonly List<(ulong Hi, ulong Lo, int Prefix)> _v6 = new();

    public CidrMatcher(IEnumerable<string> cidrs)
    {
        foreach (var c in cidrs)
        {
            var (baseAddr, prefix) = Parse(c);
            if (baseAddr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                _v4.Add((V4ToUInt(baseAddr), prefix));
            else
            {
                var (hi, lo) = V6ToUlongs(baseAddr);
                _v6.Add((hi, lo, prefix));
            }
        }
    }

    public bool Contains(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var value = V4ToUInt(address);
            return _v4.Any(n => Match32(value, n.Base, n.Prefix));
        }

        var (vHi, vLo) = V6ToUlongs(address);
        return _v6.Any(n => Match128(vHi, vLo, n.Hi, n.Lo, n.Prefix));
    }

    public static bool IsValid(string cidr)
    {
        try { _ = Parse(cidr); return true; }
        catch { return false; }
    }

    private static (IPAddress Addr, int Prefix) Parse(string cidr)
    {
        var slash = cidr.IndexOf('/');
        var ipPart = slash < 0 ? cidr : cidr[..slash];
        if (!IPAddress.TryParse(ipPart.Trim(), out var ip))
            throw new FormatException($"无法解析 IP: {ipPart}");

        int prefix;
        if (slash < 0)
        {
            prefix = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        }
        else if (!int.TryParse(cidr[(slash + 1)..], out prefix))
        {
            throw new FormatException($"无法解析前缀长度: {cidr}");
        }

        var max = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > max) throw new FormatException($"前缀越界: {cidr}");
        return (ip, prefix);
    }

    private static bool Match32(uint value, uint networkBase, int prefix)
    {
        if (prefix == 0) return true;
        var shift = 32 - prefix;
        return value >> shift == networkBase >> shift;
    }

    private static bool Match128(ulong vHi, ulong vLo, ulong bHi, ulong bLo, int prefix)
    {
        if (prefix == 0) return true;
        if (prefix >= 64)
        {
            if (vHi != bHi) return false;
            var lowBits = prefix == 64 ? 0 : prefix - 64;
            return lowBits == 0 || vLo >> (64 - lowBits) == bLo >> (64 - lowBits);
        }
        return vHi >> (64 - prefix) == bHi >> (64 - prefix);
    }

    private static uint V4ToUInt(IPAddress addr)
    {
        Span<byte> b = stackalloc byte[4];
        addr.TryWriteBytes(b, out _);
        return BinaryPrimitives.ReadUInt32BigEndian(b);
    }

    private static (ulong Hi, ulong Lo) V6ToUlongs(IPAddress addr)
    {
        Span<byte> b = stackalloc byte[16];
        addr.TryWriteBytes(b, out _);
        return (BinaryPrimitives.ReadUInt64BigEndian(b[..8]), BinaryPrimitives.ReadUInt64BigEndian(b[8..]));
    }
}
