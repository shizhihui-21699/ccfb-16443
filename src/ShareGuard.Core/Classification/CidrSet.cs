using System.Net;
using System.Net.Sockets;

namespace ShareGuard.Core.Classification;

/// <summary>
/// CIDR 网段匹配,同时支持 IPv4 与 IPv6。
/// IPv4 映射的 IPv6 地址(::ffff:a.b.c.d)会先还原为 IPv4 再匹配,避免绕过。
/// </summary>
public sealed class CidrSet
{
    private readonly List<(IPAddress Network, int PrefixLength, IPAddress Mask)> _entries = new();

    public CidrSet(IEnumerable<string> cidrs)
    {
        foreach (var cidr in cidrs)
        {
            var parts = cidr.Split('/');
            if (!IPAddress.TryParse(parts[0].Trim(), out var network)) continue;
            var prefix = parts.Length > 1 ? int.Parse(parts[1]) : (network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);

            if (network.AddressFamily == AddressFamily.InterNetworkV6 && network.IsIPv4MappedToIPv6)
                network = network.MapToIPv4();

            prefix = Math.Clamp(prefix, 0, network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
            _entries.Add((network, prefix, BuildMask(network.AddressFamily, prefix)));
        }
    }

    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        foreach (var (network, prefix, mask) in _entries)
        {
            if (network.AddressFamily != address.AddressFamily) continue;
            if (MaskedEqual(address, network, mask)) return true;
        }
        return false;
    }

    private static bool MaskedEqual(IPAddress a, IPAddress b, IPAddress mask)
    {
        var ba = a.GetAddressBytes();
        var bb = b.GetAddressBytes();
        var bm = mask.GetAddressBytes();
        for (var i = 0; i < ba.Length; i++)
        {
            if ((ba[i] & bm[i]) != (bb[i] & bm[i])) return false;
        }
        return true;
    }

    private static IPAddress BuildMask(AddressFamily family, int prefixLength)
    {
        var length = family == AddressFamily.InterNetwork ? 4 : 16;
        var bytes = new byte[length];
        var remaining = prefixLength;
        for (var i = 0; i < length; i++)
        {
            if (remaining >= 8) { bytes[i] = 0xFF; remaining -= 8; }
            else if (remaining > 0) { bytes[i] = (byte)(0xFF << (8 - remaining)); remaining = 0; }
        }
        return new IPAddress(bytes);
    }
}
