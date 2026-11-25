using System.Text;

namespace TrapSweeper.Tests;

/// <summary>
/// 按 [MS-SHLLINK] 最小子集手工构造 .lnk 夹具，不依赖 Windows shell。
/// 可注入 LinkInfo(CommonNetworkRelativeLink) 与 StringData，用于验证解析器字段覆盖。
/// </summary>
public static class LnkFixtureBuilder
{
    private static readonly byte[] LinkClsid =
    {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };

    [Flags]
    public enum LnkFlags : uint
    {
        HasLinkInfo = 0x02,
        HasArguments = 0x20,
        HasIconLocation = 0x40,
        IsUnicode = 0x80,
    }

    public static byte[] Build(
        string? netName = null,
        string? deviceName = null,
        string? iconLocation = null,
        string? arguments = null,
        bool unicodeStrings = false,
        bool truncateAtEnd = false)
    {
        var flags = LnkFlags.HasLinkInfo;
        if (iconLocation != null) flags |= LnkFlags.HasIconLocation;
        if (arguments != null) flags |= LnkFlags.HasArguments;
        // StringData 实际按 Unicode 编码时，必须同步置位 IsUnicode（真实 LNK 二者一致）
        if (unicodeStrings) flags |= LnkFlags.IsUnicode;

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // ---- ShellLinkHeader (76) ----
        w.Write(0x4Cu);
        w.Write(LinkClsid);
        w.Write((uint)flags);
        w.Write(0u); // FileAttributes
        w.Write(0L); w.Write(0L); w.Write(0L); // 三个时间戳
        w.Write(0u); // FileSize
        w.Write(0u); // IconIndex
        w.Write(0u); // ShowCommand
        w.Write((ushort)0); // HotKey
        w.Write((ushort)0); // Reserved1
        w.Write(0u); w.Write(0u); // Reserved2/3

        // ---- LinkInfo ----
        var netNameBytes = netName == null ? Array.Empty<byte>() : Encoding.Latin1.GetBytes(netName + "\0");
        var deviceBytes = deviceName == null ? Array.Empty<byte>() : Encoding.Latin1.GetBytes(deviceName + "\0");
        var suffixBytes = Encoding.Latin1.GetBytes("sub\\file.txt\0");

        const uint headerSize = 0x1C; // ANSI only
        // CommonNetworkRelativeLink 布局：5*4 头部 + netName + device
        var netBlockHeader = 20u;
        var netBlockSize = netBlockHeader + (uint)netNameBytes.Length + (uint)deviceBytes.Length;
        var netNameOffset = netNameBytes.Length > 0 ? netBlockHeader : 0u;
        var deviceNameOffset = deviceBytes.Length > 0 ? netBlockHeader + (uint)netNameBytes.Length : 0u;

        var linkInfoHeaderSize = headerSize;
        var linkInfoSize = linkInfoHeaderSize + netBlockSize + (uint)suffixBytes.Length;
        var commonNetOffset = linkInfoHeaderSize;
        var suffixOffset = commonNetOffset + netBlockSize;

        w.Write(linkInfoSize);
        w.Write(headerSize);
        w.Write(0x02u); // flags: CommonNetworkRelativeLink
        w.Write(0u);    // VolumeIDOffset
        w.Write(0u);    // LocalBasePathOffset
        w.Write(commonNetOffset);
        w.Write(suffixOffset);

        // CommonNetworkRelativeLink
        w.Write(netBlockSize);
        w.Write(0u); // flags
        w.Write(netNameOffset);
        w.Write(deviceNameOffset);
        w.Write(0x001A0000u); // NetworkProviderType: Lanman Redirector
        w.Write(netNameBytes);
        w.Write(deviceBytes);
        w.Write(suffixBytes);

        // ---- StringData：MS-SHLLINK 规定顺序 Name→RelativePath→WorkingDir→Arguments→IconLocation ----
        if (arguments != null) WriteStringData(w, arguments, unicodeStrings);
        if (iconLocation != null) WriteStringData(w, iconLocation, unicodeStrings);

        // ---- ExtraData 终止块 ----
        w.Write(0u);

        var result = ms.ToArray();
        return truncateAtEnd ? result[..^8] : result;
    }

    private static void WriteStringData(BinaryWriter w, string value, bool unicode)
    {
        if (unicode)
        {
            w.Write((ushort)value.Length);
            w.Write(Encoding.Unicode.GetBytes(value));
            w.Write((ushort)0);
        }
        else
        {
            var bytes = Encoding.Latin1.GetBytes(value);
            w.Write((ushort)bytes.Length);
            w.Write(bytes);
            w.Write((byte)0);
        }
    }
}
