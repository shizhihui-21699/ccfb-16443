using System.Text;

namespace ShareGuard.Tests.Support;

/// <summary>
/// 按 [MS-SHLLINK] 手工构造最小可用 LNK 样本,用于解析器测试。
/// 不依赖 Windows Shell COM,可在任何平台运行。
/// </summary>
internal static class LnkSampleBuilder
{
    private static readonly byte[] Clsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    private const uint HasLinkInfo = 0x00000002;
    private const uint HasIconLocation = 0x00000040;
    private const uint IsUnicode = 0x00000080;

    /// <summary>构造一个带 CommonNetworkRelativeLink(UNC 目标)的 LNK。</summary>
    public static byte[] BuildNetworkLnk(string uncServer, string share, string? iconLocation = null)
    {
        var netName = $"\\\\{uncServer}\\{share}";
        var netNameBytes = Encoding.ASCII.GetBytes(netName + "\0");
        var deviceNameBytes = Encoding.ASCII.GetBytes("Z:" + "\0");
        var suffixBytes = Encoding.ASCII.GetBytes("\0");

        // ---- CommonNetworkRelativeLink(偏移相对自身)----
        var commonBlock = new List<byte>();
        // BlockSize 占位,稍后回填
        commonBlock.AddRange(BitConverter.GetBytes(0u));
        commonBlock.AddRange(BitConverter.GetBytes(0u));                       // Flags
        var netNameOffset = 20;                                                // 固定头 20 字节
        commonBlock.AddRange(BitConverter.GetBytes((uint)netNameOffset));
        commonBlock.AddRange(BitConverter.GetBytes((uint)(netNameOffset + netNameBytes.Length))); // DeviceNameOffset
        commonBlock.AddRange(BitConverter.GetBytes(0u));                       // NetworkProviderType
        commonBlock.AddRange(netNameBytes);
        commonBlock.AddRange(deviceNameBytes);
        WriteUInt32At(commonBlock, 0, (uint)commonBlock.Count);

        // ---- LinkInfo(基础头 0x1C,ASCII 偏移)----
        var linkInfo = new List<byte>();
        linkInfo.AddRange(BitConverter.GetBytes(0u));                          // LinkInfoSize 占位
        linkInfo.AddRange(BitConverter.GetBytes(0x1Cu));                       // HeaderSize
        linkInfo.AddRange(BitConverter.GetBytes(0x1u));                        // Flags: CommonNetworkRelativeLink
        linkInfo.AddRange(BitConverter.GetBytes(0u));                          // VolumeIDOffset
        linkInfo.AddRange(BitConverter.GetBytes(0u));                          // LocalBasePathOffset
        var commonNetworkRelativeOffset = 0x1C + suffixBytes.Length;
        linkInfo.AddRange(BitConverter.GetBytes((uint)commonNetworkRelativeOffset));
        linkInfo.AddRange(BitConverter.GetBytes(0x1Cu));                       // CommonPathSuffixOffset
        linkInfo.AddRange(suffixBytes);
        linkInfo.AddRange(commonBlock);
        WriteUInt32At(linkInfo, 0, (uint)linkInfo.Count);

        // ---- Header ----
        var header = new List<byte>();
        header.AddRange(BitConverter.GetBytes(0x4Cu));                         // HeaderSize
        header.AddRange(Clsid);
        var flags = HasLinkInfo;
        if (iconLocation != null) flags |= HasIconLocation | IsUnicode;
        header.AddRange(BitConverter.GetBytes(flags));                         // LinkFlags
        header.AddRange(BitConverter.GetBytes(0u));                            // FileAttributes
        header.AddRange(BitConverter.GetBytes(0L));                            // CreationTime
        header.AddRange(BitConverter.GetBytes(0L));                            // AccessTime
        header.AddRange(BitConverter.GetBytes(0L));                            // WriteTime
        header.AddRange(BitConverter.GetBytes(0u));                            // FileSize
        header.AddRange(BitConverter.GetBytes(0u));                            // IconIndex
        header.AddRange(BitConverter.GetBytes(0u));                            // ShowCommand
        header.AddRange(new byte[10 * 2]);                                     // HotKey + Reserved1/2/3

        // ---- StringData: IconLocation(UTF-16)----
        var stringData = new List<byte>();
        if (iconLocation != null)
        {
            var chars = iconLocation.ToCharArray();
            stringData.AddRange(BitConverter.GetBytes((ushort)chars.Length));
            stringData.AddRange(Encoding.Unicode.GetBytes(iconLocation));
        }

        var result = new List<byte>(header.Count + linkInfo.Count + stringData.Count);
        result.AddRange(header);
        result.AddRange(linkInfo);
        result.AddRange(stringData);
        return result.ToArray();
    }

    /// <summary>构造一个头部 CLSID 被破坏的畸形 LNK,验证解析器的失败兜底。</summary>
    public static byte[] BuildCorruptLnk()
    {
        var bytes = BuildNetworkLnk("evil.example.com", "share");
        bytes[4] ^= 0xFF;
        return bytes;
    }

    private static void WriteUInt32At(List<byte> buffer, int offset, uint value)
    {
        var raw = BitConverter.GetBytes(value);
        for (var i = 0; i < 4; i++) buffer[offset + i] = raw[i];
    }
}
