using System.Text;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Parsers;

/// <summary>解析结果容器：所有文件格式解析器的统一返回类型。</summary>
public sealed class ParsedFile
{
    public DecoyKind? Kind { get; set; }
    public List<HostReference> References { get; } = new();
    public bool Truncated { get; set; }
    public string? Error { get; set; }
    public bool FormatMatched { get; set; } = true;

    public void Add(IEnumerable<HostReference> refs) => References.AddRange(refs);
}

/// <summary>
/// MS-SHLLINK ShellLink(.lnk) 解析器，依据 [MS-SHLLINK] 实现。
/// 关注会触发 SMB/WebDAV 外连的字段：CommonNetworkRelativeLink、ICON_LOCATION、
/// ARGUMENTS、WORKING_DIR、RELATIVE_PATH、名称字符串以及 ExtraData 中的环境变量/图标/Tracker 块。
/// 对未知或损坏结构采用"尽力解析 + 原始字节字符串扫荡"，绝不静默漏报。
/// </summary>
public static class LnkParser
{
    public const uint LinkClsidData1 = 0x00021401;
    public static ReadOnlySpan<byte> LinkClsidBytes => new byte[]
    {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
    };

    [Flags]
    private enum LinkFlags : uint
    {
        HasLinkTargetIdList = 0x00000001,
        HasLinkInfo = 0x00000002,
        HasName = 0x00000004,
        HasRelativePath = 0x00000008,
        HasWorkingDir = 0x00000010,
        HasArguments = 0x00000020,
        HasIconLocation = 0x00000040,
        IsUnicode = 0x00000080,
        ForceNoLinkTrack = 0x00000100,
        HasExpString = 0x00000200,
        RunInSeparateProcess = 0x00000400,
        HasDarwinId = 0x00001000,
        HasExpIcon = 0x00004000,
        DisableKnownFolderTracking = 0x00100000,
        DisableKnownFolderAlias = 0x00200000,
        AllowLinkToLink = 0x00400000,
        LinkOnLocalVolume = 0x00800000,
    }

    private const uint SigEnvironment = 0xA0000005;
    private const uint SigTracker = 0xA0000007;
    private const uint SigDarwin = 0xA000000A;
    private const uint SigIconPath = 0xA000000B;
    private const uint SigIconEnvironment = 0xA0000011;

    public static bool IsLnkByHeader(ReadOnlySpan<byte> bytes) =>
        bytes.Length >= 0x4C && bytes[4..20].SequenceEqual(LinkClsidBytes);

    public static ParsedFile Parse(byte[] bytes)
    {
        var result = new ParsedFile { Kind = DecoyKind.Lnk };
        if (bytes.Length < 0x4C)
        {
            result.Error = "文件小于 ShellLinkHeader 最小长度(76字节)";
            result.Truncated = true;
            result.Add(Analysis.ReferenceExtractor.SweepRawBytes(bytes));
            return result;
        }

        try
        {
            using var ms = new MemoryStream(bytes);
            using var r = new BinaryReader(ms, Encoding.Unicode, leaveOpen: true);

            var headerSize = r.ReadUInt32();
            if (headerSize < 0x4C)
                throw new InvalidDataException($"HeaderSize 异常: {headerSize}");

            var clsid = r.ReadBytes(16);
            if (!clsid.AsSpan().SequenceEqual(LinkClsidBytes))
                throw new InvalidDataException("LinkCLSID 不匹配，不是有效 .lnk 文件");

            // MS-SHLLINK 头布局：CLSID 之后立即是 LinkFlags，再是 52(0x34) 字节其余头字段
            var flags = (LinkFlags)r.ReadUInt32();
            r.ReadBytes(0x34); // FileAttributes/时间/FileSize/IconIndex/ShowCommand/HotKey/Reserved*

            // ---- LinkTargetIDList：仅跳过，IDList 内的路径不做主机引用来源（含大量历史噪声） ----
            if (flags.HasFlag(LinkFlags.HasLinkTargetIdList))
            {
                if (!TrySkipIdList(r, result)) return FinishWithSweep(bytes, result);
            }

            // ---- LinkInfo：CommonNetworkRelativeLink 是强制认证诱饵的高发字段 ----
            if (flags.HasFlag(LinkFlags.HasLinkInfo))
            {
                ParseLinkInfo(r, result);
            }

            // ---- StringData ----
            var unicode = flags.HasFlag(LinkFlags.IsUnicode);
            if (flags.HasFlag(LinkFlags.HasName)) ReadStringData(r, unicode, "Name", result);
            if (flags.HasFlag(LinkFlags.HasRelativePath)) ReadStringData(r, unicode, "RelativePath", result);
            if (flags.HasFlag(LinkFlags.HasWorkingDir)) ReadStringData(r, unicode, "WorkingDirectory", result);
            if (flags.HasFlag(LinkFlags.HasArguments)) ReadStringData(r, unicode, "Arguments", result);
            if (flags.HasFlag(LinkFlags.HasIconLocation)) ReadStringData(r, unicode, "IconLocation", result);

            // ---- ExtraData ----
            if (r.BaseStream.Position < bytes.Length)
            {
                ParseExtraData(r, result);
            }
        }
        catch (Exception ex)
        {
            result.Truncated = true;
            result.Error ??= $"结构解析中断: {ex.Message}";
        }

        // 兜底：无论结构解析成功与否，都对原始字节做字符串扫荡（去重后补充）
        var existing = new HashSet<string>(result.References.Select(x => x.Raw), StringComparer.OrdinalIgnoreCase);
        foreach (var sweep in Analysis.ReferenceExtractor.SweepRawBytes(bytes))
        {
            if (existing.Add(sweep.Raw)) result.References.Add(sweep);
        }

        return result;
    }

    private static bool TrySkipIdList(BinaryReader r, ParsedFile result)
    {
        if (r.BaseStream.Position + 2 > r.BaseStream.Length) { result.Truncated = true; return false; }
        var idListSize = r.ReadUInt16();
        if (r.BaseStream.Position + idListSize > r.BaseStream.Length) { result.Truncated = true; return false; }
        r.BaseStream.Seek(idListSize, SeekOrigin.Current);
        return true;
    }

    private static void ParseLinkInfo(BinaryReader r, ParsedFile result)
    {
        var start = r.BaseStream.Position;
        if (start + 8 > r.BaseStream.Length) { result.Truncated = true; return; }

        var linkInfoSize = r.ReadUInt32();
        var headerSize = r.ReadUInt32();
        if (linkInfoSize < headerSize || start + linkInfoSize > r.BaseStream.Length)
        {
            result.Truncated = true;
            r.BaseStream.Seek(start, SeekOrigin.Begin);
            return;
        }

        var infoFlags = r.ReadUInt32();
        var volumeIdOffset = r.ReadUInt32();
        var localBasePathOffset = r.ReadUInt32();
        var commonNetOffset = r.ReadUInt32();
        var commonSuffixOffset = r.ReadUInt32();

        uint localBaseUnicode = 0, commonSuffixUnicode = 0;
        var unicodePresent = headerSize >= 0x24;
        if (unicodePresent)
        {
            localBaseUnicode = r.ReadUInt32();
            commonSuffixUnicode = r.ReadUInt32();
        }

        var block = r.BaseStream;

        if (commonNetOffset > 0 && (infoFlags & 0x02) != 0)
        {
            block.Seek(start + commonNetOffset, SeekOrigin.Begin);
            ParseCommonNetworkRelativeLink(r, result);
        }

        if (localBasePathOffset > 0 && (infoFlags & 0x01) != 0)
        {
            block.Seek(start + localBasePathOffset, SeekOrigin.Begin);
            var s = ReadAnsiNullTerminated(r);
            result.Add(Analysis.ReferenceExtractor.Extract(s, "LocalBasePath", "ansi"));
        }

        if (commonSuffixOffset > 0)
        {
            // CommonNetworkRelativeLink 的字符串读取会改变流位置，这里按偏移绝对定位后再恢复
            block.Seek(start + commonSuffixOffset, SeekOrigin.Begin);
            var s = ReadAnsiNullTerminated(r);
            result.Add(Analysis.ReferenceExtractor.Extract(s, "CommonPathSuffix", "ansi"));
        }

        if (unicodePresent)
        {
            if (localBaseUnicode > 0)
            {
                block.Seek(start + localBaseUnicode, SeekOrigin.Begin);
                result.Add(Analysis.ReferenceExtractor.Extract(ReadUnicodeNullTerminated(r), "LocalBasePath", "utf16"));
            }
            if (commonSuffixUnicode > 0)
            {
                block.Seek(start + commonSuffixUnicode, SeekOrigin.Begin);
                result.Add(Analysis.ReferenceExtractor.Extract(ReadUnicodeNullTerminated(r), "CommonPathSuffix", "utf16"));
            }
        }

        block.Seek(start + linkInfoSize, SeekOrigin.Begin);
    }

    private static void ParseCommonNetworkRelativeLink(BinaryReader r, ParsedFile result)
    {
        var start = r.BaseStream.Position;
        if (start + 20 > r.BaseStream.Length) { result.Truncated = true; return; }

        var blockSize = r.ReadUInt32();
        r.ReadUInt32(); // CommonNetworkRelativeLinkFlags
        var netNameOffset = r.ReadUInt32();
        var deviceNameOffset = r.ReadUInt32();
        r.ReadUInt32(); // NetworkProviderType

        uint netNameUnicode = 0, deviceNameUnicode = 0;
        if (blockSize >= 0x1C && start + 28 <= r.BaseStream.Length)
        {
            netNameUnicode = r.ReadUInt32();
            deviceNameUnicode = r.ReadUInt32();
        }

        if (netNameOffset > 0 && start + netNameOffset < r.BaseStream.Length)
        {
            r.BaseStream.Seek(start + netNameOffset, SeekOrigin.Begin);
            result.Add(Analysis.ReferenceExtractor.Extract(ReadAnsiNullTerminated(r), "NetworkNetName", "ansi"));
        }
        if (deviceNameOffset > 0 && start + deviceNameOffset < r.BaseStream.Length)
        {
            r.BaseStream.Seek(start + deviceNameOffset, SeekOrigin.Begin);
            result.Add(Analysis.ReferenceExtractor.Extract(ReadAnsiNullTerminated(r), "NetworkDeviceName", "ansi"));
        }
        if (netNameUnicode > 0 && start + netNameUnicode < r.BaseStream.Length)
        {
            r.BaseStream.Seek(start + netNameUnicode, SeekOrigin.Begin);
            result.Add(Analysis.ReferenceExtractor.Extract(ReadUnicodeNullTerminated(r), "NetworkNetName", "utf16"));
        }
        if (deviceNameUnicode > 0 && start + deviceNameUnicode < r.BaseStream.Length)
        {
            r.BaseStream.Seek(start + deviceNameUnicode, SeekOrigin.Begin);
            result.Add(Analysis.ReferenceExtractor.Extract(ReadUnicodeNullTerminated(r), "NetworkDeviceName", "utf16"));
        }
        // 不重置流位置：ParseLinkInfo 末尾会按 linkInfoSize 统一回到 LinkInfo 边界
    }

    private static void ReadStringData(BinaryReader r, bool unicode, string role, ParsedFile result)
    {
        if (r.BaseStream.Position + 2 > r.BaseStream.Length) { result.Truncated = true; return; }
        var count = r.ReadUInt16();
        if (unicode)
        {
            var bytes = count * 2;
            if (r.BaseStream.Position + bytes + 2 > r.BaseStream.Length) { result.Truncated = true; return; }
            var s = Encoding.Unicode.GetString(r.ReadBytes(bytes));
            r.ReadBytes(2); // 终止空字符
            result.Add(Analysis.ReferenceExtractor.Extract(s, role, "utf16"));
        }
        else
        {
            if (r.BaseStream.Position + count + 1 > r.BaseStream.Length) { result.Truncated = true; return; }
            var s = Encoding.Latin1.GetString(r.ReadBytes(count));
            r.ReadByte();
            result.Add(Analysis.ReferenceExtractor.Extract(s, role, "ansi"));
        }
    }

    private static void ParseExtraData(BinaryReader r, ParsedFile result)
    {
        while (r.BaseStream.Position + 8 <= r.BaseStream.Length)
        {
            var blockSize = r.ReadUInt32();
            if (blockSize < 8) break; // 终止块（通常为 4 字节 0）
            if (r.BaseStream.Position - 4 + blockSize > r.BaseStream.Length)
            {
                result.Truncated = true;
                break;
            }

            var signature = r.ReadUInt32();
            var payloadStart = r.BaseStream.Position;
            var payloadLen = (int)(blockSize - 8);

            switch (signature)
            {
                case SigEnvironment:
                case SigIconEnvironment:
                {
                    var payload = r.ReadBytes(Math.Min(payloadLen, 1040));
                    // 结构为 ANSI(260) + Unicode(520) 固定缓冲
                    var ansi = Encoding.Latin1.GetString(payload[..Math.Min(260, payload.Length)]).Split('\0')[0];
                    result.Add(Analysis.ReferenceExtractor.Extract(ansi, "ExtraData.Environment", "ansi"));
                    if (payload.Length > 260)
                    {
                        var uni = Encoding.Unicode.GetString(payload[260..]).Split('\0')[0];
                        result.Add(Analysis.ReferenceExtractor.Extract(uni, "ExtraData.Environment", "utf16"));
                    }
                    break;
                }
                case SigTracker:
                {
                    // Version(4) 之后为 MachineID(Droid 等)，ANSI 空终止；机器名可用于横向移动线索
                    r.ReadUInt32();
                    var machine = ReadAnsiNullTerminated(r);
                    result.Add(Analysis.ReferenceExtractor.Extract(machine, "ExtraData.TrackerMachineId", "ansi"));
                    break;
                }
                case SigDarwin:
                {
                    var payload = r.ReadBytes(payloadLen);
                    var ansi = Encoding.Latin1.GetString(payload).Split('\0')[0];
                    result.Add(Analysis.ReferenceExtractor.Extract(ansi, "ExtraData.Darwin", "ansi"));
                    break;
                }
                case SigIconPath:
                {
                    var payload = r.ReadBytes(Math.Min(payloadLen, 520));
                    var uni = Encoding.Unicode.GetString(payload).Split('\0')[0];
                    result.Add(Analysis.ReferenceExtractor.Extract(uni, "IconLocation", "utf16"));
                    break;
                }
                default:
                    r.BaseStream.Seek(payloadStart, SeekOrigin.Begin);
                    r.ReadBytes(payloadLen); // 未知块跳过，末尾的字节扫荡兜底
                    break;
            }

            r.BaseStream.Seek(payloadStart + payloadLen, SeekOrigin.Begin);
        }
    }

    private static ParsedFile FinishWithSweep(byte[] bytes, ParsedFile result)
    {
        result.Add(Analysis.ReferenceExtractor.SweepRawBytes(bytes));
        return result;
    }

    private static string ReadAnsiNullTerminated(BinaryReader r)
    {
        var sb = new StringBuilder();
        while (r.BaseStream.Position < r.BaseStream.Length)
        {
            var b = r.ReadByte();
            if (b == 0) break;
            sb.Append((char)b);
        }
        return sb.ToString();
    }

    private static string ReadUnicodeNullTerminated(BinaryReader r)
    {
        var sb = new StringBuilder();
        while (r.BaseStream.Position + 1 < r.BaseStream.Length)
        {
            var ch = (char)(r.ReadByte() | (r.ReadByte() << 8));
            if (ch == 0) break;
            sb.Append(ch);
        }
        return sb.ToString();
    }
}
