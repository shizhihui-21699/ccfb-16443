using System.Text;
using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// Windows Shell Link(.lnk)解析器,实现 [MS-SHLLINK] 的结构化读取。
/// 关注三类可触发强制认证的位置:
///   1. LinkInfo / CommonNetworkRelativeLink 中的网络 UNC 目标;
///   2. StringData 中的 IconLocation、相对路径、工作目录、命令行参数;
///   3. ExtraData 中的 EnvironmentVariable(可内嵌 %USERNAME% 等展开后的 UNC)。
/// 结构化解析之外,再对整个二进制做 ASCII / UTF-16LE 双编码字符串扫描兜底,
/// 保证畸形或被刻意裁剪的样本里的 UNC/URL 仍能被发现。
/// </summary>
public sealed class LnkParser : IBaitParser
{
    private static readonly byte[] Clsid =
    [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ];

    // LinkFlags 位掩码(MS-SHLLINK 2.1.1)
    private const uint HasLinkTargetIdList = 0x00000001;
    private const uint HasLinkInfo = 0x00000002;
    private const uint HasName = 0x00000004;
    private const uint HasRelativePath = 0x00000008;
    private const uint HasWorkingDir = 0x00000010;
    private const uint HasArguments = 0x00000020;
    private const uint HasIconLocation = 0x00000040;
    private const uint IsUnicodeFlag = 0x00000080;

    public BaitFileType FileType => BaitFileType.Lnk;
    public IReadOnlySet<string> Extensions { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { ".lnk" };

    public IReadOnlyList<EmbeddedReference> Parse(string filePath, byte[] content)
    {
        if (content.Length < 0x4C)
            throw new BaitParseException("文件小于 76 字节 ShellLinkHeader,不是有效 LNK");

        var reader = new SpanReader(content);
        var headerSize = reader.ReadUInt32();
        if (headerSize != 0x4C)
            throw new BaitParseException($"HeaderSize={headerSize},预期 76");

        var clsid = reader.ReadBytes(16);
        if (!clsid.SequenceEqual(Clsid))
            throw new BaitParseException("CLSID 不匹配 ShellLink 结构");

        reader.Skip(4);                 // LinkFlags 之前的 LinkCLSID 之后:LinkFlags 位于偏移 20
        var flags = reader.ReadUInt32();
        reader.Skip(40);                // 剩余 header 字段(FileAttributes 到 Reserved)

        var refs = new List<EmbeddedReference>();

        // LinkTargetIDList
        if ((flags & HasLinkTargetIdList) != 0)
        {
            var idListSize = reader.ReadUInt16();
            if (!reader.CanRead(idListSize))
                throw new BaitParseException("IDList 越界");
            // IDList 内部为 ItemID,网络位置信息在 LinkInfo 中有更规范的表达,
            // 这里仅跳过,统一交给字符串扫描兜底。
            reader.Skip(idListSize);
        }

        if ((flags & HasLinkInfo) != 0)
            ParseLinkInfo(content, ref reader, refs);

        ParseStringData(content, ref reader, flags, refs);
        // ExtraData(含 TerminalBlock 0x00000004)结构变化多,统一走字符串扫描;
        // 先定位到文件尾部无需精确跳过。

        // 兜底:双编码全量字符串扫描
        StringSweeper.Sweep(content, refs);
        return Dedupe(refs);
    }

    private static void ParseLinkInfo(byte[] content, ref SpanReader reader, List<EmbeddedReference> refs)
    {
        var start = reader.Position;
        var size = reader.ReadUInt32();
        if (size < 28 || !reader.CanRead((int)size))
            throw new BaitParseException($"LinkInfoSize={size} 越界");
        var end = start + (int)size;

        var headerSize = reader.ReadUInt32();
        if (headerSize is not (0x1C or 0x24))
            throw new BaitParseException($"LinkInfoHeaderSize={headerSize} 非预期值");
        var infoFlags = reader.ReadUInt32();
        var volumeIdOffset = reader.ReadUInt32();
        var localBasePathOffset = reader.ReadUInt32();
        var commonNetworkOffset = reader.ReadUInt32();
        var commonPathSuffixOffset = reader.ReadUInt32();

        // 扩展头(0x24)才有两个 Unicode 偏移
        uint localBasePathUnicodeOffset = 0, commonPathSuffixUnicodeOffset = 0;
        if (headerSize == 0x24)
        {
            localBasePathUnicodeOffset = reader.ReadUInt32();
            commonPathSuffixUnicodeOffset = reader.ReadUInt32();
        }

        // CommonNetworkRelativeLink:外发认证的主要载体
        if (commonNetworkOffset > 0 && start + commonNetworkOffset < end)
        {
            var saved = reader.Position;
            reader.Seek(start + (int)commonNetworkOffset);
            try
            {
                ParseCommonNetworkLink(content, ref reader, start, end, refs);
            }
            catch (BaitParseException)
            {
                // 畸形网络链接块:忽略结构化结果,依赖字符串扫描
            }
            reader.Seek(saved);
        }

        // 本地 BasePath / CommonSuffix 也可能是 UNC 字符串(部分工具生成的 LNK 会这样写)
        if (localBasePathOffset > 0 && start + localBasePathOffset < end)
            ReadAsciiStringAt(content, start + (int)localBasePathOffset, end, "LinkInfo.LocalBasePath", refs);
        if (commonPathSuffixOffset > 0 && start + commonPathSuffixOffset < end)
            ReadAsciiStringAt(content, start + (int)commonPathSuffixOffset, end, "LinkInfo.CommonPathSuffix", refs);
        if (headerSize == 0x24)
        {
            if (localBasePathUnicodeOffset > 0 && start + localBasePathUnicodeOffset < end)
                ReadUtf16StringAt(content, start + (int)localBasePathUnicodeOffset, end, "LinkInfo.LocalBasePathUnicode", refs);
            if (commonPathSuffixUnicodeOffset > 0 && start + commonPathSuffixUnicodeOffset < end)
                ReadUtf16StringAt(content, start + (int)commonPathSuffixUnicodeOffset, end, "LinkInfo.CommonPathSuffixUnicode", refs);
        }

        reader.Seek(end);
    }

    private static void ParseCommonNetworkLink(byte[] content, ref SpanReader reader, int linkInfoStart,
        int linkInfoEnd, List<EmbeddedReference> refs)
    {
        var blockStart = reader.Position;
        var blockSize = reader.ReadUInt32();
        if (blockSize < 8 || blockStart + blockSize > linkInfoEnd)
            throw new BaitParseException("CommonNetworkRelativeLink 越界");

        reader.ReadUInt32();                       // CommonNetworkRelativeLinkFlags
        var netNameOffset = reader.ReadUInt32();   // 相对 blockStart
        reader.ReadUInt32();                       // DeviceNameOffset
        uint netNameUnicodeOffset = 0;
        if (blockSize >= 0x18 && reader.Remaining >= 4)
            netNameUnicodeOffset = reader.ReadUInt32();

        if (netNameOffset > 0 && blockStart + netNameOffset < linkInfoEnd)
            ReadAsciiStringAt(content, blockStart + (int)netNameOffset, linkInfoEnd,
                "CommonNetworkRelativeLink.NetName", refs);
        if (netNameUnicodeOffset > 0 && blockStart + netNameUnicodeOffset < linkInfoEnd)
            ReadUtf16StringAt(content, blockStart + (int)netNameUnicodeOffset, linkInfoEnd,
                "CommonNetworkRelativeLink.NetNameUnicode", refs);
    }

    private static void ParseStringData(byte[] content, ref SpanReader reader, uint flags, List<EmbeddedReference> refs)
    {
        // 顺序固定:NAME, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
        var unicode = HasUnicodeFlag(flags);
        TryReadString(ref reader, flags, HasName, unicode, "StringData.Name", refs);
        TryReadString(ref reader, flags, HasRelativePath, unicode, "StringData.RelativePath", refs);
        TryReadString(ref reader, flags, HasWorkingDir, unicode, "StringData.WorkingDir", refs);
        TryReadString(ref reader, flags, HasArguments, unicode, "StringData.Arguments", refs);
        TryReadString(ref reader, flags, HasIconLocation, unicode, "StringData.IconLocation", refs);
    }

    private static bool HasUnicodeFlag(uint flags) => (flags & IsUnicodeFlag) != 0;

    private static void TryReadString(ref SpanReader reader, uint flags, uint flag, bool unicode,
        string field, List<EmbeddedReference> refs)
    {
        if ((flags & flag) == 0) return;
        if (reader.Remaining < 2) return;
        var charCount = reader.ReadUInt16();
        if (charCount == 0) return;
        if (unicode)
        {
            var byteCount = charCount * 2;
            if (!reader.CanRead(byteCount)) return;
            var span = reader.ReadBytes(byteCount);
            var s = Encoding.Unicode.GetString(span);
            AddIfNetwork(s, field, refs);
        }
        else
        {
            if (!reader.CanRead(charCount)) return;
            var span = reader.ReadBytes(charCount);
            var s = Encoding.ASCII.GetString(span);
            AddIfNetwork(s, field, refs);
        }
    }

    private static void ReadAsciiStringAt(byte[] content, int offset, int end, string field, List<EmbeddedReference> refs)
    {
        var sb = new StringBuilder();
        var p = offset;
        while (p < end && content[p] != 0) { sb.Append((char)content[p]); p++; }
        AddIfNetwork(sb.ToString(), field, refs);
    }

    private static void ReadUtf16StringAt(byte[] content, int offset, int end, string field, List<EmbeddedReference> refs)
    {
        var sb = new StringBuilder();
        var p = offset;
        while (p + 1 < end)
        {
            var c = BitConverter.ToUInt16(content, p);
            if (c == 0) break;
            sb.Append((char)c);
            p += 2;
        }
        AddIfNetwork(sb.ToString(), field, refs);
    }

    private static void AddIfNetwork(string value, string field, List<EmbeddedReference> refs)
    {
        if (string.IsNullOrWhiteSpace(value)) return;
        // 一条字符串里可能同时有多个引用(命令行参数场景),逐个提取
        foreach (var (candidate, _) in ReferenceParser.ExtractNetworkStrings(value))
            refs.Add(ReferenceParser.Parse(candidate, field));
    }

    private static List<EmbeddedReference> Dedupe(List<EmbeddedReference> refs)
    {
        var seen = new HashSet<(string, string)>();
        var result = new List<EmbeddedReference>();
        foreach (var r in refs)
        {
            if (seen.Add((r.Raw, r.SourceField)))
                result.Add(r);
        }
        return result;
    }
}
