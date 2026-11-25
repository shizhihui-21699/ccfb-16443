using System.Net;
using System.Text.RegularExpressions;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Classification;

/// <summary>
/// 把原始引用字符串解析为 <see cref="EmbeddedReference"/>:
/// 统一处理 UNC、\\?\ 长路径、file:// URL、带凭据 URL、IPv6 字面量与显式端口。
/// </summary>
public static class ReferenceParser
{
    // 匹配 \\server\share 与 \\?\UNC\server\share;主机段允许 IPv6 方括号与 DNS 字符。
    // tail 排除空白,防止贪婪匹配把同一行里后续的第二个 UNC 一并吞掉。
    private static readonly Regex UncRegex = new(
        @"(?<prefix>\\\\\?\\UNC\\|\\\\)(?<host>[^\\/\[\]\s]+|\[[^\]]+\])(?<tail>\\[^\s""]*)?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // 通用带 scheme 的 URL;单独捕获 userinfo 以便标记显式凭据。
    private static readonly Regex UrlRegex = new(
        @"(?<scheme>[a-zA-Z][a-zA-Z0-9+.\-]{1,15})://(?<userinfo>[^@/\s]+@)?(?<host>[^@/\s:?#]+|\[[^\]]+\])(?::(?<port>\d{1,5}))?(?<tail>[/?#][^\s""]*)?",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>
    /// 解析一条引用。无法识别为 UNC/URL 时按本地引用返回(Host=null)。
    /// </summary>
    public static EmbeddedReference Parse(string raw, string sourceField, long? offset = null, string? encoding = null)
    {
        ArgumentNullException.ThrowIfNull(raw);
        var trimmed = raw.Trim();

        if (TryParseUnc(trimmed, out var uncHost, out var uncOffset))
        {
            return new EmbeddedReference
            {
                Raw = trimmed,
                SourceField = sourceField,
                Scheme = ReferenceScheme.Unc,
                Host = uncHost,
                Offset = offset ?? uncOffset,
                Encoding = encoding,
            };
        }

        var urlMatch = UrlRegex.Match(trimmed);
        if (urlMatch.Success)
        {
            var scheme = urlMatch.Groups["scheme"].Value.ToLowerInvariant();
            var host = NormalizeHost(urlMatch.Groups["host"].Value);
            int? port = urlMatch.Groups["port"].Success ? int.Parse(urlMatch.Groups["port"].Value) : null;
            return new EmbeddedReference
            {
                Raw = trimmed,
                SourceField = sourceField,
                Scheme = SchemeFromName(scheme),
                Host = host,
                Port = port,
                HasExplicitCredentials = urlMatch.Groups["userinfo"].Success,
                Offset = offset,
                Encoding = encoding,
            };
        }

        return new EmbeddedReference
        {
            Raw = trimmed,
            SourceField = sourceField,
            Scheme = ReferenceScheme.Local,
            Host = null,
            Offset = offset,
            Encoding = encoding,
        };
    }

    /// <summary>从任意文本(例如 LNK 二进制字符串区)中提取全部 UNC / URL 引用。</summary>
    public static IEnumerable<(string Value, long Offset)> ExtractNetworkStrings(string text, long baseOffset = 0)
    {
        foreach (Match m in UncRegex.Matches(text))
        {
            // 排除 \\.\ 设备路径之类:UncRegex 的主机段至少含一个点或为合法名,
            // 单独再过滤明显的设备前缀。
            var host = m.Groups["host"].Value;
            if (host is "." or "?" ) continue;
            // 盘符前缀(如 C:\\Windows)不是 UNC,而是畸形本地路径,跳过
            if (m.Index >= 2 && text[m.Index - 1] == ':' && char.IsLetter(text[m.Index - 2])) continue;
            yield return (m.Value, baseOffset + m.Index);
        }

        foreach (Match m in UrlRegex.Matches(text))
        {
            // file:// 相对路径或无主机形式不产生认证,跳过无主机匹配。
            if (!m.Groups["host"].Success || string.IsNullOrWhiteSpace(m.Groups["host"].Value)) continue;
            yield return (m.Value, baseOffset + m.Index);
        }
    }

    private static bool TryParseUnc(string value, out string? host, out long offset)
    {
        host = null;
        offset = 0;
        var m = UncRegex.Match(value);
        if (!m.Success || m.Index != 0) return false;
        var h = m.Groups["host"].Value;
        if (h is "." or "?") return false;
        host = NormalizeHost(h);
        offset = m.Groups["host"].Index;
        return true;
    }

    /// <summary>
    /// 规范化主机:去 IPv6 方括号、去结尾点、小写。不做 DNS 解析(离线扫描,千万级文件也承受不起)。
    /// </summary>
    public static string NormalizeHost(string host)
    {
        var h = host.Trim();
        if (h.StartsWith('[') && h.EndsWith(']')) h = h[1..^1];
        h = h.TrimEnd('.').ToLowerInvariant();
        return h;
    }

    public static bool IsIPAddress(string host, out IPAddress? address)
        => IPAddress.TryParse(host, out address);

    private static ReferenceScheme SchemeFromName(string scheme) => scheme switch
    {
        "file" => ReferenceScheme.FileUrl,
        "http" or "https" => ReferenceScheme.Http,
        "ldap" or "ldaps" => ReferenceScheme.Ldap,
        "ftp" or "ftps" => ReferenceScheme.Ftp,
        "dav" or "davs" => ReferenceScheme.WebDav,
        _ => ReferenceScheme.Other,
    };
}
