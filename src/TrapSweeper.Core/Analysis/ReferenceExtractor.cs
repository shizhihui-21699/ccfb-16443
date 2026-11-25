using System.Buffers.Binary;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Analysis;

/// <summary>
/// 从任意字符串中提取主机引用：UNC、file:// URI、http(s):// URI、内嵌凭证。
/// 同时识别十进制/八进制/十六进制等混淆 IP（攻击者常用 \123.123.123.123 与 \0xa9... 绕过简单字符串规则）。
/// </summary>
public static partial class ReferenceExtractor
{
    // UNC：\\host\share 或 \\host\share\path；也兼容 \\?\UNC\ 长路径前缀。
    // 组1 为纯 authority（host[:port]，在 / \ 处终止），组2 为其后的 share/path 原文。
    [GeneratedRegex(@"(?:\\{2}|file:[/\\]{2})(?:\?[/\\]UNC[/\\])?([^\\""'<>|/\u0000-\u001f]{1,256})((?:[\\/][^\\""'<>|\u0000-\u001f]{0,256})*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UncRegex();

    [GeneratedRegex(@"https?://[^\s""'<>|*]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex HttpRegex();

    [GeneratedRegex(@"^[a-z][a-z0-9+.-]*://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SchemePrefixRegex();

    private static readonly char[] HostSeparators = { '/', '\\' };

    /// <summary>提取一段文本中的全部引用。</summary>
    /// <param name="text">已解码为字符串的内容（UTF-16 或 ANSI 通道）。</param>
    /// <param name="role">引用角色标签。</param>
    /// <param name="encoding">来源编码标签。</param>
    public static IEnumerable<HostReference> Extract(string text, string role, string encoding = "ascii")
    {
        if (string.IsNullOrWhiteSpace(text)) yield break;

        foreach (Match m in UncRegex().Matches(text))
        {
            var authority = m.Groups[1].Value.Trim();
            var rest = m.Groups[2].Value;
            if (TryParseAuthority(authority, rest, out var scheme, out var host, out var port, out var share, out var path))
            {
                if (!LooksLikeHost(host.TrimStart('@'))) continue;
                yield return Build(m.Value, role, encoding, scheme, host, port, share, path);
            }
        }

        foreach (Match m in HttpRegex().Matches(text))
        {
            if (Uri.TryCreate(m.Value, UriKind.Absolute, out var uri) && !uri.IsLoopback)
            {
                if (!LooksLikeHost(uri.Host)) continue;
                yield return new HostReference
                {
                    Raw = m.Value,
                    Role = role,
                    Scheme = uri.Scheme,
                    Host = uri.Host,
                    Port = uri.IsDefaultPort ? null : uri.Port,
                    Path = uri.AbsolutePath,
                    IsIpLiteral = IsIpAddress(uri.Host, out _),
                    IsObfuscatedIp = IsObfuscatedIpLiteral(uri.Host),
                    HasEmbeddedCredentials = !string.IsNullOrEmpty(uri.UserInfo),
                    Encoding = encoding
                };
            }
        }
    }

    private static bool TryParseAuthority(string authority, string rest, out string scheme, out string host,
        out int? port, out string? share, out string? path)
    {
        scheme = "unc";
        port = null;
        share = null;
        path = null;
        host = string.Empty;

        var creds = false;
        if (authority.Contains('@'))
        {
            creds = true;
            authority = authority[(authority.LastIndexOf('@') + 1)..];
        }

        if (authority.StartsWith('[')) // IPv6 字面量 [fe80::1]
        {
            var close = authority.IndexOf(']');
            if (close < 0) return false;
            host = authority[1..close];
            if (authority.Length > close + 1 && authority[close + 1] == ':')
                port = TryPort(authority[(close + 2)..]);
        }
        else
        {
            var colon = authority.IndexOf(':');
            if (colon >= 0)
            {
                host = authority[..colon];
                port = TryPort(authority[(colon + 1)..]);
            }
            else
            {
                host = authority;
            }
        }

        var seg = rest.Split(HostSeparators, StringSplitOptions.RemoveEmptyEntries);
        if (seg.Length > 0) share = seg[0];
        if (seg.Length > 1) path = string.Join('\\', seg, 1, seg.Length - 1);

        if (creds) host = "@" + host;
        return host.Length > 0;
    }

    private static HostReference Build(string raw, string role, string encoding, string scheme, string host,
        int? port, string? share, string? path)
    {
        var creds = host.StartsWith('@');
        if (creds) host = host[1..];

        var obf = IsObfuscatedIpLiteral(host);
        var isIp = IsIpAddress(host, out var normalized);
        if (isIp && normalized is not null) host = normalized;

        return new HostReference
        {
            Raw = raw,
            Role = role,
            Scheme = scheme,
            Host = host,
            Port = port,
            Share = share,
            Path = path,
            IsIpLiteral = isIp,
            IsObfuscatedIp = obf,
            HasEmbeddedCredentials = creds,
            Encoding = encoding
        };
    }

    private static int? TryPort(string s) => int.TryParse(s, out var p) && p is > 0 and <= 65535 ? p : null;

    /// <summary>主机名合法性粗筛，排除把 "C$"、盘符、管道等当成主机的情况。</summary>
    private static bool LooksLikeHost(string h)
    {
        if (string.IsNullOrWhiteSpace(h) || h is "." or "..") return false;
        if (h.Length is < 1 or > 253) return false;
        if (h[0] is '.' or '-' || h.EndsWith('-')) return false;
        // 盘符形式 D: / D$
        if (h.Length == 2 && h[1] is ':' or '$' && char.IsLetter(h[0])) return false;
        return true;
    }

    /// <summary>判断是否为 IP 字面量（含 IPv6），成功时返回规范化形式。</summary>
    public static bool IsIpAddress(string host, out string? normalized)
    {
        normalized = null;
        if (IPAddress.TryParse(host, out var ip))
        {
            normalized = ip.ToString();
            return true;
        }
        return false;
    }

    /// <summary>
    /// 识别非标准写法的 IPv4：十进制整数(0xA9FE...)、八进制(0177...)、混合进制。
    /// inet_addr 接受这些形式，SMB 客户端同样会解析，因此 \2886729984\share 能直达攻击者主机。
    /// </summary>
    public static bool IsObfuscatedIpLiteral(string host)
    {
        if (host.Contains(':')) return false; // IPv6/端口由调用方处理
        var labels = host.Split('.');
        if (labels.Length is 0 or > 4) return false;

        var anyNumeric = false;
        foreach (var label in labels)
        {
            if (label.Length == 0) return false;
            if (TryParseRadix(label, out _)) { anyNumeric = true; continue; }
            return false; // 含非数字标签 → 域名
        }

        if (!anyNumeric) return false;
        // 标准 4 段、每段 0..255 的纯十进制不算混淆；全 0 段（如 0.0.0.0）也属标准写法
        if (labels.Length == 4 && labels.All(l =>
                !l.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                long.TryParse(l, out var n) && n is >= 0 and <= 255))
            return false;
        return true;
    }

    /// <summary>尝试把混淆 IP 还原为标准点分十进制，失败返回 null。</summary>
    public static string? NormalizeObfuscatedIp(string host)
    {
        try
        {
            var labels = host.Split('.');
            if (labels.Length is 0 or > 4) return null;
            var values = new List<long>();
            foreach (var label in labels)
            {
                if (!TryParseRadix(label, out var v)) return null;
                values.Add(v);
            }

            long numeric;
            if (values.Count == 1)
            {
                numeric = values[0];
            }
            else
            {
                numeric = 0;
                for (var i = 0; i < values.Count; i++)
                {
                    var shift = (values.Count - 1 - i) * 8;
                    numeric |= values[i] << shift;
                }
            }

            if (numeric is < 0 or > uint.MaxValue) return null;
            var u = (uint)numeric;
            return $"{(u >> 24) & 0xff}.{(u >> 16) & 0xff}.{(u >> 8) & 0xff}.{u & 0xff}";
        }
        catch { return null; }
    }

    private static bool TryParseRadix(string s, out long value)
    {
        value = 0;
        if (s.Length == 0) return false;
        try
        {
            if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                value = Convert.ToInt64(s, 16);
                return true;
            }
            if (s.Length > 1 && s[0] == '0') // 0 开头按八进制（inet_addr 语义）
            {
                value = Convert.ToInt64(s, 8);
                return true;
            }
            return long.TryParse(s, out value);
        }
        catch { return false; }
    }

    /// <summary>
    /// 对二进制内容做两路字符串扫荡：UTF-16LE 与 ASCII/ANSI。
    /// 用于解析失败的未知 LNK 结构以及损坏文件，保证不静默漏报。
    /// </summary>
    public static IEnumerable<HostReference> SweepRawBytes(byte[] bytes, int maxResultsPerChannel = 256)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var s in ExtractUtf16LeStrings(bytes))
        {
            foreach (var r in Extract(s, "raw-utf16", "utf16"))
                if (seen.Add(r.Raw)) yield return r;
            if (seen.Count >= maxResultsPerChannel) break;
        }

        var ansi = Encoding.Latin1.GetString(bytes);
        foreach (var r in Extract(ansi, "raw-ansi", "ansi"))
            if (seen.Add(r.Raw)) yield return r;
    }

    private static IEnumerable<string> ExtractUtf16LeStrings(byte[] bytes)
    {
        var sb = new StringBuilder();
        for (var i = 0; i + 1 < bytes.Length; i += 2)
        {
            var ch = (char)BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i, 2));
            if (ch >= 0x20 && ch != 0x7f)
            {
                sb.Append(ch);
            }
            else if (sb.Length >= 4)
            {
                yield return sb.ToString();
                sb.Clear();
            }
            else
            {
                sb.Clear();
            }
        }
        if (sb.Length >= 4) yield return sb.ToString();
    }

    /// <summary>是否为带 scheme 的绝对 URI（供解析器区分相对路径）。</summary>
    public static bool HasScheme(string value) => SchemePrefixRegex().IsMatch(value);
}
