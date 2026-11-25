using System.Text;
using ShareGuard.Core.Classification;
using ShareGuard.Core.Models;

namespace ShareGuard.Core.Parsers;

/// <summary>
/// 对二进制内容做 ASCII 与 UTF-16LE 双编码字符串扫描,
/// 提取其中所有 UNC / URL 网络引用。作用:
///   1. 兜底畸形或被裁剪的 LNK(结构化解析提前失败时仍有产出);
///   2. 覆盖未来未知的二进制诱饵格式;
///   3. 捕获 ExtraData 中未结构化解析的字符串块。
/// 最小长度过滤掉巧合字节序列;同一原文只保留一份。
/// </summary>
public static class StringSweeper
{
    private const int MinStringLength = 4;

    public static void Sweep(byte[] content, List<EmbeddedReference> sink)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in sink) seen.Add(r.Raw);

        // ---- ASCII 可打印串 ----
        var start = -1;
        for (var i = 0; i <= content.Length; i++)
        {
            if (i < content.Length && IsPrintableAscii(content[i]))
            {
                if (start < 0) start = i;
            }
            else
            {
                if (start >= 0 && i - start >= MinStringLength)
                {
                    var value = Encoding.ASCII.GetString(content, start, i - start);
                    Emit(value, start, "ASCII", seen, sink);
                }
                start = -1;
            }
        }

        // ---- UTF-16LE 串 ----
        // 两个陷阱:
        //   1) UTF-16LE 的可打印 ASCII 字符形如 "字节,0x00",但字符串可能从奇数字节
        //      偏移开始(LNK 各区块按 1 字节粒度拼接),必须偶数/奇数两种相位都扫,
        //      否则会把 5C 00 5C 00 错读成 00 5C 00 5C 而全部漏掉;
        //   2) 字符串内部可能夹杂 NUL(00 00),会把长串切碎,状态机需容忍短暂中断。
        // 段结束后统一解码,再在解码出的字符串上跑 UNC/URL 正则(不能在字节层直接
        // 匹配,因为 UTF-16LE 的两个反斜杠在字节层并不相邻)。
        foreach (var phase in new[] { 0, 1 })
        {
            var runStart = -1;
            var gap = 0;
            const int maxGapBytes = 4;
            var q = phase;
            for (; q + 1 < content.Length; q += 2)
            {
                var printablePair = content[q + 1] == 0 && IsPrintableAscii(content[q]);
                if (printablePair)
                {
                    if (runStart < 0) runStart = q;
                    gap = 0;
                }
                else if (runStart >= 0)
                {
                    gap += 2;
                    if (gap > maxGapBytes)
                    {
                        if ((q - runStart) / 2 >= MinStringLength)
                            EmitUtf16(content, runStart, q - gap, seen, sink);
                        runStart = -1;
                        gap = 0;
                    }
                }
            }
            if (runStart >= 0 && (q - runStart) / 2 >= MinStringLength)
                EmitUtf16(content, runStart, q - gap, seen, sink);
        }
    }

    private static void EmitUtf16(byte[] content, int start, int end,
        HashSet<string> seen, List<EmbeddedReference> sink)
    {
        var decoded = Encoding.Unicode.GetString(content, start, end - start);
        foreach (var (candidate, rel) in ReferenceParser.ExtractNetworkStrings(decoded))
        {
            if (!seen.Add(candidate)) continue;
            sink.Add(ReferenceParser.Parse(candidate, "StringSweep", start + rel * 2, "UTF16LE"));
        }
    }

    private static void Emit(string value, long baseOffset, string encoding,
        HashSet<string> seen, List<EmbeddedReference> sink)
    {
        foreach (var (candidate, rel) in ReferenceParser.ExtractNetworkStrings(value, baseOffset))
        {
            if (!seen.Add(candidate)) continue;
            var parsed = ReferenceParser.Parse(candidate, "StringSweep", rel, encoding);
            if (parsed.Scheme is ReferenceScheme.Unc or ReferenceScheme.FileUrl
                or ReferenceScheme.Http or ReferenceScheme.Ldap or ReferenceScheme.Ftp
                or ReferenceScheme.WebDav or ReferenceScheme.Other)
            {
                sink.Add(parsed);
            }
        }
    }

    private static bool IsPrintableAscii(byte b) => b >= 0x20 && b < 0x7F;
}
