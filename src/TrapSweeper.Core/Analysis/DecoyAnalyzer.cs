using System.Security.Cryptography;
using TrapSweeper.Core.Classification;
using TrapSweeper.Core.Models;
using TrapSweeper.Core.Parsers;

namespace TrapSweeper.Core.Analysis;

/// <summary>把"文件字节 + 元数据"转换为带判定结论的 <see cref="Finding"/>。</summary>
public sealed class DecoyAnalyzer
{
    private readonly HostClassifier _classifier;

    public DecoyAnalyzer(HostClassifier classifier) => _classifier = classifier;

    public Finding Analyze(string path, DecoyKind kind, byte[] bytes, DateTime lastWriteUtc, bool hiddenOrSystem)
    {
        ParsedFile parsed;
        try
        {
            parsed = FileTypeRegistry.Parse(bytes, kind);
        }
        catch (Exception ex)
        {
            // 解析器本身异常也不能静默：以原始字节扫荡结果兜底上报
            parsed = new ParsedFile { Kind = kind, Error = $"解析器异常: {ex.Message}", Truncated = true };
            parsed.Add(ReferenceExtractor.SweepRawBytes(bytes));
        }

        var finding = new Finding
        {
            FilePath = path,
            Kind = parsed.Kind ?? kind,
            Sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
            SizeBytes = bytes.Length,
            LastWriteTimeUtc = lastWriteUtc,
            IsHiddenOrSystem = hiddenOrSystem,
            ParseTruncated = parsed.Truncated,
            Error = parsed.Error
        };

        // 同一引用可能从多个字段/编码通道被提取，按 (role,raw) 去重
        var dedup = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var reference in parsed.References)
        {
            if (!dedup.Add($"{reference.Role}|{reference.Raw}")) continue;
            finding.References.Add(reference);

            if (string.IsNullOrEmpty(reference.Host)) continue;
            var verdict = _classifier.Classify(reference);
            var existing = finding.HostVerdicts.FirstOrDefault(x =>
                x.Host.Equals(verdict.Host, StringComparison.OrdinalIgnoreCase));
            if (existing == null)
            {
                finding.HostVerdicts.Add(verdict);
            }
            else if (verdict.Score > existing.Score)
            {
                // 同一主机被多个字段引用时保留最严重的结论，但合并信号
                foreach (var s in verdict.Signals.Where(s => !existing.Signals.Contains(s)))
                    existing.Signals.Add(s);
                foreach (var r in verdict.MatchedAllowRules.Where(r => !existing.MatchedAllowRules.Contains(r)))
                    existing.MatchedAllowRules.Add(r);
                existing.Score = verdict.Score;
                existing.Severity = verdict.Severity;
                existing.Verdict = verdict.Verdict;
            }
        }

        AggregateFinding(finding);
        return finding;
    }

    private static void AggregateFinding(Finding finding)
    {
        if (finding.HostVerdicts.Count == 0)
        {
            // 诱饵格式但不含任何网络引用：常见于空壳/损坏文件，仍记录为低级别供基线统计
            finding.Verdict = Verdict.Allowed;
            finding.Severity = Severity.Info;
            if (finding.Error != null)
                finding.Reasons.Add($"解析失败已兜底扫描: {finding.Error}");
            return;
        }

        var bad = finding.HostVerdicts.Where(x => x.IsBad).ToList();
        if (bad.Count == 0)
        {
            finding.Verdict = Verdict.Allowed;
            finding.Severity = Severity.Info;
            return;
        }

        finding.Verdict = bad.Any(x => x.Verdict == Verdict.External) ? Verdict.External : Verdict.Suspicious;
        finding.Severity = bad.Max(x => x.Severity);
        finding.Score = bad.Sum(x => x.Score);
        finding.Reasons = bad
            .SelectMany(x => x.Signals.Select(s => $"[{x.Host}] {s}"))
            .Distinct()
            .ToList();

        if (finding.IsHiddenOrSystem)
        {
            finding.Reasons.Add("文件带隐藏/系统属性（诱饵文件常用属性，避免在资源管理器中被直接看到）");
            finding.Score += 5;
        }
        if (finding.ParseTruncated)
            finding.Reasons.Add("文件结构不完整或含未知块，结论基于尽力解析+字节扫荡");
    }
}
