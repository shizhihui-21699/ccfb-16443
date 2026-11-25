using TrapSweeper.Core.Analysis;
using TrapSweeper.Core.Classification;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Cli;

/// <summary>inspect 命令：对单个文件做深度解析，输出全部引用与判定证据，用于应急响应取证。</summary>
public static class InspectRunner
{
    public static int Run(CommandLine cl)
    {
        var path = cl.Positional.ElementAtOrDefault(0) ?? cl.Get("file")
                   ?? throw new ArgumentException("需要文件路径参数或 --file <path>");
        if (!File.Exists(path)) throw new FileNotFoundException(path);

        var config = AllowListConfig.Load(cl.Require("config"));
        var analyzer = new DecoyAnalyzer(new HostClassifier(config));

        var info = new FileInfo(path);
        var spec = FileTypeRegistry.ByExtensionFirst(path)
                   ?? (TrySniff(path) ? FileTypeRegistry.ByExtensionFirst("x.lnk")! : null)
                   ?? throw new InvalidOperationException("不在追踪扩展名清单内，且头部嗅探未识别为 ShellLink。");

        var bytes = File.ReadAllBytes(path);
        var hidden = info.Attributes.HasFlag(FileAttributes.Hidden) || info.Attributes.HasFlag(FileAttributes.System);
        var finding = analyzer.Analyze(Path.GetFullPath(path), spec.Kind, bytes, info.LastWriteTimeUtc, hidden);

        Console.WriteLine($"文件: {finding.FilePath}");
        Console.WriteLine($"类型: {finding.Kind}  大小: {finding.SizeBytes}  隐藏/系统: {finding.IsHiddenOrSystem}");
        Console.WriteLine($"SHA256: {finding.Sha256}");
        Console.WriteLine($"结论: {finding.Verdict}  级别: {finding.Severity}  分数: {finding.Score}");
        if (finding.Error != null) Console.WriteLine($"解析告警: {finding.Error}");
        Console.WriteLine();

        if (finding.References.Count == 0)
        {
            Console.WriteLine("未提取到任何主机/UNC/URL 引用。");
            return finding.IsActionable ? 2 : 0;
        }

        Console.WriteLine($"提取到 {finding.References.Count} 条引用:");
        foreach (var r in finding.References)
        {
            Console.WriteLine($"  [{r.Encoding}] {r.Role}");
            Console.WriteLine($"      原始: {r.Raw}");
            Console.WriteLine($"      解析: scheme={r.Scheme} host={r.Host} port={r.Port?.ToString() ?? "-"} share={r.Share ?? "-"}");
            Console.WriteLine($"      标记: IP={r.IsIpLiteral} 混淆IP={r.IsObfuscatedIp} 内嵌凭证={r.HasEmbeddedCredentials}");
        }

        Console.WriteLine();
        Console.WriteLine("主机判定:");
        foreach (var h in finding.HostVerdicts)
        {
            Console.WriteLine($"  {h.Host} -> {h.Verdict}/{h.Severity} (score {h.Score})");
            foreach (var s in h.Signals) Console.WriteLine($"      信号: {s}");
            foreach (var a in h.MatchedAllowRules) Console.WriteLine($"      放行规则: {a}");
        }

        if (finding.Reasons.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("文件级理由:");
            foreach (var reason in finding.Reasons) Console.WriteLine($"  - {reason}");
        }

        return finding.IsActionable ? 2 : 0;
    }

    private static bool TrySniff(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var head = new byte[76]; // ShellLink 头完整长度
            var read = fs.Read(head);
            return read >= 76 && Core.Parsers.LnkParser.IsLnkByHeader(head);
        }
        catch { return false; }
    }
}
