using ShareGuard.Core.Classification;
using ShareGuard.Core.Engine;
using ShareGuard.Core.Models;
using ShareGuard.Core.Parsers;

namespace ShareGuard.Cli.Commands;

/// <summary>inspect:对单个文件做详细分析(应急响应 / 规则调试用)。</summary>
public static class InspectCommand
{
    public static async Task<int> RunAsync(CliArgs args, CancellationToken ct)
    {
        var path = args.RemainingPositionals.FirstOrDefault();
        if (path == null || !File.Exists(path))
        {
            Console.Error.WriteLine("用法: shareguard inspect <文件路径> [--config allowlist.json]");
            return 2;
        }

        var configPath = args.Get("config");
        var config = configPath != null
            ? await Core.Configuration.ConfigLoader.LoadAsync(configPath, ct)
            : AllowListConfig.Default;

        var analyzer = new FileAnalyzer(new ParserRegistry(), new HostClassifier(config));
        var result = analyzer.Analyze(path);

        Console.WriteLine($"文件:       {result.FilePath}");
        Console.WriteLine($"类型:       {result.FileType}");
        Console.WriteLine($"大小:       {result.FileSize} 字节");
        Console.WriteLine($"结论:       {result.Severity}");
        Console.WriteLine($"解析错误:   {result.ParseError}");
        Console.WriteLine();
        Console.WriteLine($"引用明细 ({result.References.Count}):");
        for (var i = 0; i < result.References.Count; i++)
        {
            var r = result.References[i];
            var v = i < result.Verdicts.Count ? result.Verdicts[i].ToString() : "?";
            Console.WriteLine($"  [{i}] {r.SourceField}");
            Console.WriteLine($"      原文:   {r.Raw}");
            Console.WriteLine($"      协议:   {r.Scheme}  主机: {r.Host ?? "(无)"}  端口: {r.Port?.ToString() ?? "默认"}");
            Console.WriteLine($"      判定:   {v}  显式凭据: {r.HasExplicitCredentials}  偏移: {r.Offset}");
        }
        Console.WriteLine();
        Console.WriteLine("判定依据:");
        foreach (var reason in result.Reasons)
            Console.WriteLine($"  - {reason}");

        return result.Severity == Severity.Malicious ? 1 : 0;
    }
}
