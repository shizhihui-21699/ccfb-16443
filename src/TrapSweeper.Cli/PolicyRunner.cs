using System.Text;
using TrapSweeper.Core.Policy;

namespace TrapSweeper.Cli;

/// <summary>policy 命令处理器：audit / apply / export-reg / export-firewall。</summary>
public static class PolicyRunner
{
    public static int Run(CommandLine cl)
    {
        var action = cl.Positional.ElementAtOrDefault(0)
                     ?? throw new ArgumentException("需要子动作: audit | apply | export-reg | export-firewall");
        var profile = ParseProfile(cl.Get("profile") ?? "balanced");
        var exceptions = cl.GetList("ntlm-exceptions");
        var outDir = cl.Get("out") ?? Path.Combine(Directory.GetCurrentDirectory(), "trapsweeper-output", "policy");
        Directory.CreateDirectory(outDir);

        using IRegistryStore registry = OperatingSystem.IsWindows()
            ? new WindowsRegistryStore()
            : new InMemoryRegistryStore();

        var engine = new PolicyEngine(registry);

        switch (action.ToLowerInvariant())
        {
            case "audit":
                return Audit(engine, profile);
            case "apply":
                return Apply(cl, engine, profile, exceptions, outDir);
            case "export-reg":
                return ExportReg(engine, profile, outDir);
            case "export-firewall":
                return ExportFirewall(cl, outDir);
            default:
                throw new ArgumentException($"未知策略动作: {action}");
        }
    }

    private static int Audit(PolicyEngine engine, PolicyEngine.Profile profile)
    {
        var result = engine.Audit(profile);
        Console.WriteLine($"平台: {(result.IsWindows ? "Windows" : "非 Windows（内存干跑）")}  档位: {profile}");
        Console.WriteLine($"合规 {result.Compliant} / 不合规 {result.NonCompliant} / 未配置 {result.NotConfigured}");
        Console.WriteLine();
        foreach (var c in result.Checks)
        {
            var mark = c.State switch
            {
                PolicyState.Compliant => "✓",
                PolicyState.NonCompliant => "✗",
                PolicyState.NotConfigured => "·",
                _ => "?"
            };
            using (new ColorScope(c.State == PolicyState.Compliant ? ConsoleColor.Green
                : c.State == PolicyState.NotConfigured ? ConsoleColor.Yellow : ConsoleColor.Red))
            {
                Console.WriteLine($"{mark} [{c.Id}] {c.Category}");
            }
            Console.WriteLine($"    {c.Description}");
            Console.WriteLine($"    注册表: HKLM\\{c.RegistryKey}\\{c.ValueName}  当前: {c.CurrentValue}  期望: {c.ExpectedValue}");
            Console.WriteLine($"    影响: {c.Impact}");
            if (c.RequiresReboot) Console.WriteLine("    变更后需重启");
            Console.WriteLine($"    参考: {c.Reference}");
            Console.WriteLine();
        }
        return 0;
    }

    private static int Apply(CommandLine cl, PolicyEngine engine, PolicyEngine.Profile profile,
        IReadOnlyCollection<string> exceptions, string outDir)
    {
        var dryRun = !cl.Flag("force");
        var backupDir = Path.Combine(outDir, "backups", DateTime.UtcNow.ToString("yyyyMMdd-HHmmss"));

        if (dryRun)
            Console.WriteLine("[dry-run] 未加 --force，仅展示将要执行的变更，不写注册表。\n");

        var (changes, warnings) = engine.Apply(profile, dryRun, exceptions, backupDir);
        if (changes.Count == 0)
        {
            Console.WriteLine("所有策略项已合规，无需变更。");
        }
        foreach (var c in changes)
        {
            Console.WriteLine($"- [{c.Id}] HKLM\\{c.RegistryKey}\\{c.ValueName}: {c.CurrentValue} -> {c.ExpectedValue}");
        }
        foreach (var w in warnings) Console.WriteLine($"[!] {w}");

        if (!dryRun)
        {
            Console.WriteLine($"\n变更前注册表备份目录: {backupDir}");
            Console.WriteLine("部分项需重启生效。建议先在试点 OU 验证文件服务器/NAS/打印访问无回退，再全域推广。");
        }
        return 0;
    }

    private static int ExportReg(PolicyEngine engine, PolicyEngine.Profile profile, string outDir)
    {
        var path = Path.Combine(outDir, $"trapsweeper-policy-{profile}.reg");
        File.WriteAllText(path, engine.ExportRegFile(profile), Encoding.Unicode);
        Console.WriteLine($"已导出 GPO/SCCM 可用的 .reg: {path}");
        return 0;
    }

    private static int ExportFirewall(CommandLine cl, string outDir)
    {
        var cidrs = cl.GetList("internal-cidrs");
        var path = Path.Combine(outDir, "firewall-outbound.ps1");
        File.WriteAllText(path, PolicyEngine.ExportFirewallScript(cidrs));
        Console.WriteLine($"已生成防火墙外发收敛脚本: {path}");
        Console.WriteLine("在终端以管理员运行；先放行内部网段再默认阻止 445/139/5355/5353 外发。");
        return 0;
    }

    private static PolicyEngine.Profile ParseProfile(string s) => s.ToLowerInvariant() switch
    {
        "audit" => PolicyEngine.Profile.Audit,
        "balanced" => PolicyEngine.Profile.Balanced,
        "strict" => PolicyEngine.Profile.Strict,
        _ => throw new ArgumentException($"未知档位: {s}（audit/balanced/strict）")
    };

    private sealed class ColorScope : IDisposable
    {
        private readonly ConsoleColor _old;
        public ColorScope(ConsoleColor color)
        {
            _old = Console.ForegroundColor;
            Console.ForegroundColor = color;
        }
        public void Dispose() => Console.ForegroundColor = _old;
    }
}
