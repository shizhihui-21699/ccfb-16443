using ShareGuard.Core.Classification;
using ShareGuard.Core.Configuration;
using ShareGuard.Core.Policy;

namespace ShareGuard.Cli.Commands;

/// <summary>
/// policy:终端自动认证外发防护。
///   policy audit                    检查本机当前合规状态
///   policy gen-script --out ps1     生成可经 GPO/MDM 下发的加固脚本
///   policy apply                    本机直接应用(需管理员,试点用)
/// 内部服务器豁免清单与 SMB 放行网段均来自扫描白名单,保证"封堵外发"与"合法访问"同源。
/// </summary>
public static class PolicyCommand
{
    public static async Task<int> RunAsync(CliArgs args, CancellationToken ct)
    {
        var mode = args.RemainingPositionals.FirstOrDefault();
        if (mode is not ("audit" or "gen-script" or "apply"))
        {
            Console.Error.WriteLine("用法: shareguard policy <audit|gen-script|apply> --config allowlist.json [--out hardening.ps1]");
            return 2;
        }

        var configPath = args.Get("config");
        var config = configPath != null
            ? await ConfigLoader.LoadAsync(configPath, ct)
            : AllowListConfig.Default;

        var policy = new EndpointPolicy
        {
            NtlmRemoteExceptions = config.AllowedHosts,
            AllowedInternalCidrs = config.AllowedCidrs,
        };
        var engine = new WindowsPolicyEngine();

        switch (mode)
        {
            case "audit":
                var findings = engine.Audit(policy);
                var nonCompliant = 0;
                foreach (var f in findings)
                {
                    if (!f.Compliant) nonCompliant++;
                    Console.WriteLine($"[{(f.Compliant ? "合规" : "不合规")}] {f.Setting}");
                    Console.WriteLine($"    期望: {f.Expected}");
                    Console.WriteLine($"    实际: {f.Actual}");
                    Console.WriteLine($"    说明: {f.Detail}");
                }
                Console.WriteLine();
                Console.WriteLine($"合计 {findings.Count} 项,不合规 {nonCompliant} 项。");
                return nonCompliant == 0 ? 0 : 1;

            case "gen-script":
                var script = engine.BuildPowerShellScript(policy);
                var outPath = args.GetOrDefault("out", "shareguard-hardening.ps1");
                await File.WriteAllTextAsync(outPath, script, ct);
                Console.WriteLine($"已生成加固脚本: {outPath}");
                Console.WriteLine("请先在试点机验证,再通过 GPO / Intune / SCCM 大规模下发。");
                return 0;

            case "apply":
                if (!OperatingSystem.IsWindows())
                {
                    Console.Error.WriteLine("apply 仅支持 Windows;当前平台请改用 gen-script 生成脚本后在 Windows 终端执行。");
                    return 3;
                }
                try
                {
                    var actions = engine.Apply(policy);
                    foreach (var a in actions) Console.WriteLine($"[已应用] {a}");
                    Console.WriteLine("防火墙规则请使用 gen-script 输出的 New-NetFirewallRule 命令单独应用。");
                    return 0;
                }
                catch (PlatformNotSupportedException ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    return 3;
                }

            default:
                return 2;
        }
    }
}
