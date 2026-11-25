namespace TrapSweeper.Core.Policy;

/// <summary>
/// 强制认证外发相关终端策略引擎。覆盖四条主要凭据外发路径：
/// NTLM 出站认证、名称解析投毒(LLMNR/mDNS/NBT-NS)、WebDAV 重定向器(WebClient)、SMB1/签名。
/// 关键设计：先审计后应用、每个键自动备份、阻断型策略支持例外服务器清单，
/// 避免误伤合法文件服务器/NAS/打印服务器上的 NTLM 依赖。
/// </summary>
public sealed class PolicyEngine
{
    private const string Ntlm = @"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
    private const string NtlmAudit = @"SYSTEM\CurrentControlSet\Control\Lsa";
    private const string Llmnr = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string Mdns = @"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters";
    private const string WebClient = @"SYSTEM\CurrentControlSet\Services\WebClient";
    private const string LanmanWorkstation = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    private const string Smb1Client = @"SYSTEM\CurrentControlSet\Services\mrxsmb10";

    /// <summary>基线档位：Audit（只审计不改阻断）、Balanced（推荐）、Strict（最大收敛）。</summary>
    public enum Profile { Audit, Balanced, Strict }

    private sealed record Spec(
        string Id, string Category, string Description, string Key, string Value,
        int Expected, int AuditValue, int StrictValue, string Impact, string Reference, bool Reboot = false);

    private static readonly Spec[] Specs =
    {
        new("NTLM-01", "NTLM 出站限制",
            "限制向远程服务器发送 NTLM 凭据：0=允许 1=审计 2=拒绝 3=拒绝域账号(允许本地账号) 5=仅拒绝域账号审计",
            Ntlm, "RestrictSendingNTLMTraffic", Expected: 2, AuditValue: 1, StrictValue: 2,
            "非域成员设备/NAS/老打印服务器可能依赖 NTLM；需配合 RestrictSendingNTLMTraffic 例外服务器清单",
            "MS-KB 4089810 / MSV1_0 策略", Reboot: true),

        new("NTLM-02", "NTLM 入站限制",
            "限制入站 NTLM 认证：0=允许 1=审计 2=拒绝（成员服务器/工作站基线，DC 另有专用策略）",
            Ntlm, "RestrictReceivingNTLMTraffic", Expected: 2, AuditValue: 1, StrictValue: 2,
            "接收 NTLM 的服务（部分文件共享/老应用）将被阻断，先跑审计模式确认",
            "MS-KB 4089810", Reboot: true),

        new("NTLM-03", "NTLM 域控制器限制",
            "限制 DC 上的 NTLM：0=允许 1=审计 2=拒绝（仅在本机是 DC 时适用）",
            NtlmAudit, "LdapEnforceChannelBinding", Expected: 2, AuditValue: 1, StrictValue: 2,
            "LDAP 通道绑定强度，阻断 EPA 缺失的中继；老 LDAP 客户端需升级",
            "AD 安全最佳实践 / CVE-2017-8563"),

        new("NAME-01", "名称解析投毒",
            "关闭多播名称解析 LLMNR（UDP 5355），消除同网段投毒应答入口",
            Llmnr, "EnableMulticast", Expected: 0, AuditValue: 0, StrictValue: 0,
            "仅依赖 DNS/NetBIOS 的名称解析；纯工作组环境需确认 DNS 覆盖完整",
            "MS-KB 3160263", Reboot: true),

        new("NAME-02", "名称解析投毒",
            "关闭 mDNS（UDP 5353），防止本地链路名称欺骗",
            Mdns, "EnableMDNS", Expected: 0, AuditValue: 0, StrictValue: 0,
            "依赖 mDNS 发现的本地设备（部分打印机/投屏）改为 DNS 或静态记录",
            "Windows DNS Cache 参数文档", Reboot: true),

        new("WEB-01", "WebDAV 重定向器",
            "禁用 WebClient 服务：阻断 http(s):// 形式的 WebDAV 自动认证与 .url/.search-ms 外连",
            WebClient, "Start", Expected: 4, AuditValue: 3, StrictValue: 4,
            "SharePoint/基于 WebDAV 的文档库访问将走浏览器而非资源管理器；4=禁用 3=手动",
            "WebClient 服务文档"),

        new("WEB-02", "WebDAV 明文凭据",
            "WebClient BasicAuthLevel=1：禁止向非 SSL 站点发送 Basic 凭据",
            WebClient + @"\Parameters", "BasicAuthLevel", Expected: 1, AuditValue: 1, StrictValue: 1,
            "仅影响明文 http 的 Basic 认证；https 不受影响",
            "WebClient BasicAuthLevel 文档"),

        new("SMB-01", "SMB 客户端签名",
            "RequireSecuritySignature=1：SMB 客户端要求签名，阻断 SMB 中继",
            LanmanWorkstation, "RequireSecuritySignature", Expected: 1, AuditValue: 1, StrictValue: 1,
            "不支持签名的极老 SMB 设备（SMB1 时代）将无法连接",
            "MS-KB 887429", Reboot: true),

        new("SMB-02", "SMB 中继面收敛",
            "RequireSecuritySignature 之外启用会话安全：EnableSecuritySignature=1",
            LanmanWorkstation, "EnableSecuritySignature", Expected: 1, AuditValue: 1, StrictValue: 1,
            "无明显兼容性影响，SMB2+ 默认协商",
            "MS-KB 887429"),

        new("SMB-03", "禁用 SMB1 客户端",
            "mrxsmb10 Start=4：禁用 SMB1 重定向器，SMB1 不支持签名且中继工具普遍依赖它",
            Smb1Client, "Start", Expected: 4, AuditValue: 4, StrictValue: 4,
            "仅 SMB1 的老 NAS/XP 共享将无法访问，应升级设备而非回退本项",
            "MS-KB 2696547", Reboot: true),
    };

    private readonly IRegistryStore _registry;

    public PolicyEngine(IRegistryStore registry) => _registry = registry;

    public PolicyBaselineResult Audit(Profile profile)
    {
        var result = new PolicyBaselineResult { IsWindows = OperatingSystem.IsWindows() };
        foreach (var spec in Specs)
        {
            var check = new PolicyCheck
            {
                Id = spec.Id, Category = spec.Category, Description = spec.Description,
                RegistryKey = spec.Key, ValueName = spec.Value,
                ExpectedValue = TargetFor(spec, profile).ToString(),
                Impact = spec.Impact, Reference = spec.Reference, RequiresReboot = spec.Reboot
            };

            var raw = _registry.GetValue(spec.Key, spec.Value);
            if (raw == null)
            {
                check.State = PolicyState.NotConfigured;
                check.CurrentValue = "(未配置)";
            }
            else if (raw is int dword)
            {
                check.CurrentValue = dword.ToString();
                check.State = dword == TargetFor(spec, profile) ? PolicyState.Compliant : PolicyState.NonCompliant;
            }
            else
            {
                check.CurrentValue = raw.ToString();
                check.State = PolicyState.NonCompliant;
            }
            result.Checks.Add(check);
        }
        return result;
    }

    /// <summary>
    /// 应用基线。dryRun=true 时只返回将要执行的变更。每个键先备份再写入。
    /// NTLM-01 在阻断值下自动写入例外服务器清单（Audit 模式不动例外）。
    /// </summary>
    public (List<PolicyCheck> Changes, List<string> Warnings) Apply(
        Profile profile, bool dryRun, IReadOnlyCollection<string>? ntlmExceptionServers, string backupDir)
    {
        var changes = new List<PolicyCheck>();
        var warnings = new List<string>();
        var audit = Audit(profile);

        foreach (var check in audit.Checks)
        {
            if (check.State == PolicyState.Compliant) continue;
            changes.Add(check);
            if (dryRun) continue;

            var spec = Specs.First(s => s.Id == check.Id);
            var target = TargetFor(spec, profile);
            try
            {
                Directory.CreateDirectory(backupDir);
                _registry.BackupKey(spec.Key, Path.Combine(backupDir, $"{spec.Id}_{SafeName(spec.Key)}.reg"));
                _registry.SetDword(spec.Key, spec.Value, target);
                check.State = PolicyState.Compliant;
                check.CurrentValue = target.ToString();
            }
            catch (Exception ex)
            {
                warnings.Add($"写入失败 {check.Id} ({spec.Key}\\{spec.Value}): {ex.Message}");
            }
        }

        // NTLM 例外清单：仅 Balanced/Strict 阻断时配置，保证合法文件服务器不受影响
        if (profile != Profile.Audit && ntlmExceptionServers is { Count: > 0 })
        {
            if (!dryRun)
            {
                try
                {
                    _registry.SetMultiString(Ntlm, "RestrictSendingNTLMTraffic_Servers", ntlmExceptionServers);
                    warnings.Add($"已配置 NTLM 出站例外服务器 {ntlmExceptionServers.Count} 台（策略客户端需支持该例外名，详见 README 部署章节）");
                }
                catch (Exception ex)
                {
                    warnings.Add($"NTLM 例外清单写入失败: {ex.Message}");
                }
            }
            else
            {
                warnings.Add($"[dry-run] 将写入 NTLM 出站例外服务器: {string.Join(", ", ntlmExceptionServers)}");
            }
        }

        if (!OperatingSystem.IsWindows())
            warnings.Add("当前为非 Windows 平台：仅能使用内存注册表做干跑，真实变更必须在 Windows 终端/文件服务器上执行");

        return (changes, warnings);
    }

    /// <summary>导出 .reg 文件供 GPO/SCCM/Intune 大规模下发。</summary>
    public string ExportRegFile(Profile profile)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Windows Registry Editor Version 5.00");
        var byKey = Specs.GroupBy(s => s.Key);
        foreach (var group in byKey)
        {
            sb.AppendLine();
            sb.AppendLine($"[HKEY_LOCAL_MACHINE\\{group.Key}]");
            foreach (var spec in group)
            {
                var target = TargetFor(spec, profile);
                sb.AppendLine($"\"{spec.Value}\"=dword:{target:X8}");
            }
        }
        return sb.ToString();
    }

    /// <summary>生成防火墙外发规则脚本：默认拒绝到公网的 445/139/5355/5353，放行内网网段。</summary>
    public static string ExportFirewallScript(IReadOnlyList<string> internalCidrs)
    {
        var cidrs = internalCidrs.Count == 0
            ? new List<string> { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" }
            : internalCidrs.ToList();

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("# TrapSweeper 外发认证面收敛防火墙脚本（在域成员/终端上以管理员运行 PowerShell）");
        sb.AppendLine("# 策略：先放行全部内部网段，再默认阻止外发 SMB/LLMNR/mDNS，不影响内部文件服务器访问");
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("$internal = @(");
        foreach (var c in cidrs) sb.AppendLine($"    '{c}',");
        sb.AppendLine(")");
        sb.AppendLine("""
$ports = @(
    @{ Name = 'SMB-TCP';  Port = 445;  Proto = 'TCP' },
    @{ Name = 'NBT-SSN';  Port = 139;  Proto = 'TCP' },
    @{ Name = 'LLMNR';    Port = 5355; Proto = 'UDP' },
    @{ Name = 'mDNS';     Port = 5353; Proto = 'UDP' }
)
foreach ($p in $ports) {
    $allow = "TrapSweeper-Allow-$($p.Name)-Internal"
    $block = "TrapSweeper-Block-$($p.Name)-Internet"
    netsh advfirewall firewall delete rule name="$allow" | Out-Null
    netsh advfirewall firewall delete rule name="$block" | Out-Null
    foreach ($net in $internal) {
        netsh advfirewall firewall add rule name="$allow" dir=out action=allow `
            protocol="$($p.Proto)" remoteport="$($p.Port)" remoteip="$net" | Out-Null
    }
    netsh advfirewall firewall add rule name="$block" dir=out action=block `
        protocol="$($p.Proto)" remoteport="$($p.Port)" | Out-Null
}
Write-Host '防火墙外发规则已下发：内部网段放行，其余目标默认阻止'
""");
        return sb.ToString();
    }

    private static int TargetFor(Spec spec, Profile profile) => profile switch
    {
        Profile.Audit => spec.AuditValue,
        Profile.Strict => spec.StrictValue,
        _ => spec.Expected
    };

    private static string SafeName(string key) => key.Replace('\\', '_').Replace('/', '_');
}
