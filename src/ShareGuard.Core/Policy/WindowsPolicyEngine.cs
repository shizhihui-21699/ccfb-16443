using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32;

namespace ShareGuard.Core.Policy;

/// <summary>
/// Windows 终端策略引擎:审计 / 应用 / 生成下发脚本三种模式。
///
/// 关键设计——为什么这些措施不会影响合法文件服务器:
///   * LLMNR/mDNS/NetBIOS 关闭后,内部主机名仍走 DNS 与 SMB 直连解析;
///   * NTLM 外发限制携带"远程服务器例外清单",内部文件服务器/DFS 根逐条豁免;
///   * SMB 防火墙规则用 RemoteAddress=Internet 阻断公网,内网网段显式 allow;
///   * 所有内部地址清单直接复用扫描白名单(AllowListConfig),保证两份名单同源。
///
/// 非 Windows 上只支持 GenerateArtifacts(产出给 Windows 管理员用的脚本)。
/// </summary>
public sealed class WindowsPolicyEngine
{
    private const string Msv10 = @"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0";
    private const string DnsClientPolicy = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
    private const string WebClientService = @"SYSTEM\CurrentControlSet\Services\WebClient";
    private const string LanmanWorkstation = @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters";
    private const string MrxSmb10 = @"SYSTEM\CurrentControlSet\Services\mrxsmb10";
    private const string NetBtInterfaces = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";

    public IReadOnlyList<PolicyFinding> Audit(EndpointPolicy policy)
    {
        var findings = new List<PolicyFinding>();
        if (!OperatingSystem.IsWindows())
        {
            findings.Add(new PolicyFinding
            {
                Setting = "Platform",
                Expected = "Windows",
                Actual = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                Detail = "非 Windows 主机无法读取注册表,请在目标终端运行 audit,或使用 gen-script 生成下发脚本。",
            });
            return findings;
        }

        if (policy.DisableLLMNR)
            findings.Add(AuditDword(DnsClientPolicy, "EnableMulticast", "0",
                "关闭 LLMNR,消除 UDP 5355 名称投毒面"));
        if (policy.DisableMDNS)
            findings.Add(AuditDword(DnsClientPolicy, "EnableMDNS", "0",
                "关闭 mDNS(UDP 5353)"));
        if (policy.DisableWebClientService)
            findings.Add(AuditDword(WebClientService, "Start", "4",
                "禁用 WebClient 服务,阻断 WebDAV 自动认证"));
        if (policy.RestrictOutboundNTLM)
        {
            findings.Add(AuditDword(Msv10, "RestrictSendingNTLMTraffic", "2",
                "拒绝所有发往远程服务器的 NTLM 认证(白名单主机经例外清单豁免)"));
            findings.Add(AuditMultiString(Msv10, "RemoteServerExceptionForExternalSDP",
                policy.NtlmRemoteExceptions,
                "NTLM 外发例外:内部文件服务器/DFS 根清单"));
        }
        if (policy.RequireSmbSigning)
            findings.Add(AuditDword(LanmanWorkstation, "RequireSecuritySignature", "1",
                "客户端强制 SMB 签名,抑制 NTLM 中继"));
        if (policy.DisableSmbV1)
            findings.Add(AuditDword(MrxSmb10, "Start", "4", "禁用 SMBv1 客户端驱动 mrxsmb10"));
        if (policy.DisableNetBios)
            findings.Add(AuditNetBios());

        return findings;
    }

    /// <summary>生成可经 GPO / Intune / SCCM 下发的 PowerShell 脚本(幂等,含回滚段注释)。</summary>
    public string BuildPowerShellScript(EndpointPolicy policy)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# ShareGuard 终端加固脚本(自动生成,请先在试点机验证)");
        sb.AppendLine("# 要求:管理员权限;适用 Windows 10/11、Server 2016+");
        sb.AppendLine("# 回滚:把对应值改回注释中标注的默认值,或删除所写策略键。");
        sb.AppendLine();
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine();

        if (policy.DisableLLMNR)
            AppendRegDword(sb, DnsClientPolicy, "EnableMulticast", 0, "默认未配置(LLMNR 开启)");
        if (policy.DisableMDNS)
            AppendRegDword(sb, DnsClientPolicy, "EnableMDNS", 0, "默认未配置(mDNS 开启)");
        if (policy.DisableWebClientService)
        {
            AppendRegDword(sb, WebClientService, "Start", 4, "默认 3(手动)");
            sb.AppendLine("Stop-Service WebClient -Force -ErrorAction SilentlyContinue");
        }
        if (policy.RestrictOutboundNTLM)
        {
            AppendRegDword(sb, Msv10, "RestrictSendingNTLMTraffic", 2, "默认 0(全部允许)");
            var exceptions = policy.NtlmRemoteExceptions.Count > 0
                ? string.Join("', '", policy.NtlmRemoteExceptions.Select(EscapePs))
                : string.Empty;
            sb.AppendLine($"New-ItemProperty -Path 'HKLM:\\{Msv10}' -Name 'RemoteServerExceptionForExternalSDP' " +
                $"-PropertyType MultiString -Value @('{exceptions}') -Force | Out-Null " +
                "# 回滚:删除该值");
        }
        if (policy.RequireSmbSigning)
            AppendRegDword(sb, LanmanWorkstation, "RequireSecuritySignature", 1, "默认 0");
        if (policy.DisableSmbV1)
        {
            AppendRegDword(sb, MrxSmb10, "Start", 4, "默认 3");
            sb.AppendLine("Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue");
        }
        if (policy.DisableNetBios)
        {
            sb.AppendLine("# 关闭所有网卡的 NetBIOS over TCP/IP(NetbiosOptions=2)");
            sb.AppendLine("Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters\\Interfaces' | ForEach-Object {");
            sb.AppendLine("  New-ItemProperty -Path $_.PsPath -Name 'NetbiosOptions' -PropertyType DWord -Value 2 -Force | Out-Null");
            sb.AppendLine("}  # 回滚:值改回 0(默认)");
        }

        if (policy.BlockInternetSmb)
        {
            sb.AppendLine();
            sb.AppendLine("# ---- 防火墙:仅阻断到公网的 SMB/NetBIOS,内网不受影响 ----");
            foreach (var cidr in policy.AllowedInternalCidrs)
            {
                sb.AppendLine($"New-NetFirewallRule -DisplayName 'ShareGuard allow SMB internal {cidr}' " +
                    $"-Direction Outbound -Action Allow -Protocol TCP -RemoteAddress {cidr} " +
                    $"-RemotePort 445,139 -Profile Any -ErrorAction SilentlyContinue | Out-Null");
            }
            sb.AppendLine("New-NetFirewallRule -DisplayName 'ShareGuard block SMB to Internet' " +
                "-Direction Outbound -Action Block -Protocol TCP -RemoteAddress Internet " +
                "-RemotePort 445,139 -Profile Any -ErrorAction SilentlyContinue | Out-Null");
            sb.AppendLine("New-NetFirewallRule -DisplayName 'ShareGuard block NetBIOS to Internet' " +
                "-Direction Outbound -Action Block -Protocol UDP -RemoteAddress Internet " +
                "-RemotePort 137,138 -Profile Any -ErrorAction SilentlyContinue | Out-Null");
            sb.AppendLine("# 回滚:Remove-NetFirewallRule -DisplayName 'ShareGuard*'");
        }

        if (policy.BlockInternetIconDownload)
        {
            sb.AppendLine();
            sb.AppendLine("# 图标外发没有独立注册表开关:浏览时的图标抓取走 SMB/WebDAV/HTTP,");
            sb.AppendLine("# 已由上面的 WebClient 禁用 + Internet 出站封堵覆盖;");
            sb.AppendLine("# 额外建议在出口防火墙拒绝内网终端到任意外部地址的 TCP 445。");
        }

        sb.AppendLine();
        sb.AppendLine("Write-Host 'ShareGuard 加固完成。建议重启或执行 gpupdate /force 后用 audit 复核。'");
        return sb.ToString();
    }

    /// <summary>本机直接应用(试点场景)。域内批量下发请用 <see cref="BuildPowerShellScript"/>。</summary>
    [SupportedOSPlatform("windows")]
    public IReadOnlyList<string> Apply(EndpointPolicy policy)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Apply 仅支持 Windows;请改用 gen-script 生成脚本后在目标机执行。");

        var actions = new List<string>();
        if (policy.DisableLLMNR) { WriteDword(DnsClientPolicy, "EnableMulticast", 0); actions.Add("LLMNR 已关闭"); }
        if (policy.DisableMDNS) { WriteDword(DnsClientPolicy, "EnableMDNS", 0); actions.Add("mDNS 已关闭"); }
        if (policy.DisableWebClientService)
        {
            WriteDword(WebClientService, "Start", 4);
            actions.Add("WebClient 服务已禁用(重启后完全生效)");
        }
        if (policy.RestrictOutboundNTLM)
        {
            WriteDword(Msv10, "RestrictSendingNTLMTraffic", 2);
            WriteMultiString(Msv10, "RemoteServerExceptionForExternalSDP", policy.NtlmRemoteExceptions);
            actions.Add($"出站 NTLM 已限制,豁免 {policy.NtlmRemoteExceptions.Count} 台内部服务器");
        }
        if (policy.RequireSmbSigning) { WriteDword(LanmanWorkstation, "RequireSecuritySignature", 1); actions.Add("SMB 签名已强制"); }
        if (policy.DisableSmbV1) { WriteDword(MrxSmb10, "Start", 4); actions.Add("SMBv1 已禁用"); }
        if (policy.DisableNetBios)
        {
            ApplyNetBiosDisable();
            actions.Add("全部网卡 NetBIOS over TCP/IP 已关闭");
        }
        if (policy.BlockInternetSmb)
            actions.Add("防火墙规则需通过 BuildPowerShellScript 生成的命令应用(本方法不直接改防火墙)");
        return actions;
    }

    // ---------------- 审计辅助 ----------------

    [SupportedOSPlatform("windows")]
    private static PolicyFinding AuditDword(string key, string name, string expected, string detail)
    {
        var actual = "缺失";
        try
        {
            using var rk = Registry.LocalMachine.OpenSubKey(key);
            if (rk?.GetValue(name) is int v) actual = v.ToString();
        }
        catch (UnauthorizedAccessException) { actual = "无权限读取"; }
        return new PolicyFinding { Setting = $@"HKLM\{key}\{name}", Expected = expected, Actual = actual, Detail = detail };
    }

    [SupportedOSPlatform("windows")]
    private static PolicyFinding AuditMultiString(string key, string name, IReadOnlyList<string> expected, string detail)
    {
        var actual = "缺失";
        try
        {
            using var rk = Registry.LocalMachine.OpenSubKey(key);
            if (rk?.GetValue(name) is string[] v) actual = string.Join(";", v);
        }
        catch (UnauthorizedAccessException) { actual = "无权限读取"; }

        var expectedJoined = string.Join(";", expected);
        var compliant = expected.Count == 0 || expected.All(e => actual.Contains(e, StringComparison.OrdinalIgnoreCase));
        return new PolicyFinding
        {
            Setting = $@"HKLM\{key}\{name}",
            Expected = expectedJoined,
            Actual = actual,
            Detail = detail + (compliant ? "" : "(例外清单不完整,策略生效后会误伤内部服务器访问)"),
        };
    }

    [SupportedOSPlatform("windows")]
    private static PolicyFinding AuditNetBios()
    {
        var ifaceCount = 0;
        var disabled = 0;
        try
        {
            using var root = Registry.LocalMachine.OpenSubKey(NetBtInterfaces);
            if (root != null)
            {
                foreach (var sub in root.GetSubKeyNames())
                {
                    using var rk = root.OpenSubKey(sub);
                    if (rk?.GetValue("NetbiosOptions") is int v)
                    {
                        ifaceCount++;
                        if (v == 2) disabled++;
                    }
                }
            }
        }
        catch (UnauthorizedAccessException) { /* 报告无权限 */ }

        return new PolicyFinding
        {
            Setting = $@"HKLM\{NetBtInterfaces}\*\NetbiosOptions",
            Expected = "全部网卡 = 2",
            Actual = ifaceCount == 0 ? "未读到网卡配置" : $"{disabled}/{ifaceCount} 块网卡已禁用",
            Detail = "关闭 NetBIOS over TCP/IP,阻断 NBT-NS 广播响应投毒",
        };
    }

    // ---------------- 写入辅助 ----------------

    [SupportedOSPlatform("windows")]
    private static void WriteDword(string key, string name, int value)
    {
        using var rk = Registry.LocalMachine.CreateSubKey(key, writable: true);
        rk.SetValue(name, value, RegistryValueKind.DWord);
    }

    [SupportedOSPlatform("windows")]
    private static void WriteMultiString(string key, string name, IReadOnlyList<string> values)
    {
        using var rk = Registry.LocalMachine.CreateSubKey(key, writable: true);
        rk.SetValue(name, values.ToArray(), RegistryValueKind.MultiString);
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyNetBiosDisable()
    {
        using var root = Registry.LocalMachine.OpenSubKey(NetBtInterfaces, writable: true);
        if (root == null) return;
        foreach (var sub in root.GetSubKeyNames())
        {
            using var rk = root.OpenSubKey(sub, writable: true);
            rk?.SetValue("NetbiosOptions", 2, RegistryValueKind.DWord);
        }
    }

    private static void AppendRegDword(StringBuilder sb, string key, string name, int value, string rollback)
    {
        sb.AppendLine($"New-ItemProperty -Path 'HKLM:\\{key}' -Name '{name}' -PropertyType DWord " +
            $"-Value {value} -Force | Out-Null  # 回滚:{rollback}");
    }

    private static string EscapePs(string value) => value.Replace("'", "''");
}
