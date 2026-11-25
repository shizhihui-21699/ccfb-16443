namespace ShareGuard.Core.Policy;

/// <summary>
/// 终端加固策略项。设计遵循两条铁律:
///   1. 只堵"自动发起的名称解析与认证外发",不堵到合法文件服务器的正常会话;
///   2. 每条策略都给出回滚方法,默认 Audit 模式只检查不修改。
/// </summary>
public sealed class EndpointPolicy
{
    /// <summary>关闭 LLMNR(UDP 5355)。组策略位置:
    /// Computer Configuration\Administrative Templates\Network\DNS Client\
    /// "Turn OFF Multicast Name Resolution" = Enabled</summary>
    public bool DisableLLMNR { get; set; } = true;

    /// <summary>关闭 mDNS(UDP 5353),Win10 1809+ 支持。</summary>
    public bool DisableMDNS { get; set; } = true;

    /// <summary>关闭 NetBIOS over TCP/IP(UDP 137/138,TCP 139),
    /// 消除 NBT-NS 投毒(Responder/Inveigh 的核心通道)。</summary>
    public bool DisableNetBios { get; set; } = true;

    /// <summary>禁用 WebClient 服务:阻断经 HTTP/WebDAV 的自动认证与 .url 外连。
    /// 注意:依赖 WebDAV 映射驱动器的业务需先排查,可改为仅加防火墙规则。</summary>
    public bool DisableWebClientService { get; set; } = true;

    /// <summary>限制发往远程服务器的 NTLM:
    /// LSA\MSV1-02\RestrictSendingNTLMTraffic = 2(全部拒绝),
    /// 配合 RemoteServerExceptionForExternalSDP 放行白名单主机。</summary>
    public bool RestrictOutboundNTLM { get; set; } = true;

    /// <summary>防火墙阻断到公网的 SMB(445/139)出站,内网网段放行。
    /// 这是"不影响合法文件服务器"的关键:规则按目的地址区分内外网。</summary>
    public bool BlockInternetSmb { get; set; } = true;

    /// <summary>阻止从 Internet 下载图标(可选,Explorer 策略)。</summary>
    public bool BlockInternetIconDownload { get; set; } = true;

    /// <summary>启用 SMB 签名(客户端侧),防御中继。</summary>
    public bool RequireSmbSigning { get; set; } = true;

    /// <summary>禁用 SMBv1。</summary>
    public bool DisableSmbV1 { get; set; } = true;

    /// <summary>NTLM 外发豁免主机(= 扫描用白名单中的内部服务器),逐条由资产清单生成。</summary>
    public List<string> NtlmRemoteExceptions { get; set; } = new();

    /// <summary>SMB 出站放行的内网 CIDR(= 白名单内网网段)。</summary>
    public List<string> AllowedInternalCidrs { get; set; } = new();
}

public enum PolicyMode
{
    /// <summary>只读取当前配置并对比期望值,输出差异,不做任何修改。</summary>
    Audit,

    /// <summary>生成 PowerShell 脚本/注册表文件,由管理员通过 GPO/MDM 下发。</summary>
    GenerateArtifacts,

    /// <summary>在本机直接应用(需要管理员权限,主要用于试点机)。</summary>
    Apply,
}

public sealed class PolicyFinding
{
    public required string Setting { get; init; }
    public required string Expected { get; init; }
    public required string Actual { get; init; }
    public bool Compliant => Expected.Equals(Actual, StringComparison.OrdinalIgnoreCase);
    public required string Detail { get; init; }
}
