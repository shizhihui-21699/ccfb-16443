namespace ShareGuard.Core.Models;

/// <summary>
/// 可承载强制认证诱饵的文件类型。
/// </summary>
public enum BaitFileType
{
    /// <summary>Windows 快捷方式 (.lnk),二进制 Shell Link 格式。</summary>
    Lnk,

    /// <summary>资源管理器命令文件 (.scf),纯文本 ini 结构。</summary>
    Scf,

    /// <summary>Internet 快捷方式 (.url),纯文本 ini 结构。</summary>
    Url,

    /// <summary>文件夹外观配置 (desktop.ini),纯文本 ini 结构。</summary>
    DesktopIni,

    /// <summary>搜索连接器 (.searchConnector-ms),纯文本 XML。</summary>
    SearchConnector,

    /// <summary>库定义 (.library-ms),纯文本 XML。</summary>
    Library,

    /// <summary>联合搜索描述 (.osdx / searchconnector),纯文本 OpenSearch XML。</summary>
    OpenSearchDescription,
}

/// <summary>
/// 一条文件内嵌的外部引用(图标路径、目标路径、搜索提供程序等)。
/// </summary>
public sealed class EmbeddedReference
{
    /// <summary>引用原文,例如 <c>\\evil.example\share\icon.ico</c>。</summary>
    public required string Raw { get; init; }

    /// <summary>引用在文件中的来源字段,例如 IconLocation / Target / URL。</summary>
    public required string SourceField { get; init; }

    /// <summary>引用使用的协议 / 路径类型。</summary>
    public ReferenceScheme Scheme { get; init; }

    /// <summary>解析出的主机名(UNC 服务器名或 URL 主机),无法解析时为 null。</summary>
    public string? Host { get; init; }

    /// <summary>URL 显式端口;UNC 与默认端口为 null。</summary>
    public int? Port { get; init; }

    /// <summary>引用是否使用了显式凭据(user@host / scheme://user:pass@host)。</summary>
    public bool HasExplicitCredentials { get; init; }

    /// <summary>文件内字节偏移(便于审计定位),未知为 null。</summary>
    public long? Offset { get; init; }

    /// <summary>文本编码(ASCII / UTF16LE),仅用于审计展示。</summary>
    public string? Encoding { get; init; }
}

public enum ReferenceScheme
{
    /// <summary>UNC 路径 \\server\share 或 \\?\UNC\server\share。</summary>
    Unc,

    /// <summary>file:// URL。</summary>
    FileUrl,

    /// <summary>http / https。</summary>
    Http,

    /// <summary>ldap / ldaps。</summary>
    Ldap,

    /// <summary>ftp / ftps。</summary>
    Ftp,

    /// <summary>dav / davs(WebDAV 专用 scheme,会走 WebClient 服务)。</summary>
    WebDav,

    /// <summary>本地路径 / 环境变量路径 / 无主机引用。</summary>
    Local,

    /// <summary>其他带主机的协议(gopher、netbios 等)。</summary>
    Other,
}
