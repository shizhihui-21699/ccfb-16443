# TrapSweeper — 共享目录强制认证诱饵检测与终端外发认证收敛工具

## 威胁背景

攻击者在员工常访问的 SMB 共享目录中投放特制的**强制认证（forced authentication）诱饵文件**：

| 载体 | 触发方式 | 外连字段 |
|---|---|---|
| `.lnk` 快捷方式 | 浏览目录即解析图标/目标 | `IconLocation`、CommonNetworkRelativeLink |
| `desktop.ini` | 进入目录即加载文件夹图标 | `IconResource` / `IconFile` |
| `.scf` Explorer 命令 | 浏览目录即加载图标 | `IconFile` |
| `.url` Internet 快捷方式 | 浏览或单击 | `URL`、`IconFile` |
| `.search-ms` / `.searchconnector-ms` / `.library-ms` | 浏览或单击，Search Connector 自动连接 | `<url>`、`<iconReference>` |

员工仅在资源管理器中**打开目录浏览**，客户端就会向攻击者控制的主机发起 SMB/WebDAV 认证，
发送 NTLMv2 散列。攻击者离线破解口令，或通过 NTLM 中继横向移动。

本工具从两个层面防御：

1. **扫描面**：在数千万文件的共享中找出指向外部/可疑地址的诱饵，支持审计与可逆隔离；
2. **策略面**：收敛终端的自动认证外发面（出站 NTLM、LLMNR/mDNS、WebClient、SMB1/签名、外发防火墙），
   即使漏过一个诱饵，凭据也无法离开内网。

## 核心设计：如何控制误报（本任务的核心难点）

正常的 `.lnk` / `desktop.ini` 中**大量**引用内部文件服务器的图标和路径，"含 UNC 就报警"会产生海量误报。
TrapSweeper 不做二元判断，而是对每个主机引用走**证据链分类**：

1. **信号收集**——公网 IP、公共后缀域名、混淆 IP（十进制整数/八进制/十六进制，如 `\\167772161\s`）、
   URI 内嵌凭证、非标准端口、明文 http、尾随点、Punycode、百分号编码等；
2. **允许列表解释**——DNS 后缀（子域自动命中）、精确主机/DFS 根、主机名正则、IPv4/IPv6 CIDR（含 v4-mapped v6）、
   单标签短名策略（`Allow` / `RequireAllow` / `Deny`）、可信端口、WebDAV 网关；
3. **结论分级**——能被规则解释且无强规避信号 → `Allowed`（静默）；命中允许列表但带混淆 IP/内嵌凭证等
   强信号 → 降级 `Suspicious` 强制人工复核；无法解释的外部地址 → `External`；可选 DNS 校验 → `Unresolvable`。

每条结论都保留 `Signals`（为什么报）和 `MatchedAllowRules`（为什么放），报告中可逐条追溯。

**部署流程用 `learn` 先盘点后定规则**：先扫描全部共享，输出被引用主机的频次/角色/方案 CSV，
管理员据此编制允许列表，再跑正式 `scan`，避免上线即误报洪流。

## 千万级文件的工程设计

- **扩展名预过滤**：枚举阶段只对 8 类追踪扩展名建立工作项，普通业务文件不打开（压测 50 万文件仅打开 10 个候选）；
- **单生产者 + 有界通道 + 多消费者**：枚举单线程（避免加剧磁盘寻道），解析/判定在线程池中并行，
  通道容量有界，内存占用不随文件总量增长（50 万文件峰值约 180 MB）；
- **断点续扫**：按相对根的目录深度记录已完整枚举的子树，重扫整棵跳过，中断（Ctrl+C）后可 `--resume`；
- **容错**：拒绝访问、IO 错误、结构损坏全部计数并继续；解析失败的文件走原始字节 UTF-16/ANSI 双通字符串扫荡兜底，绝不静默漏报；
- **伪装识别**：`--sniff` 按 ShellLink CLSID 头识别改后缀的 lnk；诱饵常带隐藏/系统属性，枚举不跳过这些属性；
- **零第三方运行时依赖**：解析器全部手写，可在隔离网内离线运行。

## 命令

```bash
# 1) 盘点环境中所有被引用主机，辅助编制允许列表（不产生判定、不动文件）
trapsweeper learn --roots \\fs01\share,\\fs02\share --config config/allowlist.json

# 2) 审计扫描（默认 dry-run，只出报告，不改任何文件）
trapsweeper scan --roots \\fs01\share --config config/allowlist.json

# 3) 单文件深度取证（输出全部引用与判定证据，退出码 2=可操作）
trapsweeper inspect X:\dir\suspect.lnk --config config/allowlist.json

# 4) 试点隔离（必须显式 --apply；隔离区带 JSONL 清单，可整体回滚）
trapsweeper scan --roots \\fs01\share --config config/allowlist.json \
    --apply --quarantine-dir D:\trap-quarantine

# 5) 隔离区管理与恢复
trapsweeper quarantine list --quarantine-dir D:\trap-quarantine
trapsweeper quarantine restore --all --quarantine-dir D:\trap-quarantine
```

### 终端策略（先审计、后试点、再全域）

```bash
# 审计当前终端的 10 项基线（不合规/未配置分别统计，不改动系统）
trapsweeper policy audit --profile balanced

# dry-run 预览将要写入的注册表变更（默认不写），并声明 NTLM 例外文件服务器
trapsweeper policy apply --profile balanced \
    --ntlm-exceptions nas01.corp.local,print01.corp.local

# 确认无误后加 --force 真正写入（每个键自动备份 .reg）
trapsweeper policy apply --profile balanced --ntlm-exceptions nas01.corp.local --force

# 大规模下发：导出 GPO/SCCM/Intune 可用的 .reg
trapsweeper policy export-reg --profile balanced

# 外发防火墙：先放行全部内部网段，再默认阻止 445/139/5355/5353 外发
trapsweeper policy export-firewall --internal-cidrs 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

### 三档策略基线

| 档位 | NTLM 出站 | LLMNR/mDNS | WebClient | 适用阶段 |
|---|---|---|---|---|
| `audit` | 审计(1)，仅记录不阻断 | 关闭 | 手动(3) | 上线观察，盘点 NTLM 依赖 |
| `balanced`（默认） | 拒绝(2)+例外清单 | 关闭 | 禁用(4) | 试点→全域推广 |
| `strict` | 拒绝(2) | 关闭 | 禁用(4) | 高安全要求环境 |

**保证合法文件服务器不受影响的三道闸**：
1. `audit` 档位先跑一段时间，从事件日志确认哪些 NAS/打印/老应用依赖 NTLM；
2. `balanced` 阻断时通过 `--ntlm-exceptions` 声明例外服务器；
3. 防火墙脚本对内部 CIDR 显式 `allow` 后再对其余目标 `block`，内部 SMB 流量不受影响。

## 允许列表配置（`config/allowlist.json`）

```json
{
  "AllowedSuffixes": [ "corp.local", "branch.corp.local" ],
  "AllowedHosts": [ "fileserver", "nas01" ],
  "AllowedHostRegex": [ "^fs-\\d+\\.corp\\.local$" ],
  "AllowedCidrs": [ "10.0.0.0/8", "172.16.0.0/12", "fc00::/7" ],
  "AllowedDfsRoots": [ "dc01.corp.local" ],
  "SingleLabelPolicy": "RequireAllow",
  "TrustedPorts": [ 80, 139, 443, 445, 5985, 5986 ],
  "AllowCleartextHttp": false,
  "EnableDnsCheck": false,
  "InternalPublicSuffixes": [ "acme-holdings.io" ],
  "WebDavGateways": [ "dav.corp.local" ]
}
```

字段非法（错误 CIDR、编译失败的正则、非法档位）在加载时即报错，不会静默跳过。

## 输出物

- `findings-<时间戳>.jsonl`：全量发现，流式落盘，每行一个含完整证据链的 Finding；
- `host-inventory-<时间戳>.csv`：主机盘点（文件数/引用数/角色/方案/可疑信号/样本路径）；
- `report-<时间戳>.html`：自包含单文件报告（内联数据、原生 JS 筛选搜索、暗色模式、无外部依赖），隔离网可直接打开；
- `quarantine/quarantine-manifest.jsonl`：每条隔离记录含原路径、SHA256、判定理由、NTFS 安全描述符（SDDL），恢复时校验并还原 ACL；
- `checkpoint.json`：断点续扫状态。

## 隔离安全性

- 先**复制 + SHA256 双向校验**，通过后才删除源文件，杜绝移动中断导致文件丢失；
- 隔离区镜像源路径并以记录 ID 重命名，保留扩展名便于人工核对；
- Windows 上捕获所有者与 DACL（SDDL），恢复时原位还原；
- `restore` 校验隔离文件仍存在、目标路径未被占用，否则拒绝恢复并计数，不做破坏性覆盖。

## 构建与测试

```bash
dotnet build
dotnet test     # 57 个测试：解析器/IP 与 CIDR/分类引擎/端到端扫描/隔离回滚/策略引擎
```

测试中的 `.lnk` 夹具按 [MS-SHLLINK] 最小子集手工构造（不依赖 Windows Shell），
覆盖 ANSI/Unicode StringData、CommonNetworkRelativeLink、截断文件兜底、CLSID 破坏等场景。

发布到 Windows 终端（在 Windows 构建机或交叉发布）：

```bash
dotnet publish src/TrapSweeper.Cli -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
```

## 覆盖的文件格式与检测点

| 格式 | 解析方式 | 检测字段 |
|---|---|---|
| `.lnk` | MS-SHLLINK 二进制手写解析 + 字节扫荡兜底 | NetworkNetName/DeviceName、LocalBasePath、CommonPathSuffix、IconLocation、Arguments、WorkingDirectory、RelativePath、Environment/Tracker/Darwin/IconPath ExtraData |
| `desktop.ini` | INI 解析（BOM 嗅探 UTF-16/UTF-8/ANSI） | IconResource/IconFile/IconLocation、CLSID |
| `.url` | INI 解析 | URL、IconFile、WorkingDirectory |
| `.scf` | INI 解析 | IconFile、Command |
| `.search-ms` / `.searchconnector-ms` / `.library-ms` / `.settingcontent-ms` | XML（DTD 禁用防 XXE，命名空间无关） | url、iconReference、propertyStore、simpleLocation |

## 局限与后续方向

- 当前为内容静态分析，不做实时网络行为捕获；建议与终端 EDR 的 SMB 外连告警互补；
- 公共后缀判断为轻量实现（内置私有 TLD 表 + 常见多级后缀），未内置完整 PSL；未命中允许列表的域名本就需要人工确认；
- `EnableDnsCheck` 会发起真实 DNS 查询，离线扫描或不希望产生探测流量时保持关闭；
- 注册表策略的 NTLM 例外项名称在不同 Windows 版本的组策略 UI 中位置不同，README 部署章节建议优先用 GPO 的"网络安全: 限制 NTLM: 传入/传出 NTLM 流量"及其服务器例外配置。
