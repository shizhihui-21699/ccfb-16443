# ShareGuard — 共享目录强制认证诱饵检测与终端防护工具

针对 **强制认证(forced authentication / coercion)诱饵文件** 的 C# / .NET 检测与处置工具。
攻击者把特制文件放进员工常去的共享目录,员工**仅仅浏览目录、无需点击**,Windows 就会自动
向攻击者服务器发起身份认证并泄露 NTLM 哈希,随后被离线破解或 NTLM 中继利用。

ShareGuard 在几千万文件规模的共享目录上找出指向外部/可疑地址的诱饵,并生成与之配套的
终端策略,在**不影响合法文件服务器访问**的前提下阻断自动认证外发。

---

## 1. 它检测什么

| 文件类型 | 扩展名 | 外发认证的触发点 |
|---|---|---|
| Windows 快捷方式 | `.lnk` | 网络目标(CommonNetworkRelativeLink)、`IconLocation`、字符串区 |
| Shell 命令文件 | `.scf` | `IconFile` UNC 路径,浏览即触发 |
| Internet 快捷方式 | `.url` `.website` | `URL=`、`IconFile` |
| 文件夹配置 | `desktop.ini` | `IconResource` / `IconFile` |
| 搜索连接器 | `.searchConnector-ms` | `simpleLocation/url`、`iconReference` |
| 库定义 | `.library-ms` | 库位置 URL、图标引用 |
| 联合搜索 | `.osdx` | OpenSearch `template` URL |

底层协议覆盖:UNC(SMB/WebDAV)、`file://`、`http(s)://`、`ldap(s)://`、`ftp(s)://`、
`dav(s)://`,支持 IPv6 字面量、`\\?\UNC\` 长路径、显式凭据 URL 与非标准端口识别。

## 2. 核心设计:为什么不会把正常文件误报成诱饵

共享目录里**大量正常文件**也引用内部服务器的图标和路径,因此工具绝不采用"见到 UNC 就报警"。
判定分两层,检测与判罚解耦:

1. **解析层只提取、不判善恶** —— 内部 UNC 和外部 UNC 一视同仁地提取出来。
2. **分级层靠白名单离线裁决**(不做 DNS 解析,千万级文件承受不起,也避免扫描本身产生外发流量):
   - 主机名匹配企业 DNS 后缀 / 显式主机清单 / 单标签名清单 → `AllowedInternal`(Benign)
   - IP 落在内部 CIDR → 放行;公网 IP / 陌生网段 → `UnknownIp`(Malicious)
   - 后缀不在白名单的域名 → `External`(Malicious)
   - **陌生单标签名只给 `Suspicious`,不直接判 Malicious** —— 它可能是新上线服务器,
     交人工复核,这是控制误伤的关键缓冲
   - 加重因子:内嵌显式凭据、非标准端口、`dav://` scheme、明文 HTTP

三级结论:`Benign` / `Suspicious`(人工复核)/ `Malicious`(可自动处置)。

## 3. 目录结构

```
src/ShareGuard.Core/
  Classification/  引用解析(UNC/URL)、CIDR 匹配、主机白名单分级
  Parsers/         LNK 二进制(MS-SHLLINK)、INI 类、XML 类解析器 + 双编码字符串扫描兜底
  Engine/          生产者-消费者扫描引擎、有界通道、断点续扫
  Remediation/     隔离/恢复(只移动不删除,manifest 可回滚)
  Policy/          Windows 终端加固:审计 / 应用 / 生成下发脚本
  Reporting/       JSONL(SIEM)与 CSV(运营复核)
  Configuration/   白名单加载与校验
src/ShareGuard.Cli/   命令行入口
tests/ShareGuard.Tests/  45 个单元/集成测试(含字节级 LNK 构造器)
samples/           攻击样本与正常对照样本、白名单模板
```

## 4. 快速开始

```bash
# 生成白名单模板,结合 AD 站点 / DFS 命名空间 / 资产台账填写
shareguard init-config allowlist.json

# 扫描共享目录(默认只报告,不动任何文件)
shareguard scan \\corp\dfs-share \\corp\finance --config allowlist.json \
  --jsonl findings.jsonl --csv findings.csv --checkpoint scan.cp.json

# 单文件详细分析(应急响应 / 调规则)
shareguard inspect suspicious.scf --config allowlist.json

# 确认无误后再隔离(只移动 Malicious,可一键恢复)
shareguard scan \\corp\dfs-share --config allowlist.json \
  --quarantine-root D:\shareguard-quarantine
shareguard restore D:\shareguard-quarantine

# 终端防护:先生成脚本在试点机验证,再经 GPO/Intune/SCCM 下发
shareguard policy gen-script --config allowlist.json --out hardening.ps1
shareguard policy audit --config allowlist.json
```

退出码:`0` 无高危 · `1` 发现高危或策略不合规 · `2` 参数错误 · `3` 平台不支持 · `130` 中断。

## 5. 千万级文件如何扛住

- **扩展名预过滤**:只有 7 类诱饵扩展名进入内容解析,其余只计数。实测 6 万文件中仅 28 个
  需要解析,6.8 万条目枚举 0.7 秒。
- **生产者-消费者 + 有界 Channel**:多根并行枚举,解析线程数可配,队列满时异步背压,
  内存占用与文件总量无关(不把清单全部加载进内存)。
- **全异步、无 sync-over-async**:枚举线程在队列满时 `await` 让出线程而非阻塞,
  避免线程池饥饿导致的静默停摆(有专门的小队列回归测试守护)。
- **断点续扫**:检查点按目录记录,中断后重跑跳过已完成目录。
- **容错**:单文件/单目录异常只计数不中断;文件以共享读方式打开,容忍其他人占用;
  超大文件只登记不解析;解析器全部带边界检查,畸形样本不会让进程崩溃。
- **LNK 双保险**:先按 MS-SHLLINK 结构化解析,再对整个二进制做 ASCII + UTF-16LE 双编码
  字符串扫描,畸形/被裁剪的 LNK 仍能捞出 UNC/URL。

## 6. 终端策略如何做到"封堵外发但不误伤合法文件服务器"

`policy gen-script` 产出的 PowerShell 与白名单**同源**——豁免清单直接取自 `allowlist.json`:

| 措施 | 防什么 | 为什么不影响合法访问 |
|---|---|---|
| 关 LLMNR / mDNS / NetBIOS over TCP/IP | 单标签名投毒(Responder/Inveigh) | 内部主机仍走 DNS 与 SMB 直连 |
| `RestrictSendingNTLMTraffic=2` + 远程例外清单 | 任意远程 NTLM 外发 | 内部文件服务器/DFS 根逐条在例外清单内 |
| 防火墙阻断到 **Internet** 的 445/139/137/138 | SMB 外连公网 | 规则按目的地址区分,内网 CIDR 显式 allow |
| 禁用 WebClient 服务 | WebDAV / `.url` 自动认证 | 普通 SMB 文件共享不依赖该服务(WebDAV 映射盘需先排查) |
| 强制 SMB 签名、禁 SMBv1 | NTLM 中继、横向移动 | 现代文件服务器均支持签名 |

每条策略在生成的脚本里都带**回滚注释**;`policy audit` 可随时核对终端合规状态。

## 7. 建议的运营流程

1. 先 `init-config` 并与 AD/DFS/资产台账对齐白名单(这是防误报的根本)。
2. 全量 `scan` 只出报告,人工过一遍 `Suspicious`,把确认合法的单标签名/网段补进白名单。
3. 重复扫描直到 Suspicious 收敛,再对 `Malicious` 启用隔离(隔离可恢复,不直接删除)。
4. 试点机验证 `hardening.ps1`,确认业务文件服务器访问无影响后域内下发。
5. 周期性增量扫描 + JSONL 接入 SIEM 持续监控。

## 8. 构建与测试

```bash
dotnet build
dotnet test
dotnet run --project src/ShareGuard.Cli -- scan <目录> --config allowlist.json
```

目标框架 .NET 11,跨平台编译运行;终端策略的 `apply`/`audit`(注册表读写)仅支持 Windows,
`gen-script` 可在任意平台生成给 Windows 终端用的脚本。
