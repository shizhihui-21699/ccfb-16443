# 样本文件说明

`malicious/` 与 `benign/` 下为纯文本/XML 诱饵样本，可直接打开查看结构差异：

- `malicious/browse-trigger.scf` — 浏览目录即触发的图标外连（\\evil.attacker.test）
- `malicious/vacation.searchconnector-ms` — 搜索连接器，url 与 iconReference 双外连
- `malicious/phishing.url` — WebDAV URL + UNC 图标
- `malicious/desktop.ini` — 文件夹图标指向公网 IP
- `benign/desktop.ini`、`benign/intranet.url` — 合法内部引用，扫描应判 Allowed 零误报

`.lnk` 为二进制格式，测试夹具 `tests/TrapSweeper.Tests/LnkFixtureBuilder.cs`
按 [MS-SHLLINK] 最小子集在内存中构造，不提交二进制样本。
用 CLI 对本目录验证（恶意应报 External/Suspicious，良性应静默）：

    trapsweeper scan samples --config config/allowlist.example.json
