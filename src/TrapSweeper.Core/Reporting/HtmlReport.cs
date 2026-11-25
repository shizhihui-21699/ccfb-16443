using System.Text;
using System.Text.Json;
using TrapSweeper.Core.Models;

namespace TrapSweeper.Core.Reporting;

/// <summary>
/// 单文件 HTML 报告：数据内联为 JSON，原生 JS 实现筛选/搜索，无外部依赖（隔离网络也能打开）。
/// 仅内联可操作的发现项，避免千万级扫描结果撑爆页面；全量数据始终在 JSONL 中。
/// </summary>
public static class HtmlReport
{
    public static void Write(string path, ScanReport report, int maxInline = 5000)
    {
        var actionable = report.Findings.Where(f => f.IsActionable)
            .OrderByDescending(f => f.Severity)
            .ThenByDescending(f => f.Score)
            .Take(maxInline)
            .ToList();

        var payload = new
        {
            toolVersion = report.ToolVersion,
            startedUtc = report.StartedUtc,
            finishedUtc = report.FinishedUtc,
            roots = report.Roots,
            counters = new
            {
                report.Counters.FilesEnumerated,
                report.Counters.DirectoriesVisited,
                report.Counters.CandidatesOpened,
                report.Counters.FindingsTotal,
                report.Counters.FindingsActionable,
                report.Counters.ParseErrors,
                report.Counters.AccessDenied,
                report.Counters.Quarantined,
                report.Counters.QuarantineFailures
            },
            truncated = report.Findings.Count(f => f.IsActionable) > maxInline,
            findings = actionable.Select(f => new
            {
                filePath = f.FilePath,
                kind = f.Kind.ToString(),
                verdict = f.Verdict.ToString(),
                severity = f.Severity.ToString(),
                score = f.Score,
                hidden = f.IsHiddenOrSystem,
                sha256 = f.Sha256,
                lastWrite = f.LastWriteTimeUtc,
                reasons = f.Reasons,
                hosts = f.HostVerdicts.Select(h => new
                {
                    host = h.Host,
                    verdict = h.Verdict.ToString(),
                    severity = h.Severity.ToString(),
                    signals = h.Signals,
                    allowedBy = h.MatchedAllowRules
                })
            })
        };

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = false });
        File.WriteAllText(path, BuildHtml(json), Encoding.UTF8);
    }

    private static string BuildHtml(string dataJson) => $$"""
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TrapSweeper 强制认证诱饵扫描报告</title>
<style>
:root { --bg:#f7f8fa; --fg:#1c2430; --muted:#5c6b80; --card:#fff; --line:#e3e8ef;
  --crit:#b42318; --high:#d92d20; --med:#dc6803; --low:#026aa2; --ok:#067647; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#12161c; --fg:#e6ebf2; --muted:#9aa8ba; --card:#1a2029; --line:#2a3340;
    --crit:#f97066; --high:#f04438; --med:#f79009; --low:#36bffa; --ok:#32d583; }
}
* { box-sizing: border-box; }
body { margin:0; font:14px/1.5 -apple-system,"Segoe UI",Roboto,"PingFang SC","Microsoft YaHei",sans-serif;
  background:var(--bg); color:var(--fg); padding:24px; }
h1 { font-size:20px; margin:0 0 4px; }
.muted { color:var(--muted); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:18px 0; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; }
.card .num { font-size:24px; font-weight:700; }
.card .lbl { color:var(--muted); font-size:12px; }
.bar { display:flex; gap:8px; flex-wrap:wrap; align-items:center; margin:12px 0; }
input,select,button { font:inherit; padding:7px 10px; border:1px solid var(--line); border-radius:8px;
  background:var(--card); color:var(--fg); }
input[type=search] { min-width:280px; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line);
  border-radius:10px; overflow:hidden; }
th,td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line); vertical-align:top;
  word-break:break-all; }
th { font-size:12px; color:var(--muted); cursor:pointer; user-select:none; }
tr:last-child td { border-bottom:none; }
.badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; }
.sev-Critical { background:color-mix(in srgb,var(--crit) 15%,transparent); color:var(--crit); }
.sev-High { background:color-mix(in srgb,var(--high) 15%,transparent); color:var(--high); }
.sev-Medium { background:color-mix(in srgb,var(--med) 15%,transparent); color:var(--med); }
.sev-Low { background:color-mix(in srgb,var(--low) 15%,transparent); color:var(--low); }
.verdict-External { color:var(--high); font-weight:700; }
.verdict-Suspicious { color:var(--med); font-weight:700; }
.verdict-Unresolvable { color:var(--low); font-weight:700; }
.host { border:1px solid var(--line); border-radius:8px; padding:8px 10px; margin:6px 0; }
.host .hname { font-weight:600; }
ul { margin:6px 0 0; padding-left:18px; }
.hidden-tag { font-size:11px; border:1px solid var(--line); border-radius:6px; padding:1px 6px; color:var(--muted); }
details summary { cursor:pointer; font-weight:600; }
</style>
</head>
<body>
<h1>TrapSweeper 强制认证诱饵扫描报告</h1>
<div class="muted" id="meta"></div>
<div class="cards" id="cards"></div>
<div class="bar">
  <input type="search" id="q" placeholder="搜索文件路径 / 主机 / 信号…">
  <select id="sev"><option value="">全部严重级别</option></select>
  <select id="verdict"><option value="">全部结论</option><option>External</option><option>Suspicious</option><option>Unresolvable</option></select>
  <span class="muted" id="shown"></span>
</div>
<table>
<thead><tr>
<th data-k="severity">级别</th><th data-k="filePath">文件</th><th>类型</th><th data-k="score">分</th><th>主机与信号</th>
</tr></thead>
<tbody id="rows"></tbody>
</table>
<script>
const DATA = __DATA_PLACEHOLDER__;
const sevRank = {Critical:4,High:3,Medium:2,Low:1,Info:0};
document.getElementById('meta').textContent =
  '根目录: ' + DATA.roots.join(' ; ') + ' ｜ 起 ' + new Date(DATA.startedUtc).toLocaleString() +
  ' ｜ 止 ' + new Date(DATA.finishedUtc).toLocaleString() + (DATA.truncated ? ' ｜ 报告仅内联前 5000 条，全量见 JSONL' : '');
const c = DATA.counters;
const cardDefs = [['枚举文件',c.filesEnumerated],['打开候选',c.candidatesOpened],['发现总数',c.findingsTotal],
  ['可操作项',c.findingsActionable],['已隔离',c.quarantined],['解析错误',c.parseErrors],['拒绝访问',c.accessDenied]];
document.getElementById('cards').innerHTML = cardDefs.map(([l,n]) =>
  `<div class="card"><div class="num">${n.toLocaleString()}</div><div class="lbl">${l}</div></div>`).join('');
const sevSel = document.getElementById('sev');
['Critical','High','Medium','Low'].forEach(s => {
  const o = document.createElement('option'); o.textContent = s; sevSel.appendChild(o);
});
let sortDesc = true;
function render() {
  const q = document.getElementById('q').value.toLowerCase();
  const sev = sevSel.value, verdict = document.getElementById('verdict').value;
  let rows = DATA.findings.filter(f =>
    (!sev || f.severity === sev) && (!verdict || f.verdict === verdict) &&
    (!q || JSON.stringify(f).toLowerCase().includes(q)));
  rows.sort((a,b) => sortDesc ? sevRank[b.severity]-sevRank[a.severity] : sevRank[a.severity]-sevRank[b.severity]);
  document.getElementById('shown').textContent = '显示 ' + rows.length + ' / ' + DATA.findings.length + ' 条';
  document.getElementById('rows').innerHTML = rows.map(f => `<tr>
    <td><span class="badge sev-${f.severity}">${f.severity}</span></td>
    <td><div>${escapeHtml(f.filePath)}</div>
      <div class="muted" style="font-size:12px;margin-top:4px">${f.kind}
      ${f.hidden ? '<span class="hidden-tag">隐藏/系统</span>' : ''}
      <span class="muted">${f.sha256.slice(0,16)}…</span></div></td>
    <td><span class="verdict-${f.verdict}">${f.verdict}</span></td>
    <td>${f.score}</td>
    <td>${f.hosts.map(h => `<div class="host"><div class="hname">${escapeHtml(h.host)}
        <span class="badge sev-${h.severity}">${h.verdict}</span></div>
        <ul>${h.signals.map(s => `<li>${escapeHtml(s)}</li>`).join('')}
        ${h.allowedBy.length ? `<li class="muted">允许规则: ${h.allowedBy.map(escapeHtml).join(', ')}</li>` : ''}</ul></div>`).join('')}
        ${f.reasons.length ? `<details><summary>文件级判定理由</summary><ul>${f.reasons.map(r=>`<li>${escapeHtml(r)}</li>`).join('')}</ul></details>` : ''}
    </td></tr>`).join('');
}
function escapeHtml(s){return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));}
document.getElementById('q').oninput = render; sevSel.onchange = render;
document.getElementById('verdict').onchange = render;
document.querySelectorAll('th[data-k]').forEach(th => th.onclick = () => { sortDesc = !sortDesc; render(); });
render();
</script>
</body>
</html>
""".Replace("__DATA_PLACEHOLDER__", JsonSerializer.Serialize(dataJson));
}
