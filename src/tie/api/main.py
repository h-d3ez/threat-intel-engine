from contextlib import asynccontextmanager
from datetime import datetime, timezone
import hmac
import html
import json
import os

import asyncpg
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
import redis.asyncio as redis

from tie.config import settings
from tie.intel.enrichment import ThreatIntelService
from tie.parsers.log_parsers import parse_log_line
from tie.rules.engine import DetectionEngine
from tie.schemas import LogSource
from tie.worker.pipeline import AlertPipeline

STREAM_NAME = "tie:events"


def _is_serverless() -> bool:
    return os.getenv("VERCEL") == "1" or os.getenv("SERVERLESS_INLINE", "").lower() == "true"


class IngestRequest(BaseModel):
    source: LogSource
    lines: list[str] = Field(..., min_length=1)


class IngestResponse(BaseModel):
    accepted: int
    rejected: int
    stream: str


def verify_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.ingest_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    effective_redis_url = (os.getenv("REDIS_URL") or settings.redis_url).strip()
    effective_db_url = (os.getenv("DATABASE_URL") or settings.database_url).strip()

    redis_client = redis.from_url(effective_redis_url, decode_responses=True)
    app.state.redis = redis_client

    try:
        db_pool = await asyncpg.create_pool(effective_db_url, min_size=1, max_size=5)
    except Exception as exc:
        print(f"DB pool error: {exc}", flush=True)
        db_pool = None
    app.state.db = db_pool

    if db_pool is not None:
        intel_service = ThreatIntelService(
            redis_client=redis_client,
            mode=os.getenv("INTEL_MODE") or settings.intel_mode,
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or settings.abuseipdb_api_key,
            cache_ttl_seconds=settings.intel_cache_ttl_seconds,
        )
        rule_engine = DetectionEngine(
            redis_client=redis_client,
            brute_force_threshold=settings.brute_force_threshold,
            brute_force_window_s=settings.brute_force_window_seconds,
            spray_distinct_users=settings.spray_distinct_users,
            spray_window_s=settings.spray_window_seconds,
            impossible_travel_max_kmh=settings.impossible_travel_max_kmh,
        )
        app.state.pipeline = AlertPipeline(db_pool, redis_client, intel_service, rule_engine)
    else:
        app.state.pipeline = None

    try:
        yield
    finally:
        if app.state.db is not None:
            await app.state.db.close()
        await redis_client.aclose()


app = FastAPI(title="Threat Intel Log Engine", version="0.1.0", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/demo/simulate")
async def simulate_from_ui(request: Request) -> RedirectResponse:
    pipeline = getattr(request.app.state, "pipeline", None)
    redis_client = getattr(request.app.state, "redis", None)

    now = datetime.now(timezone.utc)
    syslog_ts = now.strftime("%b %d %H:%M:%S")
    nginx_ts = now.strftime("%d/%b/%Y:%H:%M:%S +0000")

    samples = [
        *[
            (
                LogSource.SSHD,
                f"{syslog_ts} edge-fw-01 sshd[2100]: Failed password for invalid user admin from 203.0.113.45 port {40000 + i} ssh2",
            )
            for i in range(6)
        ],
        *[
            (
                LogSource.SSHD,
                f"{syslog_ts} edge-fw-01 sshd[2200]: Failed password for {u} from 198.51.100.22 port {41000 + idx} ssh2",
            )
            for idx, u in enumerate(["alice", "bob", "charlie", "dana", "eve"])
        ],
        (
            LogSource.NGINX,
            f'192.0.2.77 - - [{nginx_ts}] "GET /../../etc/passwd HTTP/1.1" 400 182 "-" "sqlmap/1.8"',
        ),
    ]

    for source, line in samples:
        event = parse_log_line(source, line)
        if event is None:
            continue
        if _is_serverless() and pipeline is not None:
            await pipeline.process_event(event)
        elif redis_client is not None:
            await redis_client.xadd(
                STREAM_NAME,
                {"payload": json.dumps(event.model_dump(mode="json"))},
                maxlen=settings.event_stream_maxlen,
                approximate=True,
            )

    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/alerts/{alert_id}/status")
async def update_alert_status(
    alert_id: int,
    request: Request,
    new_status: str = Form(...),
) -> RedirectResponse:
    allowed = {"open", "acknowledged", "resolved", "false_positive"}
    if new_status not in allowed:
        raise HTTPException(status_code=400, detail="Invalid alert status")

    db_pool = getattr(request.app.state, "db", None)
    if db_pool is not None:
        await db_pool.execute(
            "UPDATE alerts SET status = $1::alert_status WHERE id = $2",
            new_status,
            alert_id,
        )
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)


def _esc(val: object) -> str:
    if val is None:
        return ""
    return html.escape(str(val))


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> str:
    db_pool = getattr(request.app.state, "db", None)
    alerts_rows = []
    events_rows = []
    event_count = 0
    open_count = 0
    high_crit_count = 0
    total_hits = 0

    if db_pool is not None:
        try:
            event_count = await db_pool.fetchval("SELECT COUNT(*) FROM log_events") or 0
            open_count = (
                await db_pool.fetchval("SELECT COUNT(*) FROM alerts WHERE status = 'open'") or 0
            )
            high_crit_count = (
                await db_pool.fetchval(
                    "SELECT COUNT(*) FROM alerts WHERE severity IN ('high', 'critical')"
                )
                or 0
            )
            total_hits = (
                await db_pool.fetchval("SELECT COALESCE(SUM(occurrence_count), 0) FROM alerts")
                or 0
            )
            alerts_rows = await db_pool.fetch(
                """
                SELECT id, rule_id, rule_name, mitre_tactic, mitre_technique,
                       host(source_ip) AS source_ip, username, severity, risk_score,
                       status, title, description, occurrence_count, last_seen
                FROM alerts
                ORDER BY last_seen DESC
                LIMIT 75
                """
            )
            events_rows = await db_pool.fetch(
                """
                SELECT timestamp, source, host(source_ip) AS source_ip, username,
                       event_type, status, http_method, http_path, http_status
                FROM log_events
                ORDER BY timestamp DESC
                LIMIT 25
                """
            )
        except Exception:
            alerts_rows = []
            events_rows = []

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rule_counts: dict[str, int] = {}

    if not alerts_rows:
        alert_rows_html = (
            "<tr><td colspan='8' class='empty-row'>"
            "No alerts yet. Click <strong>Simulate Attack</strong> in the top right to trigger live detections."
            "</td></tr>"
        )
    else:
        rendered_alerts = []
        for row in alerts_rows:
            sev = str(row["severity"]).lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
            rule_label = f"{row['rule_id']} · {row['rule_name']}"
            rule_counts[rule_label] = rule_counts.get(rule_label, 0) + int(row["occurrence_count"] or 1)

            status_val = str(row["status"])
            ip_val = str(row["source_ip"])
            user_val = str(row["username"] or "-")

            rendered_alerts.append(
                f"<tr class='alert-row' "
                f"data-sev='{_esc(sev)}' "
                f"data-status='{_esc(status_val)}' "
                f"data-rule='{_esc(row['rule_id'])}' "
                f"data-search='{_esc((ip_val + ' ' + user_val + ' ' + str(row['title']) + ' ' + rule_label).lower())}'>"
                f"<td><span class='badge sev-{_esc(sev)}'>{_esc(sev.upper())}</span>"
                f"<div class='risk-sub'>Risk: <strong>{_esc(row['risk_score'])}</strong>/100</div></td>"
                f"<td><div class='rule-code'>{_esc(row['rule_id'])}</div>"
                f"<div class='rule-name'>{_esc(row['rule_name'])}</div></td>"
                f"<td><span class='mitre-pill'>{_esc(row['mitre_technique'])}</span>"
                f"<div class='muted-sm'>{_esc(row['mitre_tactic'])}</div></td>"
                f"<td><code class='ip-code'>{_esc(ip_val)}</code>"
                f"<div class='muted-sm'>User: {_esc(user_val)}</div></td>"
                f"<td><div class='alert-title'>{_esc(row['title'])}</div>"
                f"<div class='alert-desc'>{_esc(row['description'])}</div></td>"
                f"<td><span class='hits-num'>{_esc(row['occurrence_count'])}</span></td>"
                f"<td><span class='status-pill st-{_esc(status_val)}'>{_esc(status_val.replace('_', ' '))}</span></td>"
                f"<td>"
                f"<form method='post' action='/alerts/{_esc(row['id'])}/status' class='triage-form'>"
                f"<select name='new_status' class='triage-select'>"
                f"<option value='acknowledged'>Acknowledge</option>"
                f"<option value='resolved'>Resolve</option>"
                f"<option value='false_positive'>False Positive</option>"
                f"<option value='open'>Reopen</option>"
                f"</select>"
                f"<button type='submit' class='btn-save'>Update</button>"
                f"</form></td>"
                f"</tr>"
            )
        alert_rows_html = "".join(rendered_alerts)

    total_sev_alerts = max(1, sum(sev_counts.values()))
    sev_bars_html = ""
    sev_colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#eab308",
        "low": "#38bdf8",
    }
    for k, v in sev_counts.items():
        pct = round((v / total_sev_alerts) * 100)
        sev_bars_html += (
            f"<div class='bar-row'>"
            f"<div class='bar-meta'><span>{k.upper()}</span><strong>{v} ({pct}%)</strong></div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{pct}%;background:{sev_colors[k]};'></div></div>"
            f"</div>"
        )

    max_rule_hits = max(1, max(rule_counts.values(), default=1))
    rule_bars_html = ""
    if not rule_counts:
        rule_bars_html = "<div class='muted-sm'>No rule detections recorded yet.</div>"
    else:
        for r_name, r_hits in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
            pct = round((r_hits / max_rule_hits) * 100)
            rule_bars_html += (
                f"<div class='bar-row'>"
                f"<div class='bar-meta'><span>{_esc(r_name)}</span><strong>{r_hits} hits</strong></div>"
                f"<div class='bar-track'><div class='bar-fill' style='width:{pct}%;background:#6366f1;'></div></div>"
                f"</div>"
            )

    if not events_rows:
        event_rows_html = (
            "<tr><td colspan='6' class='empty-row'>No normalized log events yet.</td></tr>"
        )
    else:
        rendered_events = []
        for ev in events_rows:
            target = ev["http_path"] or "-"
            if ev["http_method"]:
                target = f"{ev['http_method']} {target}"
            rendered_events.append(
                f"<tr>"
                f"<td class='muted-sm'>{_esc(ev['timestamp'])}</td>"
                f"<td><span class='src-pill'>{_esc(ev['source'])}</span></td>"
                f"<td><code class='ip-code'>{_esc(ev['source_ip'])}</code></td>"
                f"<td>{_esc(ev['username'] or '-')}</td>"
                f"<td>{_esc(ev['event_type'])} · <strong>{_esc(ev['status'])}</strong></td>"
                f"<td class='mono-sm'>{_esc(target)}</td>"
                f"</tr>"
            )
        event_rows_html = "".join(rendered_events)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta http-equiv="refresh" content="20" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Threat Intelligence & Log Anomaly SOC</title>
  <style>
    :root {{
      --bg: #070d19;
      --panel: #0f172a;
      --panel-2: #131f38;
      --border: #1e293b;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #3b82f6;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      padding: 24px;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: radial-gradient(circle at top right, #111e38 0%, var(--bg) 48%);
      color: var(--text);
    }}
    .container {{ max-width: 1360px; margin: 0 auto; }}
    .topbar {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 22px;
      padding: 18px 22px;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
    }}
    .topbar h1 {{ margin: 0; font-size: 22px; letter-spacing: -0.01em; }}
    .topbar p {{ margin: 4px 0 0; color: var(--muted); font-size: 13px; }}
    .top-actions {{ display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }}
    .live-dot {{
      display: inline-flex; align-items: center; gap: 7px;
      font-size: 12px; color: #34d399; background: rgba(16, 185, 129, 0.12);
      border: 1px solid rgba(16, 185, 129, 0.3); padding: 6px 12px; border-radius: 999px;
    }}
    .live-dot::before {{
      content: ""; width: 8px; height: 8px; border-radius: 50%; background: #10b981;
    }}
    .btn-ghost {{
      background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
      padding: 7px 12px; border-radius: 8px; cursor: pointer; font-size: 13px; text-decoration: none;
    }}
    .btn-ghost:hover {{ border-color: var(--accent); }}
    .btn-sim {{
      background: #dc2626; color: white; border: none;
      padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600;
    }}
    .btn-sim:hover {{ background: #b91c1c; }}
    .kpis {{
      display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px;
    }}
    @media (max-width: 900px) {{ .kpis {{ grid-template-columns: repeat(2, 1fr); }} }}
    .kpi {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px;
    }}
    .kpi .lbl {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }}
    .kpi .num {{ font-size: 28px; font-weight: 700; margin-top: 6px; }}
    .kpi .sub {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
    .analytics-grid {{
      display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; margin-bottom: 18px;
    }}
    @media (max-width: 900px) {{ .analytics-grid {{ grid-template-columns: 1fr; }} }}
    .box {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 12px; padding: 16px 18px;
    }}
    .box h2 {{ margin: 0 0 12px; font-size: 15px; }}
    .bar-row {{ margin-bottom: 10px; }}
    .bar-meta {{ display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; color: var(--muted); }}
    .bar-meta strong {{ color: var(--text); }}
    .bar-track {{ height: 8px; background: var(--bg); border-radius: 999px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 999px; }}
    .filters {{
      display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; align-items: center;
    }}
    .filter-input, .filter-select {{
      background: var(--panel); color: var(--text); border: 1px solid var(--border);
      border-radius: 8px; padding: 8px 12px; font-size: 13px;
    }}
    .filter-input {{ min-width: 240px; flex: 1; }}
    .table-wrap {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 12px; overflow-x: auto;
      margin-bottom: 22px;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th {{
      text-align: left; padding: 11px 12px; background: var(--panel-2);
      color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border);
    }}
    td {{ padding: 11px 12px; border-bottom: 1px solid var(--border); vertical-align: top; font-size: 13px; }}
    tr:last-child td {{ border-bottom: none; }}
    .empty-row {{ text-align: center; padding: 24px; color: var(--muted); }}
    .badge {{
      display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 700;
    }}
    .sev-critical {{ background: rgba(239, 68, 68, 0.18); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .sev-high {{ background: rgba(249, 115, 22, 0.18); color: #fdba74; border: 1px solid rgba(249, 115, 22, 0.4); }}
    .sev-medium {{ background: rgba(234, 179, 8, 0.18); color: #fde047; border: 1px solid rgba(234, 179, 8, 0.4); }}
    .sev-low {{ background: rgba(56, 189, 248, 0.18); color: #7dd3fc; border: 1px solid rgba(56, 189, 248, 0.4); }}
    .risk-sub {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
    .rule-code {{ font-family: monospace; font-weight: 700; color: #93c5fd; }}
    .rule-name {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}
    .mitre-pill {{
      display: inline-block; font-family: monospace; font-size: 11px;
      background: rgba(99, 102, 241, 0.16); color: #c7d2fe; border: 1px solid rgba(99, 102, 241, 0.35);
      padding: 2px 7px; border-radius: 6px;
    }}
    .ip-code {{ font-family: monospace; background: var(--bg); padding: 2px 6px; border-radius: 5px; }}
    .muted-sm {{ font-size: 12px; color: var(--muted); margin-top: 3px; }}
    .alert-title {{ font-weight: 600; }}
    .alert-desc {{ font-size: 12px; color: var(--muted); margin-top: 3px; max-width: 360px; }}
    .hits-num {{ font-weight: 700; font-size: 15px; }}
    .status-pill {{
      display: inline-block; padding: 3px 8px; border-radius: 6px; font-size: 12px;
      background: var(--panel-2); border: 1px solid var(--border); text-transform: capitalize;
    }}
    .triage-form {{ display: flex; gap: 6px; align-items: center; }}
    .triage-select {{
      background: var(--bg); color: var(--text); border: 1px solid var(--border);
      border-radius: 6px; padding: 5px 7px; font-size: 12px;
    }}
    .btn-save {{
      background: var(--accent); color: white; border: none; border-radius: 6px;
      padding: 6px 10px; font-size: 12px; font-weight: 600; cursor: pointer;
    }}
    .btn-save:hover {{ filter: brightness(1.1); }}
    .src-pill {{
      font-family: monospace; font-size: 11px; background: var(--panel-2);
      padding: 2px 7px; border-radius: 5px; border: 1px solid var(--border);
    }}
    .mono-sm {{ font-family: monospace; font-size: 12px; color: #cbd5e1; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="topbar">
      <div>
        <h1>Threat Intelligence &amp; Log Anomaly SOC</h1>
        <p>Real-time ingestion, sliding-window rule detections, threat-intel scoring &amp; alert triage</p>
      </div>
      <div class="top-actions">
        <span class="live-dot">Pipeline Active</span>
        <form method="post" action="/demo/simulate" style="margin:0;">
          <button type="submit" class="btn-sim">Simulate Attack</button>
        </form>
        <button type="button" class="btn-ghost" onclick="location.reload()">Refresh</button>
      </div>
    </div>

    <div class="kpis">
      <div class="kpi">
        <div class="lbl">Events Ingested</div>
        <div class="num">{event_count}</div>
        <div class="sub">Normalized in PostgreSQL</div>
      </div>
      <div class="kpi">
        <div class="lbl">Open Alerts</div>
        <div class="num">{open_count}</div>
        <div class="sub">Awaiting analyst triage</div>
      </div>
      <div class="kpi">
        <div class="lbl">High / Critical</div>
        <div class="num">{high_crit_count}</div>
        <div class="sub">Elevated severity alerts</div>
      </div>
      <div class="kpi">
        <div class="lbl">Total Alert Hits</div>
        <div class="num">{total_hits}</div>
        <div class="sub">Intel Mode: {_esc(settings.intel_mode.upper())}</div>
      </div>
    </div>

    <div class="analytics-grid">
      <div class="box">
        <h2>Severity Distribution</h2>
        {sev_bars_html}
      </div>
      <div class="box">
        <h2>Detection Rule Hits</h2>
        {rule_bars_html}
      </div>
    </div>

    <div class="filters">
      <input id="searchBox" type="text" class="filter-input" placeholder="Search by IP, username, rule, or alert summary..." oninput="filterAlerts()" />
      <select id="sevFilter" class="filter-select" onchange="filterAlerts()">
        <option value="">All Severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select id="statusFilter" class="filter-select" onchange="filterAlerts()">
        <option value="">All Statuses</option>
        <option value="open">Open</option>
        <option value="acknowledged">Acknowledged</option>
        <option value="resolved">Resolved</option>
        <option value="false_positive">False Positive</option>
      </select>
      <select id="ruleFilter" class="filter-select" onchange="filterAlerts()">
        <option value="">All Rules</option>
        <option value="TIE-001">TIE-001 (Brute Force)</option>
        <option value="TIE-002">TIE-002 (Password Spray)</option>
        <option value="TIE-003">TIE-003 (Impossible Travel)</option>
        <option value="TIE-004">TIE-004 (Web Exploit)</option>
      </select>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Rule</th>
            <th>MITRE ATT&amp;CK</th>
            <th>Source / User</th>
            <th>Detection Summary</th>
            <th>Hits</th>
            <th>Status</th>
            <th>Triage Action</th>
          </tr>
        </thead>
        <tbody id="alertsBody">{alert_rows_html}</tbody>
      </table>
    </div>

    <div class="box" style="padding:0;overflow:hidden;">
      <div style="padding:14px 18px;border-bottom:1px solid var(--border);">
        <h2 style="margin:0;">Recent Normalized Log Events (Latest 25)</h2>
      </div>
      <div class="table-wrap" style="margin:0;border:none;border-radius:0;">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source</th>
              <th>Source IP</th>
              <th>User</th>
              <th>Event &amp; Status</th>
              <th>Request / Detail</th>
            </tr>
          </thead>
          <tbody>{event_rows_html}</tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    function filterAlerts() {{
      const q = document.getElementById("searchBox").value.trim().toLowerCase();
      const sev = document.getElementById("sevFilter").value;
      const st = document.getElementById("statusFilter").value;
      const rule = document.getElementById("ruleFilter").value;
      const rows = document.querySelectorAll("#alertsBody tr.alert-row");
      rows.forEach((row) => {{
        const matchQ = !q || (row.dataset.search || "").includes(q);
        const matchSev = !sev || row.dataset.sev === sev;
        const matchSt = !st || row.dataset.status === st;
        const matchRule = !rule || row.dataset.rule === rule;
        row.style.display = (matchQ && matchSev && matchSt && matchRule) ? "" : "none";
      }});
    }}
  </script>
</body>
</html>"""


@app.post("/ingest", response_model=IngestResponse, dependencies=[Depends(verify_api_key)])
async def ingest_logs(payload: IngestRequest, request: Request) -> IngestResponse:
    if len(payload.lines) > settings.max_batch_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Batch exceeds max size of {settings.max_batch_size}",
        )

    redis_client = getattr(request.app.state, "redis", None)
    if redis_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Redis client not initialized",
        )

    pipeline = getattr(request.app.state, "pipeline", None)
    serverless = _is_serverless()

    accepted = 0
    rejected = 0

    for raw_line in payload.lines:
        if len(raw_line.encode("utf-8")) > settings.max_raw_log_bytes:
            rejected += 1
            continue

        event = parse_log_line(payload.source, raw_line)
        if event is None:
            rejected += 1
            continue

        if serverless and pipeline is not None:
            await pipeline.process_event(event)
        else:
            await redis_client.xadd(
                STREAM_NAME,
                {"payload": json.dumps(event.model_dump(mode="json"))},
                maxlen=settings.event_stream_maxlen,
                approximate=True,
            )
        accepted += 1

    return IngestResponse(accepted=accepted, rejected=rejected, stream=STREAM_NAME)