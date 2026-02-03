from __future__ import annotations

from collections import Counter, deque
from contextlib import asynccontextmanager
import asyncio
from datetime import datetime, timezone
from io import BytesIO
import json
import logging
import os
import socket
import threading
import time
from typing import Deque, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from openpyxl import Workbook
from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .collector.etw_collector import ETWCollector
from .collector.polling_collector import PollingCollector
from .db import DBWriter, get_database_url
from .enrichment import EnrichmentService
from .mitre import best_match, map_event
from .models import Event
from .cve_store import CVEStore

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787


class AppState:
    def __init__(self) -> None:
        self.buffer: Deque[Event] = deque(maxlen=10000)
        self.config: Dict[str, object] = {
            "interval_sec": 1.0,
            "direction": "outbound",
            "allow_list": [],
            "deny_list": [],
            "ipinfo_key": "",
            "abuseipdb_key": "",
            "otx_key": "",
            "threatfox_key": "",
            "threatfox_days": 1,
            "feodo_url": "",
            "otx_export_url": "",
            "abuseipdb_confidence_min": "75",
            "abuseipdb_limit": "100000",
            "mitre_min_score": 25,
            "suppress_private": False,
            "suppress_loopback": True,
            "suppress_processes": [],
            "suppress_ports": [],
            "cve_source_path": "",
            "cve_import_limit": 2000,
            "cve_min_year": 2020,
        }
        self.status: Dict[str, object] = {
            "collector": "none",
            "privileged": False,
            "events_total": 0,
            "events_per_sec": 0.0,
            "started_at": time.time(),
            "host": DEFAULT_HOST,
            "port": DEFAULT_PORT,
        }
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.websockets: List[WebSocket] = []
        self._last_rate_at = time.time()
        self._last_rate_count = 0
        self.collector_thread: Optional[threading.Thread] = None
        self.collector_stop = threading.Event()
        self.collector = None
        self.enrichment: Optional[EnrichmentService] = None
        self.db_writer: Optional[DBWriter] = None
        self.cve_store: Optional[CVEStore] = None

    def enrich_event(self, event: Event) -> None:
        if self.enrichment is not None:
            self.enrichment.enrich(event)
        _apply_mitre_and_triage(event, self.config)

    def enqueue(self, event: Event) -> None:
        self.buffer.append(event)
        if self.db_writer is not None:
            self.db_writer.enqueue(event)
        self.status["events_total"] = int(self.status["events_total"]) + 1
        self._update_rate()
        if self.loop is None:
            return
        self.loop.call_soon_threadsafe(asyncio.create_task, self._broadcast(event))

    async def _broadcast(self, event: Event) -> None:
        dead: List[WebSocket] = []
        for ws in self.websockets:
            try:
                await ws.send_json({"type": "event", "data": event.model_dump()})
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self.websockets:
                self.websockets.remove(ws)

    def _update_rate(self) -> None:
        now = time.time()
        if now - self._last_rate_at >= 1.0:
            delta = int(self.status["events_total"]) - self._last_rate_count
            self.status["events_per_sec"] = float(delta) / (now - self._last_rate_at)
            self._last_rate_at = now
            self._last_rate_count = int(self.status["events_total"])


state = AppState()


def _get_config_file() -> str:
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    return os.path.join(base, ".redcybers-config.json")


def _load_config() -> Dict[str, object]:
    path = _get_config_file()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


def _save_config(data: Dict[str, object]) -> None:
    path = _get_config_file()
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
    except Exception:
        logging.warning("failed to write config file: %s", path)


def _is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _get_free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def _select_port(host: str, port: int, auto: bool) -> int:
    if port == 0:
        return _get_free_port(host)
    if auto:
        if _is_port_free(host, port):
            return port
        logging.warning("port %s in use, selecting a free port", port)
        return _get_free_port(host)
    return port


def _get_port_file() -> str:
    env_path = os.getenv("NETWATCH_PORT_FILE")
    if env_path:
        return os.path.abspath(env_path)
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    return os.path.join(base, ".netwatch-port")


def _parse_list(value: object) -> List[str]:
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    raw = str(value or "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _parse_int_list(value: object) -> List[int]:
    items = _parse_list(value)
    ints: List[int] = []
    for item in items:
        try:
            ints.append(int(item))
        except ValueError:
            continue
    return ints


def _apply_mitre_and_triage(event: Event, config: Dict[str, object]) -> None:
    matches = map_event(event)
    top = best_match(matches)
    if top:
        event.mitre_tactic = top.tactic
        event.mitre_technique = top.technique
        event.mitre_technique_id = top.technique_id
        event.mitre_confidence = top.confidence

    score = int(event.threat_score)
    tactic_weight = {
        "Command and Control": 20,
        "Exfiltration": 25,
        "Credential Access": 20,
        "Lateral Movement": 15,
        "Execution": 10,
        "Defense Evasion": 10,
        "Persistence": 10,
    }
    score += tactic_weight.get(event.mitre_tactic, 0)
    if event.is_public:
        score += 5
    if event.mitre_confidence:
        score += min(20, int(event.mitre_confidence / 4))
    event.relevance_score = min(score, 100)

    suppress_private = bool(config.get("suppress_private", True))
    suppress_loopback = bool(config.get("suppress_loopback", True))
    suppress_processes = {p.lower() for p in _parse_list(config.get("suppress_processes", []))}
    suppress_ports = set(_parse_int_list(config.get("suppress_ports", [])))
    min_score = int(config.get("mitre_min_score", 25))

    if suppress_loopback and event.remote_ip.startswith("127."):
        event.suppressed = True
        event.suppression_reason = "loopback"
        return
    if suppress_private and not event.is_public:
        event.suppressed = True
        event.suppression_reason = "private"
        return
    if event.process_name.lower() in suppress_processes:
        event.suppressed = True
        event.suppression_reason = "process"
        return
    if event.remote_port in suppress_ports:
        event.suppressed = True
        event.suppression_reason = "port"
        return
    if event.relevance_score < min_score:
        event.suppressed = True
        event.suppression_reason = "low-score"


def _write_port_file(port: int) -> None:
    path = _get_port_file()
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(str(port))
        logging.info("wrote port file: %s", path)
    except Exception:
        logging.warning("failed to write port file: %s", path)


def _summary(events: List[Event]) -> Dict[str, object]:
    visible = [e for e in events if not e.suppressed]
    public_events = [e for e in visible if e.is_public]
    by_app = Counter([e.process_name for e in public_events])
    top_apps = []
    for app, count in by_app.most_common(5):
        uniq_ips = {e.remote_ip for e in public_events if e.process_name == app}
        top_apps.append({"app": app, "count": count, "unique_public_ips": len(uniq_ips)})

    by_country = Counter([e.remote_country for e in public_events if e.remote_country])
    top_countries = [
        {"country": country, "count": count} for country, count in by_country.most_common(5)
    ]

    threat_hits = sum(1 for e in public_events if e.threat_sources)
    suppressed_count = len([e for e in events if e.suppressed])

    alerts = []
    for event in reversed(visible[-200:]):
        if not event.threat_sources:
            continue
        alerts.append(
            {
                "ts": event.ts,
                "process_name": event.process_name,
                "remote_ip": event.remote_ip,
                "remote_country": event.remote_country,
                "threat_sources": event.threat_sources,
                "threat_score": event.threat_score,
            }
        )
        if len(alerts) >= 8:
            break

    mitre_tactics = Counter([e.mitre_tactic for e in public_events if e.mitre_tactic])
    mitre_techniques = Counter([e.mitre_technique_id for e in public_events if e.mitre_technique_id])
    breakdown: Dict[str, Counter] = {}
    for event in public_events:
        if not event.mitre_tactic or not event.mitre_technique_id:
            continue
        breakdown.setdefault(event.mitre_tactic, Counter())
        breakdown[event.mitre_tactic][event.mitre_technique_id] += 1
    return {
        "top_public_apps": top_apps,
        "top_countries": top_countries,
        "public_events": len(public_events),
        "threat_hits": threat_hits,
        "alerts": alerts,
        "suppressed_events": suppressed_count,
        "mitre_tactics": [{"tactic": k, "count": v} for k, v in mitre_tactics.most_common()],
        "mitre_techniques": [{"technique_id": k, "count": v} for k, v in mitre_techniques.most_common(10)],
        "mitre_breakdown": {
            tactic: [{"technique_id": k, "count": v} for k, v in counter.most_common(8)]
            for tactic, counter in breakdown.items()
        },
    }


def _build_pdf_report(events: List[Event], summary: Dict[str, object], health_payload: Dict[str, object]) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=LETTER,
        leftMargin=0.7 * inch,
        rightMargin=0.7 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="RedCybers Audit Report",
    )
    styles = getSampleStyleSheet()
    title = ParagraphStyle(
        "RedCybersTitle",
        parent=styles["Title"],
        fontSize=20,
        textColor=colors.HexColor("#0b0f14"),
        spaceAfter=12,
    )
    h2 = ParagraphStyle(
        "RedCybersH2",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#0b0f14"),
        spaceBefore=10,
        spaceAfter=6,
    )
    body = ParagraphStyle(
        "RedCybersBody",
        parent=styles["BodyText"],
        fontSize=10,
        leading=13,
    )

    now = datetime.now(timezone.utc)
    logo_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "public", "redcybers-logo.png")
    )
    header = []
    if os.path.exists(logo_path):
        header.append(Image(logo_path, width=0.55 * inch, height=0.55 * inch))
    header.extend(
        [
            Paragraph("<b>RedCybers</b> Audit & Threat Telemetry Report", title),
            Paragraph(f"Generated: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}", body),
            Paragraph("Scope: Real-time telemetry, threat enrichment, and audit artifacts.", body),
        ]
    )

    ops = [
        ["Collector", health_payload.get("collector", "-")],
        ["Mode", "privileged" if health_payload.get("privileged") else "unprivileged"],
        ["Events (total)", str(health_payload.get("events_total", 0))],
        ["Events/sec", f"{health_payload.get('events_per_sec', 0.0):.2f}"],
        ["Public events", str(summary.get("public_events", 0))],
        ["Threat hits", str(summary.get("threat_hits", 0))],
        ["Suppressed events", str(summary.get("suppressed_events", 0))],
    ]
    ops_table = Table(ops, colWidths=[2.1 * inch, 3.8 * inch])
    ops_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )

    top_apps = summary.get("top_public_apps", [])
    apps_rows = [["App", "Connections", "Unique Public IPs"]]
    for item in top_apps:
        apps_rows.append([item["app"], str(item["count"]), str(item["unique_public_ips"])])
    if len(apps_rows) == 1:
        apps_rows.append(["No public activity observed", "-", "-"])
    apps_table = Table(apps_rows, colWidths=[3.2 * inch, 1.2 * inch, 1.6 * inch])
    apps_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9edf2")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    countries = summary.get("top_countries", [])
    country_rows = [["Country", "Count"]]
    for item in countries:
        country_rows.append([item["country"], str(item["count"])])
    if len(country_rows) == 1:
        country_rows.append(["No geo data observed", "-"])
    country_table = Table(country_rows, colWidths=[3.2 * inch, 1.2 * inch])
    country_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9edf2")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    alerts = summary.get("alerts", [])
    alert_rows = [["Time", "Process", "Remote IP", "Country", "Threat Score", "Sources"]]
    for alert in alerts:
        alert_rows.append(
            [
                str(alert.get("ts", ""))[:19],
                alert.get("process_name", "-"),
                alert.get("remote_ip", "-"),
                alert.get("remote_country", "-"),
                str(alert.get("threat_score", 0)),
                ",".join(alert.get("threat_sources", [])),
            ]
        )
    if len(alert_rows) == 1:
        alert_rows.append(["-", "No threat alerts observed", "-", "-", "-", "-"])
    alert_table = Table(alert_rows, colWidths=[1.2 * inch, 1.5 * inch, 1.2 * inch, 0.9 * inch, 0.8 * inch, 1.3 * inch])
    alert_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9edf2")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]
        )
    )

    feeds = health_payload.get("feeds", []) or []
    feed_rows = [["Feed", "Last Count", "Status"]]
    for feed in feeds:
        status = "OK" if not feed.get("last_error") else f"Error: {feed.get('last_error')}"
        feed_rows.append([feed.get("name", "-"), str(feed.get("last_count", 0)), status])
    if len(feed_rows) == 1:
        feed_rows.append(["No feeds configured", "-", "-"])
    feed_table = Table(feed_rows, colWidths=[2.0 * inch, 1.0 * inch, 3.0 * inch])
    feed_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9edf2")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )

    crosswalk_rows = [
        ["ATT&CK Tactic", "Observed Evidence", "NIST CSF", "ISO 27001", "CIS"],
        ["Initial Access", "Phishing/Email alerts", "DE.CM-7", "A.8.23", "CIS 9"],
        ["Execution", "PowerShell / script activity", "DE.CM-1", "A.8.9", "CIS 8"],
        ["Persistence", "Autoruns / services", "PR.IP-1", "A.8.12", "CIS 4"],
        ["Command & Control", "DNS/Firewall beaconing", "DE.CM-1", "A.8.16", "CIS 13"],
        ["Exfiltration", "DLP/NDR alerts", "DE.CM-7", "A.8.24", "CIS 14"],
    ]
    crosswalk_table = Table(crosswalk_rows, colWidths=[1.2 * inch, 2.0 * inch, 0.8 * inch, 0.9 * inch, 0.6 * inch])
    crosswalk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9edf2")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story = []
    story.extend(header)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Executive Summary", h2))
    story.append(Paragraph(
        "This report summarizes observed RedCybers telemetry, enrichment, and audit artifacts. "
        "It is designed to support a coherent audit trail aligned with NIST CSF, ISO/IEC 27001, "
        "and CIS Critical Security Controls while mapping detections to MITRE ATT&CK.",
        body,
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Required Feeds & Telemetry (Template)", h2))
    story.append(Paragraph(
        "EDR/XDR telemetry, identity logs (Entra ID/AD/Okta), email security, firewall/NDR, DNS, "
        "cloud control plane logs, vulnerability scanner output, and asset inventory (CMDB). "
        "Audits require evidence of log source coverage beyond endpoint telemetry.",
        body,
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Operational Snapshot", h2))
    story.append(ops_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Top Public Applications", h2))
    story.append(apps_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("Top Countries (Public IPs)", h2))
    story.append(country_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("Threat Alerts (Observed Window)", h2))
    story.append(alert_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("Threat Feed Status", h2))
    story.append(feed_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("MITRE ATT&CK Coverage (Observed)", h2))
    tactic_rows = [["Tactic", "Count"]]
    for item in summary.get("mitre_tactics", []):
        tactic_rows.append([item.get("tactic", "-"), str(item.get("count", 0))])
    if len(tactic_rows) == 1:
        tactic_rows.append(["No mapped tactics observed", "-"])
    tactic_table = Table(tactic_rows, colWidths=[3.0 * inch, 1.0 * inch])
    tactic_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e9edf2")),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(tactic_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("ATT&CK → NIST/ISO/CIS Crosswalk Template", h2))
    story.append(Paragraph(
        "The table below provides a practitioner-aligned mapping. Replace with observed evidence "
        "as coverage expands (e.g., Red Canary detections, firewall/NDR validation, identity logs).",
        body,
    ))
    story.append(Spacer(1, 6))
    story.append(crosswalk_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Evidence & Audit Artifacts (Required)", h2))
    story.append(Paragraph(
        "Include timestamped alert samples, detection logic summaries, log source enablement screenshots, "
        "incident closure notes, control ownership assignments, and exception registers.",
        body,
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph("Gaps & Roadmap", h2))
    story.append(Paragraph(
        "Document missing ATT&CK techniques, planned telemetry (EDR/XDR, identity, DNS, NDR), and "
        "target maturity state with remediation timelines.",
        body,
    ))

    doc.build(story)
    buf.seek(0)
    return buf.read()


@asynccontextmanager
async def lifespan(_: FastAPI):
    state.loop = asyncio.get_running_loop()
    persisted = _load_config()
    if persisted:
        state.config.update(persisted)

    state.enrichment = EnrichmentService()
    state.enrichment.start(state.config)

    db_url = get_database_url()
    if db_url:
        retention_days = int(os.getenv("REDCYBERS_RETENTION_DAYS", "90"))
        state.db_writer = DBWriter(db_url, retention_days=retention_days)
        state.db_writer.start()
        state.cve_store = CVEStore(db_url)
        state.cve_store.start()

    if ETWCollector.available():
        state.collector = ETWCollector(state, state.collector_stop)
        state.status["collector"] = "etw"
        state.status["privileged"] = True
    else:
        state.collector = PollingCollector(state, state.collector_stop)
        state.status["collector"] = "polling"
        state.status["privileged"] = False

    state.collector_thread = threading.Thread(target=state.collector.run, daemon=False)
    state.collector_thread.start()
    logging.info("collector started: %s", state.status["collector"])

    try:
        yield
    finally:
        state.collector_stop.set()
        if state.db_writer is not None:
            state.db_writer.stop()
        if state.cve_store is not None:
            state.cve_store.stop()
        if state.enrichment is not None:
            state.enrichment.stop()
        if hasattr(state.collector, "stop"):
            try:
                state.collector.stop()
            except Exception:
                pass
        if state.collector_thread is not None:
            state.collector_thread.join(timeout=3)


app = FastAPI(title="RedCybers", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1):\d+$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> JSONResponse:
    payload = {
        "collector": state.status["collector"],
        "privileged": state.status["privileged"],
        "events_total": state.status["events_total"],
        "events_per_sec": state.status["events_per_sec"],
        "uptime_sec": time.time() - state.status["started_at"],
        "host": state.status.get("host"),
        "port": state.status.get("port"),
        "feeds": state.enrichment.threats.status() if state.enrichment else [],
    }
    return JSONResponse(payload)


@app.get("/summary")
async def summary() -> JSONResponse:
    events = list(state.buffer)
    return JSONResponse(_summary(events))


@app.get("/config")
async def get_config() -> JSONResponse:
    return JSONResponse(state.config)


@app.post("/config")
async def set_config(payload: Dict[str, object]) -> JSONResponse:
    state.config.update(payload)
    _save_config(state.config)
    if state.enrichment is not None:
        state.enrichment.apply_config(state.config)
    return JSONResponse(state.config)


@app.get("/history")
async def history(limit: int = 500) -> JSONResponse:
    events = list(state.buffer)[-limit:]
    return JSONResponse([e.model_dump() for e in events])


@app.get("/query")
async def query(
    limit: int = 500,
    process_name: str = "",
    remote_ip: str = "",
    country: str = "",
    threat_min: int = 0,
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None,
) -> JSONResponse:
    if state.db_writer is None:
        return JSONResponse({"error": "database disabled"}, status_code=400)
    rows = state.db_writer.query(
        limit=limit,
        process_name=process_name,
        remote_ip=remote_ip,
        country=country,
        threat_min=threat_min,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    return JSONResponse(rows)


@app.post("/cve/import")
async def import_cves(limit: int = 2000, path: Optional[str] = None) -> JSONResponse:
    if state.cve_store is None:
        return JSONResponse({"error": "database disabled"}, status_code=400)
    source = path or str(state.config.get("cve_source_path") or os.getenv("CVE_SOURCE_PATH", "")).strip()
    if not source:
        return JSONResponse({"error": "missing CVE source path"}, status_code=400)
    max_limit = int(state.config.get("cve_import_limit") or limit or 2000)
    min_year = int(state.config.get("cve_min_year") or os.getenv("CVE_MIN_YEAR", "0"))
    records = import_cves_from_path(source, max_limit, min_year=min_year)
    if not records:
        return JSONResponse({"imported": 0})
    count = state.cve_store.upsert(records)
    return JSONResponse({"imported": count})


@app.get("/cve/search")
async def search_cves(query: str = "", severity_min: float = 0.0, limit: int = 100) -> JSONResponse:
    if state.cve_store is None:
        return JSONResponse({"error": "database disabled"}, status_code=400)
    return JSONResponse(state.cve_store.search(query=query, severity_min=severity_min, limit=limit))


@app.get("/cve/stats")
async def cve_stats() -> JSONResponse:
    if state.cve_store is None:
        return JSONResponse({"error": "database disabled"}, status_code=400)
    return JSONResponse(state.cve_store.stats())


@app.get("/export/xlsx")
async def export_xlsx(limit: int = 2000) -> Response:
    events = list(state.buffer)[-min(limit, 10000):]
    wb = Workbook()
    ws = wb.active
    ws.title = "RedCybers"

    headers = [
        "ts",
        "pid",
        "process_name",
        "process_path",
        "user",
        "direction",
        "protocol",
        "local_ip",
        "local_port",
        "remote_ip",
        "remote_port",
        "state",
        "is_public",
        "remote_country",
        "remote_region",
        "remote_city",
        "remote_org",
        "remote_asn",
        "remote_hostname",
        "remote_loc",
        "remote_timezone",
        "threat_sources",
        "threat_score",
        "mitre_tactic",
        "mitre_technique",
        "mitre_technique_id",
        "mitre_confidence",
        "relevance_score",
        "suppressed",
        "suppression_reason",
    ]
    ws.append(headers)
    for event in events:
        data = event.model_dump()
        data["threat_sources"] = ",".join(event.threat_sources)
        ws.append([data.get(h, "") for h in headers])

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=redcybers-export.xlsx"},
    )


@app.get("/export/pdf")
async def export_pdf(limit: int = 2000) -> Response:
    events = list(state.buffer)[-min(limit, 10000):]
    summary_payload = _summary(events)
    health_payload = {
        "collector": state.status["collector"],
        "privileged": state.status["privileged"],
        "events_total": state.status["events_total"],
        "events_per_sec": state.status["events_per_sec"],
        "host": state.status.get("host"),
        "port": state.status.get("port"),
        "feeds": state.enrichment.threats.status() if state.enrichment else [],
    }
    pdf = _build_pdf_report(events, summary_payload, health_payload)
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=redcybers-report.pdf"},
    )


@app.websocket("/stream")
async def stream(websocket: WebSocket) -> None:
    await websocket.accept()
    state.websockets.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.websockets:
            state.websockets.remove(websocket)


if __name__ == "__main__":
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="RedCybers backend")
    parser.add_argument("--host", default=os.getenv("NETWATCH_HOST", DEFAULT_HOST))
    parser.add_argument("--port", type=int, default=int(os.getenv("NETWATCH_PORT", DEFAULT_PORT)))
    parser.add_argument("--auto-port", action="store_true", help="Pick a free port if the requested one is busy")
    args = parser.parse_args()

    port = _select_port(args.host, args.port, args.auto_port)
    if port != args.port:
        logging.info("selected free port: %s", port)

    state.status["host"] = args.host
    state.status["port"] = port
    _write_port_file(port)

    uvicorn.run("app.main:app", host=args.host, port=port, reload=False)
from .cve import import_cves_from_path
