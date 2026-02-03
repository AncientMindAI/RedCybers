from __future__ import annotations

from collections import Counter, deque
from contextlib import asynccontextmanager
import asyncio
import logging
import os
import socket
import threading
import time
from typing import Deque, Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, Response
from openpyxl import Workbook

from .collector.etw_collector import ETWCollector
from .collector.polling_collector import PollingCollector
from .enrichment import EnrichmentService
from .models import Event

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

    def enrich_event(self, event: Event) -> None:
        if self.enrichment is not None:
            self.enrichment.enrich(event)

    def enqueue(self, event: Event) -> None:
        self.buffer.append(event)
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


def _write_port_file(port: int) -> None:
    path = _get_port_file()
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(str(port))
        logging.info("wrote port file: %s", path)
    except Exception:
        logging.warning("failed to write port file: %s", path)


def _summary(events: List[Event]) -> Dict[str, object]:
    public_events = [e for e in events if e.is_public]
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

    alerts = []
    for event in reversed(events[-200:]):
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

    return {
        "top_public_apps": top_apps,
        "top_countries": top_countries,
        "public_events": len(public_events),
        "threat_hits": threat_hits,
        "alerts": alerts,
    }


@asynccontextmanager
async def lifespan(_: FastAPI):
    state.loop = asyncio.get_running_loop()
    state.enrichment = EnrichmentService(state.collector_stop)
    state.enrichment.start()

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
    return JSONResponse(state.config)


@app.get("/history")
async def history(limit: int = 500) -> JSONResponse:
    events = list(state.buffer)[-limit:]
    return JSONResponse([e.model_dump() for e in events])


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
    ]
    ws.append(headers)
    for event in events:
        data = event.model_dump()
        data["threat_sources"] = ",".join(event.threat_sources)
        ws.append([data.get(h, "") for h in headers])

    from io import BytesIO

    buf = BytesIO()
    wb.save(buf)
    buf.seek(0)

    return Response(
        content=buf.read(),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": "attachment; filename=redcybers-export.xlsx"},
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
