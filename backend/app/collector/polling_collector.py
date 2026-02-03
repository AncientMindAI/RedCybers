from __future__ import annotations

import socket
import threading
import time
from typing import Dict, Tuple

import psutil

from ..models import Event


class PollingCollector:
    def __init__(self, state, stop_event: threading.Event) -> None:
        self.state = state
        self._cache: Dict[int, Tuple[str, str, str, float]] = {}
        self._stop_event = stop_event

    def run(self) -> None:
        interval = float(self.state.config.get("interval_sec", 1.0))
        while not self._stop_event.is_set():
            self._poll_once()
            self._stop_event.wait(interval)

    def _poll_once(self) -> None:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            pid = conn.pid or 0
            proc_name, proc_path, user = self._get_proc_info(pid)
            proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            event = Event(
                ts=Event.now_iso(),
                pid=pid,
                process_name=proc_name,
                process_path=proc_path,
                user=user,
                direction="outbound",
                protocol=proto,
                local_ip=str(conn.laddr.ip),
                local_port=int(conn.laddr.port),
                remote_ip=str(conn.raddr.ip),
                remote_port=int(conn.raddr.port),
                state=str(conn.status),
            )
            if hasattr(self.state, "enrich_event"):
                self.state.enrich_event(event)
            self.state.enqueue(event)

    def _get_proc_info(self, pid: int) -> Tuple[str, str, str]:
        now = time.time()
        if pid in self._cache:
            name, path, user, ts = self._cache[pid]
            if now - ts < 60:
                return name, path, user
        try:
            p = psutil.Process(pid)
            name = p.name()
            path = p.exe() if p.exe() else ""
            user = p.username() if p.username() else ""
        except Exception:
            name, path, user = "unknown", "", ""
        self._cache[pid] = (name, path, user, now)
        return name, path, user
