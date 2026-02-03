from __future__ import annotations

import ctypes
import logging
import threading
import time
from typing import Dict, Tuple

import psutil

from ..models import Event


class ETWCollector:
    def __init__(self, state, stop_event: threading.Event) -> None:
        self.state = state
        self._stop_event = stop_event
        self._cache: Dict[int, Tuple[str, str, str, float]] = {}
        self._job = None

    @staticmethod
    def available() -> bool:
        try:
            import etw  # noqa: F401
        except Exception:
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def run(self) -> None:
        import etw

        providers = [
            etw.ProviderInfo(
                "Tcpip",
                etw.GUID("{9A280AC0-C8E0-11D1-84E2-00C04FB998A2}"),
            )
        ]

        self._job = etw.ETW(providers=providers, event_callback=self._on_event)
        self._job.start()
        logging.info("etw capture started (Tcpip provider)")

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(1)
        finally:
            self.stop()

    def stop(self) -> None:
        job = self._job
        if job is None:
            return
        try:
            job.stop()
        except Exception:
            pass

    def _on_event(self, event) -> None:
        props = self._extract_props(event)
        if not props:
            return

        pid = self._get_int(props, ["PID", "Pid", "ProcessId", "ProcessID"])
        if pid is None:
            pid = 0
        proc_name, proc_path, user = self._get_proc_info(pid)

        saddr = self._get_str(props, ["saddr", "SourceAddress", "SourceIP", "LocalAddress"])
        daddr = self._get_str(props, ["daddr", "DestAddress", "DestinationAddress", "RemoteAddress"])
        sport = self._get_int(props, ["sport", "SourcePort", "LocalPort"])
        dport = self._get_int(props, ["dport", "DestPort", "DestinationPort", "RemotePort"])

        if not saddr or not daddr or sport is None or dport is None:
            return

        event_obj = Event(
            ts=Event.now_iso(),
            pid=int(pid),
            process_name=proc_name,
            process_path=proc_path,
            user=user,
            direction="outbound",
            protocol="TCP",
            local_ip=str(saddr),
            local_port=int(sport),
            remote_ip=str(daddr),
            remote_port=int(dport),
            state="ESTABLISHED",
        )
        if hasattr(self.state, "enrich_event"):
            self.state.enrich_event(event_obj)
        self.state.enqueue(event_obj)

    def _extract_props(self, event) -> Dict[str, object]:
        if isinstance(event, dict):
            return event

        for attr in ["EventData", "event_data", "data", "Data", "payload", "Payload"]:
            if hasattr(event, attr):
                value = getattr(event, attr)
                if isinstance(value, dict):
                    return value
                if isinstance(value, list):
                    out = {}
                    for item in value:
                        name = getattr(item, "Name", None) or getattr(item, "name", None)
                        val = getattr(item, "Value", None) or getattr(item, "value", None)
                        if name is not None:
                            out[str(name)] = val
                    if out:
                        return out

        props = {}
        if hasattr(event, "properties"):
            value = getattr(event, "properties")
            if isinstance(value, list):
                for item in value:
                    name = getattr(item, "Name", None) or getattr(item, "name", None)
                    val = getattr(item, "Value", None) or getattr(item, "value", None)
                    if name is not None:
                        props[str(name)] = val
        return props

    def _get_int(self, props: Dict[str, object], keys) -> int | None:
        for key in keys:
            if key in props and props[key] is not None:
                try:
                    return int(props[key])
                except Exception:
                    continue
        return None

    def _get_str(self, props: Dict[str, object], keys) -> str | None:
        for key in keys:
            if key in props and props[key] is not None:
                try:
                    return str(props[key])
                except Exception:
                    continue
        return None

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
