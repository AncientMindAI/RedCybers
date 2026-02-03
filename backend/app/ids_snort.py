from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Callable, Optional

from .models import IDSAlert


class SnortJsonTailer:
    def __init__(self, path: str, on_alert: Callable[[IDSAlert], None]) -> None:
        self._path = path
        self._on_alert = on_alert
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._offset = 0

    def start(self) -> None:
        if not self._path:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            if not os.path.exists(self._path):
                time.sleep(1.0)
                continue
            try:
                self._read_new_lines()
            except Exception as exc:
                logging.warning("snort tailer error: %s", exc)
            time.sleep(0.5)

    def _read_new_lines(self) -> None:
        with open(self._path, "r", encoding="utf-8", errors="ignore") as handle:
            handle.seek(self._offset)
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                alert = self._parse(line)
                if alert:
                    self._on_alert(alert)
            self._offset = handle.tell()

    def _parse(self, line: str) -> Optional[IDSAlert]:
        try:
            data = json.loads(line)
        except Exception:
            return None
        if data.get("event_type") not in ("alert", "snort.alert"):
            return None
        alert = data.get("alert") or {}
        return IDSAlert(
            ts=str(data.get("timestamp", "")),
            sid=int(alert.get("signature_id") or alert.get("sid") or 0),
            gid=int(alert.get("gid") or 1),
            rev=int(alert.get("rev") or 1),
            signature=str(alert.get("signature") or alert.get("msg") or ""),
            classification=str(alert.get("category") or alert.get("classification") or ""),
            priority=int(alert.get("severity") or alert.get("priority") or 0),
            src_ip=str(data.get("src_ip", "")),
            src_port=int(data.get("src_port") or 0),
            dst_ip=str(data.get("dest_ip", "")),
            dst_port=int(data.get("dest_port") or 0),
            proto=str(data.get("proto", "")),
            raw=line,
        )
