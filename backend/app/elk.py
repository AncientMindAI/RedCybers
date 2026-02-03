from __future__ import annotations

import logging
import queue
import threading
from typing import Dict, Optional

import requests


class ElkSender:
    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._queue: queue.Queue[Dict[str, object]] = queue.Queue(maxsize=20000)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def enqueue(self, payload: Dict[str, object], index: str) -> None:
        try:
            payload = dict(payload)
            payload["index"] = index
            self._queue.put_nowait(payload)
        except queue.Full:
            pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                requests.post(self._base_url, json=item, timeout=2)
            except Exception as exc:
                logging.debug("elk send failed: %s", exc)
