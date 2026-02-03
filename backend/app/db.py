from __future__ import annotations

import logging
import os
import queue
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, Text, create_engine, text
from sqlalchemy.engine import Engine

from .models import Event


def _parse_ts(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return datetime.now(timezone.utc)


class DBWriter:
    def __init__(self, database_url: str, retention_days: int = 90) -> None:
        self.database_url = database_url
        self.retention_days = retention_days
        self._engine: Engine = create_engine(database_url, pool_pre_ping=True)
        self._meta = MetaData()
        self._table = Table(
            "events",
            self._meta,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("ts", DateTime(timezone=True), index=True),
            Column("pid", Integer),
            Column("process_name", String(256)),
            Column("process_path", Text),
            Column("user_name", String(256)),
            Column("direction", String(32)),
            Column("protocol", String(16)),
            Column("local_ip", String(64)),
            Column("local_port", Integer),
            Column("remote_ip", String(64), index=True),
            Column("remote_port", Integer),
            Column("state", String(64)),
            Column("is_public", Integer),
            Column("remote_country", String(32), index=True),
            Column("remote_region", String(64)),
            Column("remote_city", String(64)),
            Column("remote_org", Text),
            Column("remote_asn", String(64)),
            Column("remote_hostname", Text),
            Column("remote_loc", String(64)),
            Column("remote_timezone", String(64)),
            Column("threat_sources", Text),
            Column("threat_score", Integer),
        )
        self._queue: queue.Queue[Event] = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._retention_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._meta.create_all(self._engine)
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._retention_thread = threading.Thread(target=self._retention_loop, daemon=True)
        self._retention_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._retention_thread is not None:
            self._retention_thread.join(timeout=2)

    def enqueue(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            pass

    def query(
        self,
        limit: int = 500,
        process_name: str = "",
        remote_ip: str = "",
        country: str = "",
        threat_min: int = 0,
        start_ts: Optional[str] = None,
        end_ts: Optional[str] = None,
    ) -> List[Dict[str, object]]:
        clauses = []
        params: Dict[str, object] = {"limit": limit, "threat_min": threat_min}
        if process_name:
            clauses.append("process_name ILIKE :process_name")
            params["process_name"] = f"%{process_name}%"
        if remote_ip:
            clauses.append("remote_ip = :remote_ip")
            params["remote_ip"] = remote_ip
        if country:
            clauses.append("remote_country = :country")
            params["country"] = country
        if start_ts:
            clauses.append("ts >= :start_ts")
            params["start_ts"] = _parse_ts(start_ts)
        if end_ts:
            clauses.append("ts <= :end_ts")
            params["end_ts"] = _parse_ts(end_ts)
        clauses.append("threat_score >= :threat_min")

        where = " AND ".join(clauses) if clauses else "1=1"
        sql = text(
            f"""
            SELECT ts, pid, process_name, process_path, user_name, direction, protocol,
                   local_ip, local_port, remote_ip, remote_port, state, is_public,
                   remote_country, remote_region, remote_city, remote_org, remote_asn,
                   remote_hostname, remote_loc, remote_timezone, threat_sources, threat_score
            FROM events
            WHERE {where}
            ORDER BY ts DESC
            LIMIT :limit
            """
        )
        with self._engine.connect() as conn:
            rows = conn.execute(sql, params).mappings().all()
        return [dict(r) for r in rows]

    def _run(self) -> None:
        batch: List[Event] = []
        last_flush = time.time()
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=0.5)
                batch.append(event)
            except queue.Empty:
                pass

            now = time.time()
            if batch and (len(batch) >= 200 or now - last_flush > 1.0):
                self._flush(batch)
                batch = []
                last_flush = now

        if batch:
            self._flush(batch)

    def _flush(self, batch: Iterable[Event]) -> None:
        rows = []
        for event in batch:
            rows.append(
                {
                    "ts": _parse_ts(event.ts),
                    "pid": event.pid,
                    "process_name": event.process_name,
                    "process_path": event.process_path,
                    "user_name": event.user,
                    "direction": event.direction,
                    "protocol": event.protocol,
                    "local_ip": event.local_ip,
                    "local_port": event.local_port,
                    "remote_ip": event.remote_ip,
                    "remote_port": event.remote_port,
                    "state": event.state,
                    "is_public": 1 if event.is_public else 0,
                    "remote_country": event.remote_country,
                    "remote_region": event.remote_region,
                    "remote_city": event.remote_city,
                    "remote_org": event.remote_org,
                    "remote_asn": event.remote_asn,
                    "remote_hostname": event.remote_hostname,
                    "remote_loc": event.remote_loc,
                    "remote_timezone": event.remote_timezone,
                    "threat_sources": ",".join(event.threat_sources),
                    "threat_score": event.threat_score,
                }
            )
        if not rows:
            return
        try:
            with self._engine.begin() as conn:
                conn.execute(self._table.insert(), rows)
        except Exception as exc:
            logging.warning("db insert failed: %s", exc)

    def _retention_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._cleanup_old()
            except Exception as exc:
                logging.warning("db retention cleanup failed: %s", exc)
            self._stop_event.wait(3600)

    def _cleanup_old(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        sql = text("DELETE FROM events WHERE ts < :cutoff")
        with self._engine.begin() as conn:
            conn.execute(sql, {"cutoff": cutoff})


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", "").strip()
