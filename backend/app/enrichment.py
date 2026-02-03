from __future__ import annotations

import ipaddress
import logging
import os
import queue
import re
import threading
import time
from typing import Dict, List, Optional, Set

import requests

from .models import Event

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_ipv4(text: str) -> Set[str]:
    ips = set()
    for match in IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(match)
        except ValueError:
            continue
        ips.add(match)
    return ips


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


def _score_event(event: Event) -> int:
    score = 0
    if event.is_public:
        score += 10
    if event.threat_sources:
        score += 60 + min(20, 10 * len(event.threat_sources))
    if event.remote_org:
        score += 5
    if event.remote_asn:
        score += 5
    return min(score, 100)


class ThreatFeed:
    def __init__(
        self,
        name: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        interval_sec: int = 3600,
        mode: str = "text",
        days: int = 1,
    ) -> None:
        self.name = name
        self.url = url
        self.headers = headers or {}
        self.interval_sec = interval_sec
        self.mode = mode
        self.days = days
        self.next_run = 0.0
        self.last_count = 0
        self.last_error = ""


class ThreatFeedManager:
    def __init__(self, stop_event: threading.Event) -> None:
        self._stop_event = stop_event
        self._lock = threading.Lock()
        self._feeds: List[ThreatFeed] = []
        self._ip_sets: Dict[str, Set[str]] = {}
        self._thread: Optional[threading.Thread] = None

    def configure(self) -> None:
        self._feeds = []
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        otx_key = os.getenv("OTX_API_KEY", "").strip()
        threatfox_key = os.getenv("THREATFOX_API_KEY", "").strip()
        abuse_min = os.getenv("ABUSEIPDB_CONFIDENCE_MIN", "75").strip()
        abuse_limit = os.getenv("ABUSEIPDB_LIMIT", "100000").strip()
        threatfox_days = int(os.getenv("THREATFOX_DAYS", "1").strip() or 1)

        if abuse_key:
            url = (
                "https://api.abuseipdb.com/api/v2/blacklist"
                f"?confidenceMinimum={abuse_min}&limit={abuse_limit}&plaintext=true"
            )
            headers = {"Key": abuse_key, "Accept": "text/plain"}
            self._feeds.append(ThreatFeed("AbuseIPDB", url, headers=headers))
        else:
            logging.info("AbuseIPDB disabled (missing ABUSEIPDB_API_KEY)")

        if otx_key:
            url = os.getenv("OTX_EXPORT_URL", "https://otx.alienvault.com/api/v1/indicators/export")
            headers = {"X-OTX-API-KEY": otx_key}
            self._feeds.append(ThreatFeed("OTX", url, headers=headers))
        else:
            logging.info("OTX disabled (missing OTX_API_KEY)")

        feodo_url = os.getenv(
            "FEODO_URL",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        )
        self._feeds.append(ThreatFeed("Feodo", feodo_url))

        if threatfox_key:
            self._feeds.append(
                ThreatFeed(
                    "ThreatFox",
                    "https://threatfox-api.abuse.ch/api/v1/",
                    headers={"Auth-Key": threatfox_key},
                    mode="threatfox_api",
                    days=threatfox_days,
                )
            )
        else:
            logging.info("ThreatFox disabled (missing THREATFOX_API_KEY)")

    def start(self) -> None:
        self.configure()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            now = time.time()
            for feed in self._feeds:
                if now < feed.next_run:
                    continue
                try:
                    ips = self._fetch_feed(feed)
                    with self._lock:
                        self._ip_sets[feed.name] = ips
                    feed.last_count = len(ips)
                    feed.last_error = ""
                    feed.next_run = now + feed.interval_sec
                    logging.info("feed updated: %s (%s IPs)", feed.name, feed.last_count)
                except Exception as exc:
                    feed.last_error = str(exc)
                    feed.next_run = now + max(300, feed.interval_sec // 4)
                    logging.warning("feed update failed: %s (%s)", feed.name, exc)
            self._stop_event.wait(30)

    def _fetch_feed(self, feed: ThreatFeed) -> Set[str]:
        if feed.mode == "threatfox_api":
            return self._fetch_threatfox(feed)
        resp = requests.get(feed.url, headers=feed.headers, timeout=20)
        resp.raise_for_status()
        return _extract_ipv4(resp.text)

    def _fetch_threatfox(self, feed: ThreatFeed) -> Set[str]:
        payload = {"query": "get_iocs", "days": max(1, min(feed.days, 7))}
        resp = requests.post(feed.url, headers=feed.headers, json=payload, timeout=20)
        resp.raise_for_status()
        data = resp.json() if resp.text else {}
        if data.get("query_status") != "ok":
            return set()
        ips: Set[str] = set()
        for item in data.get("data", []):
            ioc = str(item.get("ioc", ""))
            if not ioc:
                continue
            ip = ioc.split(":", 1)[0].strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            ips.add(ip)
        return ips

    def check_ip(self, ip: str) -> List[str]:
        hits: List[str] = []
        with self._lock:
            for name, ips in self._ip_sets.items():
                if ip in ips:
                    hits.append(name)
        return hits

    def status(self) -> List[Dict[str, object]]:
        data = []
        for feed in self._feeds:
            data.append(
                {
                    "name": feed.name,
                    "last_count": feed.last_count,
                    "last_error": feed.last_error,
                    "next_run_in": max(0, int(feed.next_run - time.time())),
                }
            )
        return data


class IpInfoResolver:
    def __init__(self, stop_event: threading.Event) -> None:
        self._stop_event = stop_event
        self._token = os.getenv("IPINFO_API_KEY", "").strip()
        self._queue: queue.Queue[str] = queue.Queue()
        self._cache: Dict[str, Dict[str, object]] = {}
        self._cache_ts: Dict[str, float] = {}
        self._inflight: Set[str] = set()
        self._thread: Optional[threading.Thread] = None
        self._ttl = 24 * 3600

    def start(self) -> None:
        if not self._token:
            logging.info("ipinfo disabled (missing IPINFO_API_KEY)")
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def enqueue(self, ip: str) -> None:
        if not self._token:
            return
        if ip in self._inflight:
            return
        self._inflight.add(ip)
        self._queue.put(ip)

    def get(self, ip: str) -> Optional[Dict[str, object]]:
        if ip not in self._cache:
            return None
        if time.time() - self._cache_ts.get(ip, 0) > self._ttl:
            return None
        return self._cache[ip]

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                ip = self._queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                info = self._fetch(ip)
                if info:
                    self._cache[ip] = info
                    self._cache_ts[ip] = time.time()
            except Exception as exc:
                logging.debug("ipinfo lookup failed for %s: %s", ip, exc)
            finally:
                self._inflight.discard(ip)

    def _fetch(self, ip: str) -> Optional[Dict[str, object]]:
        url = f"https://ipinfo.io/{ip}/json"
        resp = requests.get(url, params={"token": self._token}, timeout=10)
        if resp.status_code == 429:
            time.sleep(2)
            return None
        resp.raise_for_status()
        data = resp.json() if resp.text else {}
        return data


class EnrichmentService:
    def __init__(self, stop_event: threading.Event) -> None:
        self._stop_event = stop_event
        self.threats = ThreatFeedManager(stop_event)
        self.ipinfo = IpInfoResolver(stop_event)

    def start(self) -> None:
        self.threats.start()
        self.ipinfo.start()

    def stop(self) -> None:
        self.threats.stop()
        self.ipinfo.stop()

    def enrich(self, event: Event) -> None:
        event.is_public = is_public_ip(event.remote_ip)
        if event.is_public:
            event.threat_sources = self.threats.check_ip(event.remote_ip)
            cached = self.ipinfo.get(event.remote_ip)
            if cached is None:
                self.ipinfo.enqueue(event.remote_ip)
            else:
                event.remote_country = str(cached.get("country", ""))
                event.remote_region = str(cached.get("region", ""))
                event.remote_city = str(cached.get("city", ""))
                event.remote_org = str(cached.get("org", ""))
                event.remote_asn = str(cached.get("asn", ""))
                event.remote_hostname = str(cached.get("hostname", ""))
                event.remote_loc = str(cached.get("loc", ""))
                event.remote_timezone = str(cached.get("timezone", ""))
        event.threat_score = _score_event(event)
