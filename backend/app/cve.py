from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional


@dataclass
class CVERecord:
    cve_id: str
    published: str
    updated: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: str
    cwe_ids: str
    vendors: str
    products: str
    references: str
    raw_json: str


def _pick_description(data: Dict[str, object]) -> str:
    cna = _get_cna(data)
    for item in cna.get("descriptions", []) if isinstance(cna, dict) else []:
        if str(item.get("lang", "")).lower() == "en":
            return str(item.get("value", ""))
    return ""


def _get_cna(data: Dict[str, object]) -> Dict[str, object]:
    containers = data.get("containers") or {}
    if isinstance(containers, dict):
        return containers.get("cna") or {}
    return {}


def _metrics_list(cna: Dict[str, object]) -> List[Dict[str, object]]:
    metrics = cna.get("metrics")
    if isinstance(metrics, list):
        return metrics
    return []


def _cvss_from_metrics(metrics: List[Dict[str, object]]) -> tuple[float, str, str]:
    score = 0.0
    vector = ""
    severity = ""
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0"):
            data = metric.get(key)
            if not isinstance(data, dict):
                continue
            base = float(data.get("baseScore", 0.0))
            if base >= score:
                score = base
                vector = str(data.get("vectorString", ""))
                severity = str(data.get("baseSeverity", ""))
    return score, vector, severity


def _cwe_ids(cna: Dict[str, object]) -> str:
    result = []
    for item in cna.get("problemTypes", []) if isinstance(cna, dict) else []:
        for desc in item.get("descriptions", []) if isinstance(item, dict) else []:
            cwe_id = str(desc.get("cweId", "") or desc.get("value", "")).strip()
            if cwe_id and cwe_id not in result:
                result.append(cwe_id)
    return ",".join(result)


def _affected(cna: Dict[str, object]) -> tuple[str, str]:
    vendors = []
    products = []
    for item in cna.get("affected", []) if isinstance(cna, dict) else []:
        vendor = str(item.get("vendor", "")).strip()
        product = str(item.get("product", "")).strip()
        if vendor and vendor not in vendors:
            vendors.append(vendor)
        if product and product not in products:
            products.append(product)
    return ",".join(vendors), ",".join(products)


def _references(cna: Dict[str, object]) -> str:
    refs = []
    for item in cna.get("references", []) if isinstance(cna, dict) else []:
        url = str(item.get("url", "")).strip()
        if url and url not in refs:
            refs.append(url)
    return ",".join(refs)


def _title(cna: Dict[str, object]) -> str:
    title = cna.get("title") if isinstance(cna, dict) else ""
    return str(title or "")


def parse_cve(data: Dict[str, object]) -> Optional[CVERecord]:
    meta = data.get("cveMetadata") or {}
    cve_id = str(meta.get("cveId", "")).strip()
    if not cve_id:
        return None
    published = str(meta.get("datePublished", "") or meta.get("dateReserved", "") or "")
    updated = str(meta.get("dateUpdated", "") or "")
    cna = _get_cna(data)
    desc = _pick_description(data)
    score, vector, severity = _cvss_from_metrics(_metrics_list(cna))
    cwe = _cwe_ids(cna)
    vendors, products = _affected(cna)
    refs = _references(cna)
    title = _title(cna)
    return CVERecord(
        cve_id=cve_id,
        published=published,
        updated=updated,
        title=title,
        description=desc,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cwe_ids=cwe,
        vendors=vendors,
        products=products,
        references=refs,
        raw_json=json.dumps(data),
    )


def _iter_cve_files(base_path: str) -> Iterable[str]:
    for root, _, files in os.walk(base_path):
        for name in files:
            if name.lower().endswith(".json") and name.startswith("CVE-"):
                yield os.path.join(root, name)


def import_cves_from_path(base_path: str, limit: int = 2000) -> List[CVERecord]:
    records: List[CVERecord] = []
    if not os.path.isdir(base_path):
        return records
    for path in _iter_cve_files(base_path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            continue
        record = parse_cve(data)
        if record:
            records.append(record)
        if len(records) >= limit:
            break
    return records
