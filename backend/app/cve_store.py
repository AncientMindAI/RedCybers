from __future__ import annotations

import logging
from typing import Dict, List

from sqlalchemy import Column, Float, MetaData, String, Table, Text, create_engine, text
from sqlalchemy.engine import Engine

from .cve import CVERecord


class CVEStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url
        self._engine: Engine = create_engine(database_url, pool_pre_ping=True)
        self._meta = MetaData()
        self._table = Table(
            "cves",
            self._meta,
            Column("cve_id", String(32), primary_key=True),
            Column("published", String(64)),
            Column("updated", String(64)),
            Column("title", Text),
            Column("description", Text),
            Column("severity", String(32)),
            Column("cvss_score", Float),
            Column("cvss_vector", String(128)),
            Column("cwe_ids", Text),
            Column("vendors", Text),
            Column("products", Text),
            Column("reference_urls", Text),
            Column("raw_json", Text),
        )

    def start(self) -> None:
        self._meta.create_all(self._engine)
        self._ensure_columns()

    def stop(self) -> None:
        return None

    def upsert(self, records: List[CVERecord]) -> int:
        if not records:
            return 0
        rows = []
        for record in records:
            row = dict(record.__dict__)
            row["reference_urls"] = row.pop("references", "")
            rows.append(row)
        try:
            with self._engine.begin() as conn:
                for row in rows:
                    sql = text(
                        """
                        INSERT INTO cves (cve_id, published, updated, title, description, severity, cvss_score, cvss_vector,
                                          cwe_ids, vendors, products, reference_urls, raw_json)
                        VALUES (:cve_id, :published, :updated, :title, :description, :severity, :cvss_score, :cvss_vector,
                                :cwe_ids, :vendors, :products, :reference_urls, :raw_json)
                        ON CONFLICT (cve_id) DO UPDATE SET
                            published = EXCLUDED.published,
                            updated = EXCLUDED.updated,
                            title = EXCLUDED.title,
                            description = EXCLUDED.description,
                            severity = EXCLUDED.severity,
                            cvss_score = EXCLUDED.cvss_score,
                            cvss_vector = EXCLUDED.cvss_vector,
                            cwe_ids = EXCLUDED.cwe_ids,
                            vendors = EXCLUDED.vendors,
                            products = EXCLUDED.products,
                            reference_urls = EXCLUDED.reference_urls,
                            raw_json = EXCLUDED.raw_json
                        """
                    )
                    conn.execute(sql, row)
            return len(rows)
        except Exception as exc:
            logging.warning("cve upsert failed: %s", exc)
            return 0

    def search(self, query: str = "", severity_min: float = 0.0, limit: int = 100) -> List[Dict[str, object]]:
        q = (query or "").strip()
        params: Dict[str, object] = {"limit": limit, "severity_min": severity_min}
        where = "1=1"
        if q:
            where = "(cve_id ILIKE :q OR title ILIKE :q OR description ILIKE :q)"
            params["q"] = f"%{q}%"
        if severity_min:
            where += " AND cvss_score >= :severity_min"
        sql = text(
            f"""
            SELECT cve_id, published, updated, title, severity, cvss_score, cwe_ids, vendors, products
            FROM cves
            WHERE {where}
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT :limit
            """
        )
        with self._engine.connect() as conn:
            rows = conn.execute(sql, params).mappings().all()
        return [dict(r) for r in rows]

    def match_for_process(self, name: str, min_sev: str = "HIGH") -> List[Dict[str, object]]:
        q = name.strip()
        if not q:
            return []
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_rank = order.get(min_sev.upper(), 0)
        allowed = [sev for sev, rank in order.items() if rank >= min_rank]
        params: Dict[str, object] = {"q": f"%{q}%", "limit": 20, "severities": tuple(allowed)}
        sql = text(
            """
            SELECT cve_id, severity, cvss_score
            FROM cves
            WHERE (vendors ILIKE :q OR products ILIKE :q)
              AND severity = ANY(:severities)
            ORDER BY cvss_score DESC NULLS LAST
            LIMIT :limit
            """
        )
        with self._engine.connect() as conn:
            rows = conn.execute(sql, params).mappings().all()
        return [dict(r) for r in rows]

    def stats(self) -> Dict[str, object]:
        sql = text(
            """
            SELECT severity, COUNT(*) as count
            FROM cves
            GROUP BY severity
            ORDER BY count DESC
            """
        )
        with self._engine.connect() as conn:
            rows = conn.execute(sql).mappings().all()
        return {"by_severity": [dict(r) for r in rows]}

    def _ensure_columns(self) -> None:
        columns = [
            ("reference_urls", "TEXT"),
        ]
        for name, col_type in columns:
            try:
                sql = text(f"ALTER TABLE cves ADD COLUMN IF NOT EXISTS {name} {col_type}")
                with self._engine.begin() as conn:
                    conn.execute(sql)
            except Exception as exc:
                logging.debug("column ensure failed for %s: %s", name, exc)
