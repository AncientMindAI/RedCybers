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
            Column("references", Text),
            Column("raw_json", Text),
        )

    def start(self) -> None:
        self._meta.create_all(self._engine)

    def stop(self) -> None:
        return None

    def upsert(self, records: List[CVERecord]) -> int:
        if not records:
            return 0
        rows = [record.__dict__ for record in records]
        try:
            with self._engine.begin() as conn:
                for row in rows:
                    sql = text(
                        """
                        INSERT INTO cves (cve_id, published, updated, title, description, severity, cvss_score, cvss_vector,
                                          cwe_ids, vendors, products, references, raw_json)
                        VALUES (:cve_id, :published, :updated, :title, :description, :severity, :cvss_score, :cvss_vector,
                                :cwe_ids, :vendors, :products, :references, :raw_json)
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
                            references = EXCLUDED.references,
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
