# RedCybers IDS/IPS (Snort/Suricata) Branch

This branch bootstraps IDS/IPS integration planning for RedCybers.

## Goals
- Capture network alerts from an IDS/IPS engine (Snort or Suricata).
- Normalize alerts into RedCybers events for audit + real-time correlation.
- Store alerts in Postgres for reporting.

## Proposed Integration Options
### Option A — Snort (3.x)
- Run Snort in a container or on host.
- Use JSON alert output (fast/alert_json) and ingest into RedCybers.
- Map signature category to ATT&CK tactic (initial mapping table).

### Option B — Suricata (recommended)
- Suricata has rich JSON (EVE) output and easier parsing.
- EVE logs include flow, DNS, TLS, HTTP metadata for correlation.

## Next Steps (Implementation Plan)
1) Add a lightweight `ids_collector` service to tail Snort/Suricata JSON logs.
2) Create `ids_alerts` table and API endpoints:
   - `GET /ids/alerts`
   - `GET /ids/stats`
3) Add UI tab: IDS/IPS ? Alerts + signature coverage.
4) Correlate IDS alerts with existing MITRE/CVE data.

## Expected Config
- `IDS_ENGINE=snort|suricata`
- `IDS_LOG_PATH=/path/to/alert.json` (Snort) or `eve.json` (Suricata)

---
When you're ready, I can implement Option A or B.
