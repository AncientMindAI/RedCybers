# RedCybers

Windows-only real-time network telemetry with a browser UI.

## Structure
- `backend/` FastAPI service + collectors
- `frontend/` React UI
- `docker-compose.yml` Grafana + PostgreSQL
- `grafana/` provisioning + dashboard

## Quick Start (dev)
Backend:
```
cd backend
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python -m app.main --auto-port
```

Frontend:
```
cd frontend
npm install
.\scripts\dev.ps1
```

## PostgreSQL + Grafana (Docker)
```
docker compose up -d
```
- Grafana: `http://localhost:3000` (admin / admin)
- Postgres: `localhost:5432`

Grafana auto-imports `RedCybers Overview` on startup.

Set backend DB connection:
```
setx DATABASE_URL "postgresql+psycopg2://redcybers:redcybers@localhost:5432/redcybers"
setx REDCYBERS_RETENTION_DAYS "90"
```
Restart backend after setting env vars.

## API
- `GET /health`
- `GET /summary`
- `GET /history`
- `GET /query` (filters: `process_name`, `remote_ip`, `country`, `threat_min`, `start_ts`, `end_ts`)
- `GET /export/xlsx`
- `POST /config`
- `WS /stream`

## Optional Environment Variables
Backend:
- `DATABASE_URL` (PostgreSQL)
- `REDCYBERS_RETENTION_DAYS`
- `IPINFO_API_KEY` (ipinfo.io enrichment)
- `ABUSEIPDB_API_KEY`
- `ABUSEIPDB_CONFIDENCE_MIN` (default 75)
- `ABUSEIPDB_LIMIT` (default 100000)
- `OTX_API_KEY`
- `OTX_EXPORT_URL`
- `FEODO_URL`
- `THREATFOX_API_KEY`
- `THREATFOX_DAYS` (default 1)
- `NETWATCH_PORT_FILE` (override port file path)

Frontend:
- `VITE_API_PORT`
