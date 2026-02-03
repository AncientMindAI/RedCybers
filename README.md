# RedCybers

Windows-only real-time network telemetry with a browser UI.

## Structure
- `backend/` FastAPI service + collectors
- `frontend/` React UI

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

## Optional Environment Variables
Backend:
- `IPINFO_API_KEY` (ipinfo.io enrichment)
- `ABUSEIPDB_API_KEY`
- `ABUSEIPDB_CONFIDENCE_MIN` (default 75)
- `ABUSEIPDB_LIMIT` (default 100000)
- `OTX_API_KEY`
- `OTX_EXPORT_URL`
- `FEODO_URL`
- `THREATFOX_URL`
- `NETWATCH_PORT_FILE` (override port file path)

Frontend:
- `VITE_API_PORT`
