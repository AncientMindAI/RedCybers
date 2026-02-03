# Backend (RedCybers)

FastAPI service that streams live connection events over WebSocket.

Collector selection order:
1) ETW (preferred, admin required)
2) psutil polling (fallback)

Run:
```
python -m app.main --auto-port
```

Endpoints:
- `/health`
- `/summary`
- `/history`
- `/export/xlsx`
- `WS /stream`
