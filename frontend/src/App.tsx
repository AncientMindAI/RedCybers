import { useEffect, useMemo, useRef, useState } from "react";

type EventItem = {
  ts: string;
  pid: number;
  process_name: string;
  process_path: string;
  user: string;
  direction: string;
  protocol: string;
  local_ip: string;
  local_port: number;
  remote_ip: string;
  remote_port: number;
  state: string;
  is_public?: boolean;
  remote_country?: string;
  remote_org?: string;
  threat_sources?: string[];
};

type Health = {
  collector: string;
  privileged: boolean;
  events_total: number;
  events_per_sec: number;
  uptime_sec: number;
  host?: string;
  port?: number;
};

type Summary = {
  top_public_apps: { app: string; count: number; unique_public_ips: number }[];
  public_events: number;
  threat_hits: number;
};

const API_PORT = (import.meta as any).env?.VITE_API_PORT ?? "8787";
const API_URL = `http://127.0.0.1:${API_PORT}`;
const WS_URL = `ws://127.0.0.1:${API_PORT}/stream`;

export default function App() {
  const [events, setEvents] = useState<EventItem[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const load = () => {
      fetch(`${API_URL}/health`).then(r => r.json()).then(setHealth).catch(() => null);
      fetch(`${API_URL}/summary`).then(r => r.json()).then(setSummary).catch(() => null);
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (paused) return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onmessage = (msg) => {
      try {
        const payload = JSON.parse(msg.data as string);
        if (payload.type === "event") {
          setEvents((prev) => {
            const next = [payload.data as EventItem, ...prev];
            return next.slice(0, 200);
          });
        }
      } catch {
        // ignore malformed frames
      }
    };

    ws.onclose = () => {
      wsRef.current = null;
    };

    return () => ws.close();
  }, [paused]);

  const filtered = useMemo(() => {
    if (!filter.trim()) return events;
    const f = filter.toLowerCase();
    return events.filter(e =>
      e.process_name.toLowerCase().includes(f) ||
      e.remote_ip.toLowerCase().includes(f) ||
      String(e.remote_port).includes(f) ||
      (e.remote_country ?? "").toLowerCase().includes(f)
    );
  }, [events, filter]);

  const exportXlsx = () => {
    window.open(`${API_URL}/export/xlsx`, "_blank");
  };

  return (
    <div className="min-h-screen bg-bg text-white">
      <div className="bg-grid" />
      <header className="sticky top-0 z-10 border-b border-white/10 bg-black/30 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div>
            <div className="text-sm uppercase tracking-[0.3em] text-white/60">RedCybers</div>
            <h1 className="text-2xl font-semibold">Live Threat Telemetry</h1>
          </div>
          <div className="flex items-center gap-3">
            <span className="badge">collector: {health?.collector ?? "-"}</span>
            <span className={`badge ${health?.privileged ? "badge-ok" : "badge-warn"}`}>
              {health?.privileged ? "privileged" : "unprivileged"}
            </span>
            <span className="badge">eps: {health?.events_per_sec?.toFixed(1) ?? "-"}</span>
          </div>
        </div>
      </header>

      <main className="mx-auto grid max-w-6xl gap-6 px-6 py-8 lg:grid-cols-[280px_1fr]">
        <aside className="panel space-y-6">
          <div>
            <div className="panel-title">Filters</div>
            <input
              className="input"
              placeholder="process / ip / port / country"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <div className="mt-4 space-y-2 text-sm text-white/70">
              <div>Status: {health?.collector ?? "-"}</div>
              <div>Events: {health?.events_total ?? 0}</div>
              <div>Uptime: {health ? Math.floor(health.uptime_sec) + "s" : "-"}</div>
              <div>Public Events: {summary?.public_events ?? 0}</div>
              <div>Threat Hits: {summary?.threat_hits ?? 0}</div>
            </div>
            <div className="mt-4 flex gap-2">
              <button className="btn" onClick={() => setPaused(p => !p)}>
                {paused ? "Resume" : "Pause"}
              </button>
              <button className="btn btn-outline" onClick={exportXlsx}>
                Export XLSX
              </button>
            </div>
          </div>

          <div>
            <div className="panel-title">Top Public Apps</div>
            <div className="space-y-2 text-sm">
              {(summary?.top_public_apps ?? []).map((item, idx) => (
                <div key={idx} className="row">
                  <span>{item.app}</span>
                  <span className="muted">{item.count} / {item.unique_public_ips}</span>
                </div>
              ))}
              {(!summary?.top_public_apps || summary.top_public_apps.length === 0) && (
                <div className="muted">No public connections yet</div>
              )}
            </div>
          </div>
        </aside>

        <section className="panel">
          <div className="panel-title">Active Connections</div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>App</th>
                  <th>PID</th>
                  <th>Proto</th>
                  <th>Local</th>
                  <th>Remote</th>
                  <th>Country</th>
                  <th>Threats</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, i) => (
                  <tr key={i}>
                    <td>{new Date(e.ts).toLocaleTimeString()}</td>
                    <td>{e.process_name}</td>
                    <td>{e.pid}</td>
                    <td>{e.protocol}</td>
                    <td>{e.local_ip}:{e.local_port}</td>
                    <td>{e.remote_ip}:{e.remote_port}</td>
                    <td>{e.remote_country || "-"}</td>
                    <td>{(e.threat_sources && e.threat_sources.length > 0) ? e.threat_sources.join(",") : "-"}</td>
                    <td>{e.state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}
