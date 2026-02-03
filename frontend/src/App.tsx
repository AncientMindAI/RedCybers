import { Fragment, useEffect, useMemo, useRef, useState } from "react";

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
  remote_region?: string;
  remote_city?: string;
  remote_org?: string;
  remote_asn?: string;
  remote_hostname?: string;
  remote_loc?: string;
  remote_timezone?: string;
  threat_sources?: string[];
  threat_score?: number;
};

type FeedStatus = {
  name: string;
  last_count: number;
  last_error: string;
  next_run_in: number;
};

type Health = {
  collector: string;
  privileged: boolean;
  events_total: number;
  events_per_sec: number;
  uptime_sec: number;
  host?: string;
  port?: number;
  feeds?: FeedStatus[];
};

type Summary = {
  top_public_apps: { app: string; count: number; unique_public_ips: number }[];
  top_countries: { country: string; count: number }[];
  public_events: number;
  threat_hits: number;
  alerts: {
    ts: string;
    process_name: string;
    remote_ip: string;
    remote_country?: string;
    threat_sources: string[];
    threat_score: number;
  }[];
};

type ConfigPayload = {
  ipinfo_key?: string;
  abuseipdb_key?: string;
  otx_key?: string;
  threatfox_key?: string;
  threatfox_days?: number;
  abuseipdb_confidence_min?: string;
  abuseipdb_limit?: string;
  feodo_url?: string;
  otx_export_url?: string;
};

const API_PORT = (import.meta as any).env?.VITE_API_PORT ?? "8787";
const API_URL = `http://127.0.0.1:${API_PORT}`;
const WS_URL = `ws://127.0.0.1:${API_PORT}/stream`;

export default function App() {
  const [page, setPage] = useState<"realtime" | "insights" | "settings">("realtime");
  const [events, setEvents] = useState<EventItem[]>([]);
  const [paused, setPaused] = useState(false);
  const [filter, setFilter] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const [config, setConfig] = useState<ConfigPayload>({});
  const [saveStatus, setSaveStatus] = useState<string>("");
  const wsRef = useRef<WebSocket | null>(null);
  const [wsStatus, setWsStatus] = useState<"connecting" | "connected" | "failed">("connecting");

  useEffect(() => {
    const load = () => {
      fetch(`${API_URL}/health`).then(r => r.json()).then(setHealth).catch(() => null);
      fetch(`${API_URL}/summary`).then(r => r.json()).then(setSummary).catch(() => null);
      fetch(`${API_URL}/config`).then(r => r.json()).then(setConfig).catch(() => null);
    };
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (paused || page !== "realtime") return;

    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;
    setWsStatus("connecting");

    ws.onopen = () => setWsStatus("connected");
    ws.onerror = () => setWsStatus("failed");

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
      if (wsStatus !== "failed") setWsStatus("failed");
    };

    return () => ws.close();
  }, [paused, page]);

  useEffect(() => {
    if (page !== "realtime") return;
    if (wsStatus === "connected") return;
    const id = setInterval(() => {
      fetch(`${API_URL}/history?limit=200`)
        .then((r) => r.json())
        .then((data) => Array.isArray(data) && setEvents(data.reverse()))
        .catch(() => null);
    }, 2000);
    return () => clearInterval(id);
  }, [page, wsStatus]);

  const filtered = useMemo(() => {
    if (!filter.trim()) return events;
    const f = filter.toLowerCase();
    return events.filter(e =>
      e.process_name.toLowerCase().includes(f) ||
      e.remote_ip.toLowerCase().includes(f) ||
      String(e.remote_port).includes(f) ||
      (e.remote_country ?? "").toLowerCase().includes(f) ||
      (e.remote_org ?? "").toLowerCase().includes(f)
    );
  }, [events, filter]);

  const exportXlsx = () => {
    window.open(`${API_URL}/export/xlsx`, "_blank");
  };

  const toggleRow = (key: string) => {
    setExpandedKey(prev => (prev === key ? null : key));
  };

  const rowKey = (e: EventItem, index: number) => `${e.ts}-${e.pid}-${e.remote_ip}-${index}`;

  const saveConfig = async () => {
    setSaveStatus("Saving...");
    try {
      const resp = await fetch(`${API_URL}/config`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
      });
      if (!resp.ok) throw new Error("Save failed");
      const data = await resp.json();
      setConfig(data);
      setSaveStatus("Saved");
      setTimeout(() => setSaveStatus(""), 2000);
    } catch {
      setSaveStatus("Save failed");
    }
  };

  const updateConfig = (key: keyof ConfigPayload, value: string | number) => {
    setConfig(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="min-h-screen bg-bg text-white">
      <div className="bg-grid" />
      <header className="sticky top-0 z-10 border-b border-white/10 bg-black/30 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div>
            <div className="text-sm uppercase tracking-[0.3em] text-white/60">RedCybers</div>
            <h1 className="text-2xl font-semibold">Live Threat Telemetry</h1>
            <div className="text-xs text-white/50">Connected to backend: {health?.host ?? "127.0.0.1"}:{health?.port ?? API_PORT}</div>
          </div>
          <div className="flex items-center gap-3">
            <button className={`tab ${page === "realtime" ? "tab-active" : ""}`} onClick={() => setPage("realtime")}>Real-time</button>
            <button className={`tab ${page === "insights" ? "tab-active" : ""}`} onClick={() => setPage("insights")}>Insights</button>
            <button className={`tab ${page === "settings" ? "tab-active" : ""}`} onClick={() => setPage("settings")}>Settings</button>
            <span className="badge">collector: {health?.collector ?? "-"}</span>
            <span className={`badge ${health?.privileged ? "badge-ok" : "badge-warn"}`}>
              {health?.privileged ? "privileged" : "unprivileged"}
            </span>
            <span className="badge">eps: {health?.events_per_sec?.toFixed(1) ?? "-"}</span>
            <span className={`badge ${wsStatus === "connected" ? "badge-ok" : "badge-warn"}`}>
              ws: {wsStatus}
            </span>
          </div>
        </div>
      </header>

      {page === "settings" ? (
        <main className="mx-auto max-w-3xl px-6 py-8">
          <section className="panel space-y-6">
            <div>
              <div className="panel-title">API Keys</div>
              <div className="field">
                <label>IPinfo Key</label>
                <input className="input" value={config.ipinfo_key || ""} onChange={(e) => updateConfig("ipinfo_key", e.target.value)} />
              </div>
              <div className="field">
                <label>AbuseIPDB Key</label>
                <input className="input" value={config.abuseipdb_key || ""} onChange={(e) => updateConfig("abuseipdb_key", e.target.value)} />
              </div>
              <div className="field">
                <label>OTX Key</label>
                <input className="input" value={config.otx_key || ""} onChange={(e) => updateConfig("otx_key", e.target.value)} />
              </div>
              <div className="field">
                <label>ThreatFox Key</label>
                <input className="input" value={config.threatfox_key || ""} onChange={(e) => updateConfig("threatfox_key", e.target.value)} />
              </div>
            </div>

            <div>
              <div className="panel-title">Feed Options</div>
              <div className="field">
                <label>ThreatFox Days</label>
                <input className="input" type="number" min={1} max={7} value={config.threatfox_days ?? 1} onChange={(e) => updateConfig("threatfox_days", Number(e.target.value))} />
              </div>
              <div className="field">
                <label>AbuseIPDB Confidence Min</label>
                <input className="input" value={config.abuseipdb_confidence_min || "75"} onChange={(e) => updateConfig("abuseipdb_confidence_min", e.target.value)} />
              </div>
              <div className="field">
                <label>AbuseIPDB Limit</label>
                <input className="input" value={config.abuseipdb_limit || "100000"} onChange={(e) => updateConfig("abuseipdb_limit", e.target.value)} />
              </div>
              <div className="field">
                <label>Feodo URL (optional)</label>
                <input className="input" value={config.feodo_url || ""} onChange={(e) => updateConfig("feodo_url", e.target.value)} />
              </div>
              <div className="field">
                <label>OTX Export URL (optional)</label>
                <input className="input" value={config.otx_export_url || ""} onChange={(e) => updateConfig("otx_export_url", e.target.value)} />
              </div>
            </div>

            <div className="row">
              <button className="btn" onClick={saveConfig}>Save Settings</button>
              <span className="muted">{saveStatus}</span>
            </div>
            <div className="muted text-xs">
              Settings are stored locally in `.redcybers-config.json` and applied live. Restart backend if needed.
            </div>
          </section>
        </main>
      ) : page === "insights" ? (
        <main className="mx-auto grid max-w-6xl gap-6 px-6 py-8 lg:grid-cols-[300px_1fr]">
          <aside className="panel space-y-6">
            <div>
              <div className="panel-title">Insights Overview</div>
              <div className="space-y-2 text-sm text-white/70">
                <div>Public Events: {summary?.public_events ?? 0}</div>
                <div>Threat Hits: {summary?.threat_hits ?? 0}</div>
                <div>Events (total): {health?.events_total ?? 0}</div>
                <div>Events/sec: {health?.events_per_sec?.toFixed(1) ?? "-"}</div>
              </div>
              <div className="mt-4">
                <button className="btn btn-outline" onClick={exportXlsx}>Export XLSX</button>
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

            <div>
              <div className="panel-title">Top Countries</div>
              <div className="space-y-2 text-sm">
                {(summary?.top_countries ?? []).map((item, idx) => (
                  <div key={idx} className="row">
                    <span>{item.country}</span>
                    <span className="muted">{item.count}</span>
                  </div>
                ))}
                {(!summary?.top_countries || summary.top_countries.length === 0) && (
                  <div className="muted">No geo data yet</div>
                )}
              </div>
            </div>
          </aside>

          <section className="panel space-y-6">
            <div>
              <div className="panel-title">Alert Feed</div>
              <div className="space-y-2 text-sm">
                {(summary?.alerts ?? []).map((alert, idx) => (
                  <div key={idx} className="alert-row">
                    <div>
                      <div className="alert-title">{alert.process_name} → {alert.remote_ip}</div>
                      <div className="muted">{alert.remote_country || "-"} • {alert.threat_sources.join(",")}</div>
                    </div>
                    <div className="alert-score">{alert.threat_score}</div>
                  </div>
                ))}
                {(!summary?.alerts || summary.alerts.length === 0) && (
                  <div className="muted">No threat alerts yet</div>
                )}
              </div>
            </div>

            <div>
              <div className="panel-title">Feed Status</div>
              <div className="space-y-2 text-sm">
                {(health?.feeds ?? []).map((feed, idx) => (
                  <div key={idx} className="feed-row">
                    <div>
                      <div className="feed-title">{feed.name}</div>
                      <div className="muted">
                        {feed.last_error ? `error: ${feed.last_error}` : `${feed.last_count} IPs`}
                      </div>
                    </div>
                    <div className="feed-next">{feed.next_run_in}s</div>
                  </div>
                ))}
                {(!health?.feeds || health.feeds.length === 0) && (
                  <div className="muted">No feeds configured</div>
                )}
              </div>
            </div>
          </section>
        </main>
      ) : (
        <main className="mx-auto grid max-w-6xl gap-6 px-6 py-8 lg:grid-cols-[300px_1fr]">
          <aside className="panel space-y-6">
            <div>
              <div className="panel-title">Real-time Controls</div>
              <input
                className="input"
                placeholder="process / ip / port / country / org"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
              <div className="mt-4 space-y-2 text-sm text-white/70">
                <div>Status: {health?.collector ?? "-"}</div>
                <div>Events: {health?.events_total ?? 0}</div>
                <div>Uptime: {health ? Math.floor(health.uptime_sec) + "s" : "-"}</div>
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
          </aside>

          <section className="panel">
            <div className="panel-title">Real-time Monitoring</div>
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
                    <th>Org</th>
                    <th>Threats</th>
                    <th>Score</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((e, i) => {
                    const key = rowKey(e, i);
                    const expanded = expandedKey === key;
                    return (
                      <Fragment key={key}>
                        <tr className="row-click" onClick={() => toggleRow(key)}>
                          <td>{new Date(e.ts).toLocaleTimeString()}</td>
                          <td>{e.process_name}</td>
                          <td>{e.pid}</td>
                          <td>{e.protocol}</td>
                          <td>{e.local_ip}:{e.local_port}</td>
                          <td>{e.remote_ip}:{e.remote_port}</td>
                          <td>{e.remote_country || "-"}</td>
                          <td>{e.remote_org || "-"}</td>
                          <td>{(e.threat_sources && e.threat_sources.length > 0) ? e.threat_sources.join(",") : "-"}</td>
                          <td>{e.threat_score ?? 0}</td>
                          <td>{e.state}</td>
                        </tr>
                        {expanded && (
                          <tr className="row-detail">
                            <td colSpan={11}>
                              <div className="detail-grid">
                                <div><span className="muted">Region:</span> {e.remote_region || "-"}</div>
                                <div><span className="muted">City:</span> {e.remote_city || "-"}</div>
                                <div><span className="muted">ASN:</span> {e.remote_asn || "-"}</div>
                                <div><span className="muted">Hostname:</span> {e.remote_hostname || "-"}</div>
                                <div><span className="muted">Loc:</span> {e.remote_loc || "-"}</div>
                                <div><span className="muted">Timezone:</span> {e.remote_timezone || "-"}</div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      )}
    </div>
  );
}
