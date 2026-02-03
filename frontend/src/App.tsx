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
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_technique_id?: string;
  mitre_confidence?: number;
  relevance_score?: number;
  suppressed?: boolean;
  suppression_reason?: string;
  cve_matches?: string[];
  cve_max_severity?: string;
  cve_count?: number;
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
  suppressed_events?: number;
  mitre_tactics?: { tactic: string; count: number }[];
  mitre_techniques?: { technique_id: string; count: number }[];
  mitre_breakdown?: Record<string, { technique_id: string; count: number }[]>;
  cve_high_hits?: number;
  cve_medium_hits?: number;
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
  mitre_min_score?: number;
  suppress_private?: boolean;
  suppress_loopback?: boolean;
  suppress_processes?: string[];
  suppress_ports?: string[];
  cve_source_path?: string;
  cve_import_limit?: number;
  cve_min_year?: number;
  cve_match_enabled?: boolean;
  cve_min_severity?: string;
  cve_match_strict?: boolean;
  ids_enabled?: boolean;
  ids_engine?: string;
  ids_log_path?: string;
  elk_enabled?: boolean;
  elk_logstash_url?: string;
};

const API_PORT = (import.meta as any).env?.VITE_API_PORT ?? "8787";
const API_URL = `http://127.0.0.1:${API_PORT}`;
const WS_URL = `ws://127.0.0.1:${API_PORT}/stream`;
const KIBANA_URL = (import.meta as any).env?.VITE_KIBANA_URL ?? "http://localhost:5601";
const APP_VERSION = (globalThis as any).__APP_VERSION__ ?? "dev";

export default function App() {
  const [page, setPage] = useState<"realtime" | "insights" | "audit" | "vulns" | "ids" | "elk" | "settings">("realtime");
  const [events, setEvents] = useState<EventItem[]>([]);
  const [paused, setPaused] = useState(false);
  const [showSuppressed, setShowSuppressed] = useState(false);
  const [showTimeWait, setShowTimeWait] = useState(false);
  const [onlyEstablished, setOnlyEstablished] = useState(true);
  const [filter, setFilter] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [expandedKey, setExpandedKey] = useState<string | null>(null);
  const [selectedTactic, setSelectedTactic] = useState<string>("");
  const [cveQuery, setCveQuery] = useState("");
  const [cveResults, setCveResults] = useState<Array<Record<string, any>>>([]);
  const [cveStats, setCveStats] = useState<{ by_severity?: { severity: string; count: number }[] }>({});
  const [cveImportStatus, setCveImportStatus] = useState<string>("");
  const [idsAlerts, setIdsAlerts] = useState<Array<Record<string, any>>>([]);
  const [idsStats, setIdsStats] = useState<{ by_classification?: { classification: string; count: number }[]; by_priority?: { priority: number; count: number }[]; total?: number }>({});
  const [config, setConfig] = useState<ConfigPayload>({});
  const [saveStatus, setSaveStatus] = useState<string>("");
  const wsRef = useRef<WebSocket | null>(null);
  const lastNonEmptyFiltered = useRef<EventItem[]>([]);
  const [wsStatus, setWsStatus] = useState<"connecting" | "connected" | "failed">("connecting");
  const epsActive = (health?.events_per_sec ?? 0) > 0.1;
  const [showAbout, setShowAbout] = useState(false);
  const MAX_EVENTS = 2000;
  const eventKey = (e: EventItem) =>
    `${e.ts}|${e.pid}|${e.local_ip}|${e.local_port}|${e.remote_ip}|${e.remote_port}|${e.state}`;
  const mergeEvents = (prev: EventItem[], incoming: EventItem[]) => {
    if (incoming.length === 0) return prev;
    const map = new Map<string, EventItem>();
    for (const item of prev) {
      map.set(eventKey(item), item);
    }
    for (const item of incoming) {
      map.set(eventKey(item), item);
    }
    const merged = Array.from(map.values()).sort((a, b) => b.ts.localeCompare(a.ts));
    return merged.slice(0, MAX_EVENTS);
  };

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
          setEvents((prev) => mergeEvents(prev, [payload.data as EventItem]));
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
      fetch(`${API_URL}/history?limit=2000`)
        .then((r) => r.json())
        .then((data) => {
          if (!Array.isArray(data)) return;
          const incoming = data.reverse();
          setEvents((prev) => mergeEvents(prev, incoming));
        })
        .catch(() => null);
    }, 5000);
    return () => clearInterval(id);
  }, [page, wsStatus]);

  const filtered = useMemo(() => {
    let base = showSuppressed ? events : events.filter(e => !e.suppressed);
    const state = (e: EventItem) => String(e.state || "").toUpperCase();
    if (onlyEstablished) {
      base = base.filter(e => state(e) === "ESTABLISHED");
    } else if (!showTimeWait) {
      base = base.filter(e => state(e) !== "TIME_WAIT");
    }
    if (!filter.trim()) return base;
    const f = filter.toLowerCase();
    return base.filter(e =>
      e.process_name.toLowerCase().includes(f) ||
      e.remote_ip.toLowerCase().includes(f) ||
      String(e.remote_port).includes(f) ||
      (e.remote_country ?? "").toLowerCase().includes(f) ||
      (e.remote_org ?? "").toLowerCase().includes(f) ||
      (e.mitre_technique_id ?? "").toLowerCase().includes(f)
    );
  }, [events, filter, showSuppressed, showTimeWait, onlyEstablished]);

  const visible = useMemo(() => {
    if (filtered.length > 0) {
      lastNonEmptyFiltered.current = filtered;
      return filtered;
    }
    return lastNonEmptyFiltered.current;
  }, [filtered]);

  const exportXlsx = () => {
    window.open(`${API_URL}/export/xlsx`, "_blank");
  };

  const exportPdf = () => {
    window.open(`${API_URL}/export/pdf`, "_blank");
  };

  const searchCves = async () => {
    const qs = new URLSearchParams({ query: cveQuery, limit: "50" });
    const resp = await fetch(`${API_URL}/cve/search?${qs.toString()}`);
    if (!resp.ok) return;
    const data = await resp.json();
    setCveResults(Array.isArray(data) ? data : []);
  };

  const loadCveStats = async () => {
    const resp = await fetch(`${API_URL}/cve/stats`);
    if (!resp.ok) return;
    const data = await resp.json();
    setCveStats(data || {});
  };

  const loadIds = async () => {
    const resp = await fetch(`${API_URL}/ids/alerts?limit=200`);
    if (resp.ok) {
      const data = await resp.json();
      setIdsAlerts(Array.isArray(data) ? data : []);
    }
    const statsResp = await fetch(`${API_URL}/ids/stats`);
    if (statsResp.ok) {
      const data = await statsResp.json();
      setIdsStats(data || {});
    }
  };

  const importCves = async () => {
    setCveImportStatus("Importing...");
    const resp = await fetch(`${API_URL}/cve/import`, { method: "POST" });
    if (!resp.ok) {
      setCveImportStatus("Import failed");
      return;
    }
    const data = await resp.json();
    setCveImportStatus(`Imported ${data.imported ?? 0}`);
    setTimeout(() => setCveImportStatus(""), 2000);
    loadCveStats();
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

  const listValue = (value: string[] | undefined) => {
    if (!value) return "";
    return Array.isArray(value) ? value.join(", ") : String(value);
  };

  return (
    <div className="min-h-screen bg-bg text-white">
      <div className="bg-grid" />
      <header className="sticky top-0 z-10 border-b border-white/10 bg-black/30 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
          <div>
            <div className="flex items-center gap-3">
              <img className="logo" src="/redcybers-logo.png" alt="RedCybers" />
              <div className="text-sm uppercase tracking-[0.3em] text-white/60">RedCybers</div>
            </div>
            <h1 className="text-2xl font-semibold">Live Threat Telemetry</h1>
            <div className="text-xs text-white/50">Connected to backend: {health?.host ?? "127.0.0.1"}:{health?.port ?? API_PORT}</div>
          </div>
          <div className="flex items-center gap-3">
            <div className="nav-group">
              <div className="nav-label">Ops</div>
              <div className="tab-row">
                <button className={`tab ${page === "realtime" ? "tab-active" : ""}`} onClick={() => setPage("realtime")}>Real-time</button>
                <button className={`tab ${page === "elk" ? "tab-active" : ""}`} onClick={() => setPage("elk")}>ELK</button>
                <button className={`tab ${page === "insights" ? "tab-active" : ""}`} onClick={() => setPage("insights")}>Insights</button>
                <button className={`tab ${page === "audit" ? "tab-active" : ""}`} onClick={() => setPage("audit")}>Audit</button>
                <button className={`tab ${page === "vulns" ? "tab-active" : ""}`} onClick={() => { setPage("vulns"); loadCveStats(); }}>Vulns</button>
                <button className={`tab ${page === "ids" ? "tab-active" : ""}`} onClick={() => { setPage("ids"); loadIds(); }}>IDS/IPS</button>
              </div>
            </div>
            <div className="info-box">
              <div className="info-title">Config</div>
              <div className="info-row">collector: {health?.collector ?? "-"}</div>
              <button className="link-pill" onClick={() => setPage("settings")}>Settings</button>
            </div>
            <div className="info-box">
              <div className="info-title">System Health</div>
              <div className={`status-pill ${health?.privileged ? "status-ok" : "status-warn"}`}>
                {health?.privileged ? "privileged" : "unprivileged"}
              </div>
              <div className={`status-pill ${epsActive ? "status-ok" : "status-warn"}`}>
                eps: {health?.events_per_sec?.toFixed(1) ?? "-"}
              </div>
              <div className={`status-pill ${wsStatus === "connected" ? "status-ok" : "status-warn"}`}>
                ws: {wsStatus}
              </div>
            </div>
            <button className="link-pill" onClick={() => setShowAbout((prev) => !prev)}>
              About
            </button>
          </div>
        </div>
      </header>

      {showAbout && (
        <div className="about-banner">
          <div className="about-title">RedCybers</div>
          <div className="about-meta">Version {APP_VERSION}</div>
          <div className="about-meta">Build: {new Date().toISOString()}</div>
        </div>
      )}

      {page === "elk" ? (
        <main className="mx-auto max-w-6xl px-6 py-8">
          <section className="panel space-y-4">
            <div className="row">
              <div className="panel-title">Kibana</div>
              <a className="btn btn-outline grafana-link" href={KIBANA_URL} target="_blank" rel="noreferrer">
                Open in new tab
              </a>
            </div>
            <div className="muted text-xs">
              If the embed is blocked, open Kibana directly at {KIBANA_URL}.
            </div>
            <div className="grafana-frame-wrap">
              <iframe className="grafana-frame" src={KIBANA_URL} title="Kibana" />
            </div>
          </section>
        </main>
      ) : page === "ids" ? (
        <main className="mx-auto grid max-w-6xl gap-6 px-6 py-8 lg:grid-cols-[320px_1fr]">
          <aside className="panel space-y-6">
            <div>
              <div className="panel-title">IDS Status</div>
              <div className="space-y-2 text-sm">
                <div>Total alerts: {idsStats.total ?? 0}</div>
              </div>
            </div>
            <div>
              <div className="panel-title">By Classification</div>
              <div className="space-y-2 text-sm">
                {(idsStats.by_classification ?? []).map((row, idx) => (
                  <div key={idx} className="row">
                    <span>{row.classification || "-"}</span>
                    <span className="muted">{row.count}</span>
                  </div>
                ))}
                {(!idsStats.by_classification || idsStats.by_classification.length === 0) && (
                  <div className="muted">No IDS alerts yet</div>
                )}
              </div>
            </div>
            <div>
              <div className="panel-title">By Priority</div>
              <div className="space-y-2 text-sm">
                {(idsStats.by_priority ?? []).map((row, idx) => (
                  <div key={idx} className="row">
                    <span>{row.priority}</span>
                    <span className="muted">{row.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </aside>

          <section className="panel space-y-6">
            <div className="panel-title">Alerts</div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Signature</th>
                    <th>Class</th>
                    <th>Priority</th>
                    <th>Src</th>
                    <th>Dst</th>
                    <th>Proto</th>
                  </tr>
                </thead>
                <tbody>
                  {idsAlerts.map((row, idx) => (
                    <tr key={idx}>
                      <td>{row.ts ? new Date(row.ts).toLocaleTimeString() : "-"}</td>
                      <td>{row.signature || "-"}</td>
                      <td>{row.classification || "-"}</td>
                      <td>{row.priority ?? "-"}</td>
                      <td>{row.src_ip}:{row.src_port}</td>
                      <td>{row.dst_ip}:{row.dst_port}</td>
                      <td>{row.proto || "-"}</td>
                    </tr>
                  ))}
                  {idsAlerts.length === 0 && (
                    <tr>
                      <td colSpan={7} className="muted">No IDS alerts loaded</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      ) : page === "vulns" ? (
        <main className="mx-auto grid max-w-6xl gap-6 px-6 py-8 lg:grid-cols-[320px_1fr]">
          <aside className="panel space-y-6">
            <div>
              <div className="panel-title">CVE Import</div>
              <div className="space-y-3 text-sm text-white/70">
                <div className="muted">Point to a local CVE.org cvelistV5 folder in Settings, then import.</div>
                <button className="btn btn-outline" onClick={importCves}>Import CVEs</button>
                <div className="muted">{cveImportStatus}</div>
              </div>
            </div>
            <div>
              <div className="panel-title">Severity</div>
              <div className="space-y-2 text-sm">
                {(cveStats.by_severity ?? []).map((row, idx) => (
                  <div key={idx} className="row">
                    <span>{row.severity || "Unknown"}</span>
                    <span className="muted">{row.count}</span>
                  </div>
                ))}
                {(!cveStats.by_severity || cveStats.by_severity.length === 0) && (
                  <div className="muted">No CVE data loaded</div>
                )}
              </div>
            </div>
          </aside>

          <section className="panel space-y-6">
            <div>
              <div className="panel-title">CVE Search</div>
              <div className="row">
                <input className="input" placeholder="CVE-2024-xxxx, vendor, keyword" value={cveQuery} onChange={(e) => setCveQuery(e.target.value)} />
                <button className="btn btn-outline btn-inline" onClick={searchCves}>Search</button>
              </div>
            </div>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Vendors</th>
                    <th>Products</th>
                  </tr>
                </thead>
                <tbody>
                  {cveResults.map((row, idx) => (
                    <tr key={idx}>
                      <td>{row.cve_id}</td>
                      <td>{row.title || "-"}</td>
                      <td>{row.severity || "-"}</td>
                      <td>{row.cvss_score ?? "-"}</td>
                      <td>{row.vendors || "-"}</td>
                      <td>{row.products || "-"}</td>
                    </tr>
                  ))}
                  {cveResults.length === 0 && (
                    <tr>
                      <td colSpan={6} className="muted">No results</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </main>
      ) : page === "audit" ? (
        <main className="mx-auto grid max-w-6xl gap-6 px-6 py-8 lg:grid-cols-[320px_1fr]">
          <aside className="panel space-y-6">
            <div>
              <div className="panel-title">Audit Controls</div>
              <div className="space-y-3 text-sm text-white/70">
                <div>Export evidence snapshots and investigation artifacts.</div>
                <div className="row">
                  <button className="btn btn-outline btn-inline" onClick={exportXlsx}>Export XLSX</button>
                  <button className="btn btn-outline btn-inline" onClick={exportPdf}>Export PDF</button>
                </div>
              </div>
            </div>

            <div>
              <div className="panel-title">Casework</div>
              <div className="space-y-2 text-sm">
                <div className="muted">Investigation queues and audit trails.</div>
                <div className="row">
                  <button className="tab tab-soon" disabled>Investigations</button>
                  <button className="tab" onClick={exportPdf}>Reports</button>
                </div>
              </div>
            </div>
          </aside>

          <section className="panel space-y-6">
            <div>
              <div className="panel-title">Recent Alerts</div>
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
              <div className="panel-title">Audit Notes</div>
              <div className="space-y-2 text-sm text-white/70">
                <div>Capture analyst notes and remediation actions (planned).</div>
                <div className="muted">Next release: tripwire alerts, remediation reports, content filtering evidence.</div>
              </div>
            </div>
          </section>
        </main>
      ) : page === "grafana" ? (
        <main className="mx-auto max-w-6xl px-6 py-8">
          <section className="panel space-y-4">
            <div className="row">
              <div className="panel-title">Grafana Dashboards</div>
              <a className="btn btn-outline grafana-link" href={GRAFANA_URL} target="_blank" rel="noreferrer">
                Open in new tab
              </a>
            </div>
            <div className="muted text-xs">
              If the embed is blocked, open Grafana directly at {GRAFANA_URL}.
            </div>
            <div className="grafana-frame-wrap">
              <iframe className="grafana-frame" src={GRAFANA_URL} title="Grafana" />
            </div>
          </section>
        </main>
      ) : page === "settings" ? (
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

            <div>
              <div className="panel-title">Triage & ATT&CK</div>
              <div className="field">
                <label>Minimum Relevance Score</label>
                <input className="input" type="number" min={0} max={100} value={config.mitre_min_score ?? 25} onChange={(e) => updateConfig("mitre_min_score", Number(e.target.value))} />
              </div>
              <div className="field">
                <label>Suppress Private IPs</label>
                <select className="input" value={String(config.suppress_private ?? false)} onChange={(e) => updateConfig("suppress_private", e.target.value === "true")}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
              <div className="field">
                <label>Suppress Loopback</label>
                <select className="input" value={String(config.suppress_loopback ?? true)} onChange={(e) => updateConfig("suppress_loopback", e.target.value === "true")}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
              <div className="field">
                <label>Suppress Processes (comma separated)</label>
                <input className="input" value={listValue(config.suppress_processes)} onChange={(e) => updateConfig("suppress_processes", e.target.value)} />
              </div>
              <div className="field">
                <label>Suppress Ports (comma separated)</label>
                <input className="input" value={listValue(config.suppress_ports)} onChange={(e) => updateConfig("suppress_ports", e.target.value)} />
              </div>
            </div>

            <div>
              <div className="panel-title">Vulnerability Data</div>
              <div className="field">
                <label>CVE Source Path (local cvelistV5)</label>
                <input className="input" value={String(config.cve_source_path || "")} onChange={(e) => updateConfig("cve_source_path", e.target.value)} />
              </div>
              <div className="field">
                <label>Min CVE Year</label>
                <input className="input" type="number" min={1999} max={2100} value={config.cve_min_year ?? 2020} onChange={(e) => updateConfig("cve_min_year", Number(e.target.value))} />
              </div>
              <div className="field">
                <label>CVE Import Limit</label>
                <input className="input" type="number" min={100} max={100000} value={config.cve_import_limit ?? 2000} onChange={(e) => updateConfig("cve_import_limit", Number(e.target.value))} />
              </div>
              <div className="field">
                <label>Enable CVE Matching</label>
                <select className="input" value={String(config.cve_match_enabled ?? true)} onChange={(e) => updateConfig("cve_match_enabled", e.target.value === "true")}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
              <div className="field">
                <label>Strict CVE Match (exact vendor/product)</label>
                <select className="input" value={String(config.cve_match_strict ?? true)} onChange={(e) => updateConfig("cve_match_strict", e.target.value === "true")}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
              <div className="field">
                <label>Minimum CVE Severity</label>
                <select className="input" value={String(config.cve_min_severity ?? "HIGH")} onChange={(e) => updateConfig("cve_min_severity", e.target.value)}>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>
            </div>

            <div>
              <div className="panel-title">IDS / IPS</div>
              <div className="field">
                <label>Enable IDS</label>
                <select className="input" value={String(config.ids_enabled ?? false)} onChange={(e) => updateConfig("ids_enabled", e.target.value === "true")}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
              <div className="field">
                <label>Engine</label>
                <select className="input" value={String(config.ids_engine ?? "snort")} onChange={(e) => updateConfig("ids_engine", e.target.value)}>
                  <option value="snort">snort</option>
                </select>
              </div>
              <div className="field">
                <label>Snort JSON Log Path</label>
                <input className="input" value={String(config.ids_log_path || "")} onChange={(e) => updateConfig("ids_log_path", e.target.value)} />
              </div>
            </div>

            <div>
              <div className="panel-title">ELK Shipping</div>
              <div className="field">
                <label>Enable ELK</label>
                <select className="input" value={String(config.elk_enabled ?? true)} onChange={(e) => updateConfig("elk_enabled", e.target.value === "true")}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
              <div className="field">
                <label>Logstash HTTP URL</label>
                <input className="input" value={String(config.elk_logstash_url || "http://localhost:8080")} onChange={(e) => updateConfig("elk_logstash_url", e.target.value)} />
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
                <div>Suppressed: {summary?.suppressed_events ?? 0}</div>
                <div>CVE High: {summary?.cve_high_hits ?? 0}</div>
                <div>CVE Medium: {summary?.cve_medium_hits ?? 0}</div>
                <div>Events (total): {health?.events_total ?? 0}</div>
                <div>Events/sec: {health?.events_per_sec?.toFixed(1) ?? "-"}</div>
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

            <div>
              <div className="panel-title">Audit</div>
              <div className="space-y-3 text-sm">
                <div className="muted">Export current telemetry for investigations and reporting.</div>
                <div className="row">
                  <button className="tab tab-soon" disabled>Investigations</button>
                  <button className="tab tab-soon" disabled>Reports</button>
                </div>
                <div className="row">
                  <button className="btn btn-outline btn-inline" onClick={exportXlsx}>Export XLSX</button>
                  <button className="btn btn-outline btn-inline" onClick={exportPdf}>Export PDF</button>
                </div>
              </div>
            </div>

            <div>
              <div className="panel-title">MITRE ATT&CK</div>
              <div className="space-y-2 text-sm">
                {(summary?.mitre_tactics ?? []).slice(0, 6).map((item, idx) => (
                  <div key={idx} className="row">
                    <span>{item.tactic}</span>
                    <span className="muted">{item.count}</span>
                  </div>
                ))}
                {(!summary?.mitre_tactics || summary.mitre_tactics.length === 0) && (
                  <div className="muted">No ATT&CK mapping yet</div>
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

            <div>
              <div className="panel-title">ATT&CK Mapping</div>
              <div className="attack-grid">
                {(summary?.mitre_tactics ?? []).slice(0, 8).map((item, idx) => (
                  <div
                    key={idx}
                    className={`attack-tile ${selectedTactic === item.tactic ? "attack-active" : ""}`}
                    onClick={() => setSelectedTactic(selectedTactic === item.tactic ? "" : item.tactic)}
                  >
                    <div className="attack-name">{item.tactic}</div>
                    <div className="attack-count">{item.count}</div>
                  </div>
                ))}
                {(!summary?.mitre_tactics || summary.mitre_tactics.length === 0) && (
                  <div className="muted">No mapped tactics observed</div>
                )}
              </div>
              <div className="mt-4 space-y-2 text-sm">
                {(selectedTactic && summary?.mitre_breakdown?.[selectedTactic]
                  ? summary.mitre_breakdown[selectedTactic]
                  : (summary?.mitre_techniques ?? [])
                ).map((item, idx) => (
                  <div key={idx} className="row">
                    <span>{item.technique_id}</span>
                    <span className="muted">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </main>
      ) : (
        <main className="mx-auto grid max-w-none gap-6 px-4 py-8 lg:grid-cols-[240px_1fr]">
          <aside className="panel space-y-6">
            <div>
              <div className="panel-title">Real-time Controls</div>
              <input
                className="input"
                placeholder="process / ip / port / country / org"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
              <div className="mt-3 flex items-center gap-2 text-xs text-white/70">
                <input
                  type="checkbox"
                  checked={showSuppressed}
                  onChange={(e) => setShowSuppressed(e.target.checked)}
                />
                <span>Show suppressed</span>
              </div>
              <div className="mt-2 flex items-center gap-2 text-xs text-white/70">
                <input
                  type="checkbox"
                  checked={onlyEstablished}
                  onChange={(e) => setOnlyEstablished(e.target.checked)}
                />
                <span>Only ESTABLISHED</span>
              </div>
              <div className="mt-2 flex items-center gap-2 text-xs text-white/70">
                <input
                  type="checkbox"
                  checked={showTimeWait}
                  onChange={(e) => setShowTimeWait(e.target.checked)}
                />
                <span>Show TIME_WAIT</span>
              </div>
              <div className="mt-4 space-y-2 text-sm text-white/70">
                <div>Status: {health?.collector ?? "-"}</div>
                <div>Events: {health?.events_total ?? 0}</div>
                <div>Uptime: {health ? Math.floor(health.uptime_sec) + "s" : "-"}</div>
              </div>
              <div className="mt-4 flex gap-2">
                <button className="btn" onClick={() => setPaused(p => !p)}>
                  {paused ? "Resume" : "Pause"}
                </button>
              </div>
            </div>
          </aside>
          <section className="panel">
            <div className="panel-title">Real-time Monitoring</div>
            <div className="table-wrap table-wrap-taller">
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
                    <th>ATT&CK</th>
                    <th>CVE</th>
                    <th>Threats</th>
                    <th>Score</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map((e, i) => {
                    const key = rowKey(e, i);
                    const expanded = expandedKey === key;
                    return (
                      <Fragment key={key}>
                        <tr className={`row-click ${e.suppressed ? "row-suppressed" : ""} ${e.cve_max_severity ? "row-cve" : ""} ${e.process_name === "unknown" ? "row-unknown" : ""}`} onClick={() => toggleRow(key)}>
                          <td>{new Date(e.ts).toLocaleTimeString()}</td>
                          <td>{e.process_name}</td>
                          <td>{e.pid}</td>
                          <td>{e.protocol}</td>
                          <td>{e.local_ip}:{e.local_port}</td>
                          <td>{e.remote_ip}:{e.remote_port}</td>
                          <td>{e.remote_country || "-"}</td>
                          <td>{e.remote_org || "-"}</td>
                          <td>{e.mitre_technique_id || "-"}</td>
                          <td>{e.cve_max_severity ? `${e.cve_max_severity} (${e.cve_count ?? 0})` : "-"}</td>
                          <td>{(e.threat_sources && e.threat_sources.length > 0) ? e.threat_sources.join(",") : "-"}</td>
                          <td>{e.threat_score ?? 0}</td>
                          <td>{e.state}</td>
                        </tr>
                        {expanded && (
                          <tr className="row-detail">
                            <td colSpan={13}>
                              <div className="detail-grid">
                                <div><span className="muted">Region:</span> {e.remote_region || "-"}</div>
                                <div><span className="muted">City:</span> {e.remote_city || "-"}</div>
                                <div><span className="muted">ASN:</span> {e.remote_asn || "-"}</div>
                                <div><span className="muted">Hostname:</span> {e.remote_hostname || "-"}</div>
                                <div><span className="muted">Loc:</span> {e.remote_loc || "-"}</div>
                                <div><span className="muted">Timezone:</span> {e.remote_timezone || "-"}</div>
                                <div><span className="muted">ATT&CK:</span> {e.mitre_tactic || "-"} {e.mitre_technique_id ? `(${e.mitre_technique_id})` : ""}</div>
                                <div><span className="muted">Relevance:</span> {e.relevance_score ?? 0}</div>
                                <div><span className="muted">Suppressed:</span> {e.suppressed ? e.suppression_reason || "yes" : "no"}</div>
                                <div><span className="muted">CVE:</span> {e.cve_max_severity || "-"} {e.cve_matches && e.cve_matches.length ? e.cve_matches.join(",") : ""}</div>
                                <div><span className="muted">Correlation:</span> {(e.cve_max_severity ? `CVE ${e.cve_max_severity}` : "CVE -")} • {e.mitre_tactic || "ATT&CK -"}</div>
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
