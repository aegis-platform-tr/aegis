import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  ApiError,
  setToken,
  setUnauthorizedHandler,
  type EventOut,
  type Fixture,
  type IncidentDetail,
  type IncidentOut,
  type IncidentStatus,
  type Page,
  type User,
} from "./api";
import { NEXT_STATES, relative, utc } from "./format";

type Route =
  | { view: "incidents" }
  | { view: "incident"; id: string }
  | { view: "event"; id: string; from?: string };

function parseRoute(): Route {
  const parts = window.location.hash.replace(/^#\/?/, "").split("/");
  if (parts[0] === "incidents" && parts[1]) return { view: "incident", id: decodeURIComponent(parts[1]) };
  if (parts[0] === "events" && parts[1])
    return { view: "event", id: decodeURIComponent(parts[1]), from: parts[2] };
  return { view: "incidents" };
}

function go(hash: string): void {
  window.location.hash = hash;
}

function useRoute(): Route {
  const [route, setRoute] = useState<Route>(parseRoute);
  useEffect(() => {
    const on = () => setRoute(parseRoute());
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);
  return route;
}

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const route = useRoute();

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setToken(null);
      setUser(null);
      setNotice("Your session ended. Please sign in again.");
    });
  }, []);

  if (!user) return <Login notice={notice} onLogin={(u) => { setNotice(null); setUser(u); }} />;

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setToken(null);
      setUser(null);
    }
  };

  return (
    <div className="shell">
      <header className="topbar">
        <button className="brand" onClick={() => go("#/incidents")}>AEGIS</button>
        <ModeBadge />
        <span className="spacer" />
        <span className="who">
          {user.username} · <span className="mono">{user.tenant_id}</span> · {user.roles.join(", ")}
        </span>
        <button className="ghost" onClick={logout}>Sign out</button>
      </header>
      <main>
        {route.view === "incidents" && <IncidentList user={user} />}
        {route.view === "incident" && <IncidentView id={route.id} user={user} />}
        {route.view === "event" && <EventView id={route.id} from={route.from} />}
      </main>
    </div>
  );
}

function ModeBadge() {
  const [state, setState] = useState<{ profile: string; ok: boolean } | null>(null);
  useEffect(() => {
    api.ready().then(
      (r) => setState({ profile: r.profile, ok: r.status === "ready" }),
      () => setState({ profile: "unknown", ok: false }),
    );
  }, []);
  if (!state) return null;
  return (
    <span className={`badge ${state.ok ? "ok" : "bad"}`} title="Runtime profile and API readiness">
      {state.profile.toUpperCase()} · {state.ok ? "API ready" : "API not ready"}
    </span>
  );
}

function Login({ onLogin, notice }: { onLogin: (u: User) => void; notice: string | null }) {
  const [username, setUsername] = useState("analyst@demo.local");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.login(username, password);
      setToken(res.access_token);
      onLogin(res.user);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
      setPassword("");
    }
  };

  return (
    <div className="login">
      <form onSubmit={submit} className="card">
        <h1>AEGIS</h1>
        <p className="muted">Defensive SOC workspace · local-demo profile uses synthetic data only</p>
        {notice && <div className="info">{notice}</div>}
        <label>
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {error && <div className="error" role="alert">{error}</div>}
        <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}

function useLoad<T>(loader: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const load = useCallback(loader, deps);
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await load());
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "unknown", String(e), null));
    } finally {
      setLoading(false);
    }
  }, [load]);
  useEffect(() => {
    void reload();
  }, [reload]);
  return { data, error, loading, reload, setData };
}

function ErrorBox({ error }: { error: ApiError }) {
  return (
    <div className="error" role="alert">
      {error.message}
      {error.correlationId && <span className="mono muted"> · ref {error.correlationId}</span>}
    </div>
  );
}

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "new", "investigating", "contained", "resolved", "closed"];

function IncidentList({ user }: { user: User }) {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [history, setHistory] = useState<(string | null)[]>([]);
  const { data, error, loading, reload } = useLoad<Page<IncidentOut>>(() => {
    const p = new URLSearchParams({ limit: "25" });
    if (status) p.set("status", status);
    if (severity) p.set("severity", severity);
    if (cursor) p.set("cursor", cursor);
    return api.incidents(p);
  }, [status, severity, cursor]);

  const resetPaging = () => {
    setCursor(null);
    setHistory([]);
  };

  return (
    <section>
      <div className="row">
        <h2>Incidents {data && <span className="muted">({data.total})</span>}</h2>
        <span className="spacer" />
        <select value={status} onChange={(e) => { setStatus(e.target.value); resetPaging(); }} aria-label="Status filter">
          {STATUSES.map((s) => <option key={s} value={s}>{s || "any status"}</option>)}
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); resetPaging(); }} aria-label="Severity filter">
          {SEVERITIES.map((s) => <option key={s} value={s}>{s || "any severity"}</option>)}
        </select>
        <button className="ghost" onClick={() => void reload()}>Refresh</button>
      </div>
      {error && <ErrorBox error={error} />}
      {loading && !data && <p className="muted">Loading…</p>}
      {data && data.items.length === 0 && (
        <EmptyState user={user} filtered={Boolean(status || severity)} onImported={reload} />
      )}
      {data && data.items.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Priority</th><th>Severity</th><th>Title</th><th>Status</th><th>Alerts</th>
              <th>Last activity (UTC)</th><th>Data</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((i) => (
              <tr key={i.incident_id} className="click" onClick={() => go(`#/incidents/${i.incident_id}`)}>
                <td className="mono">{i.priority}</td>
                <td><Sev s={i.severity} /></td>
                <td>{i.title}</td>
                <td><span className={`status ${i.status}`}>{i.status}</span></td>
                <td>{i.alert_count}</td>
                <td className="mono" title={relative(i.last_activity_at)}>{utc(i.last_activity_at)}</td>
                <td><Origin o={i.origin} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && (history.length > 0 || data.next_cursor) && (
        <div className="row pager">
          <button className="ghost" disabled={history.length === 0}
            onClick={() => { const prev = history[history.length - 1] ?? null; setHistory(history.slice(0, -1)); setCursor(prev); }}>
            ← Previous
          </button>
          <button className="ghost" disabled={!data.next_cursor}
            onClick={() => { setHistory([...history, cursor]); setCursor(data.next_cursor); }}>
            Next →
          </button>
        </div>
      )}
    </section>
  );
}

function EmptyState({ user, filtered, onImported }: { user: User; filtered: boolean; onImported: () => Promise<void> }) {
  const canImport = user.capabilities.includes("fixtures:import");
  const [fixtures, setFixtures] = useState<Fixture[]>([]);
  const [msg, setMsg] = useState<string | null>(null);
  useEffect(() => {
    if (canImport && !filtered) api.fixtures().then(setFixtures, () => setFixtures([]));
  }, [canImport, filtered]);

  if (filtered) return <p className="muted">No incidents match these filters.</p>;
  const importPack = async (name: string) => {
    setMsg("Importing…");
    try {
      const r = await api.importFixture(name);
      setMsg(`Imported: ${r.accepted} new, ${r.duplicate} already present, ${r.rejected} rejected. ` +
        "The worker evaluates events in the background; refreshing in a moment…");
      setTimeout(() => void onImported(), 2500);
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : "Import failed");
    }
  };
  return (
    <div className="card empty">
      <h3>No incidents yet</h3>
      <p className="muted">Incidents appear when detection rules match ingested events.</p>
      {canImport && fixtures.map((f) => (
        <div key={f.name} className="fixture">
          <div>
            <strong>{f.name}</strong> <Origin o={f.origin} /> <span className="muted">· {f.event_count} events</span>
            <p className="muted small">{f.description}</p>
          </div>
          <button onClick={() => void importPack(f.name)}>Import sample data</button>
        </div>
      ))}
      {msg && <div className="info">{msg}</div>}
    </div>
  );
}

function Sev({ s }: { s: string }) {
  return <span className={`sev ${s}`}>{s}</span>;
}
function Origin({ o }: { o: string }) {
  return <span className={`origin ${o}`} title="Data provenance">{o}</span>;
}

function IncidentView({ id, user }: { id: string; user: User }) {
  const { data, error, loading, setData } = useLoad<IncidentDetail>(() => api.incident(id), [id]);
  if (loading && !data) return <p className="muted">Loading incident…</p>;
  if (error && !data) return <><Back /><ErrorBox error={error} /></>;
  if (!data) return null;
  return (
    <section>
      <Back />
      <div className="row">
        <h2>{data.title}</h2>
      </div>
      <div className="facts">
        <Fact k="Status"><span className={`status ${data.status}`}>{data.status}</span></Fact>
        <Fact k="Severity"><Sev s={data.severity} /></Fact>
        <Fact k="Priority">{data.priority}</Fact>
        <Fact k="Correlation"><span className="mono">{data.correlation_key}</span> <span className="muted">({data.correlation_rule})</span></Fact>
        <Fact k="Created (UTC)"><span className="mono">{utc(data.created_at)}</span></Fact>
        <Fact k="Version">{data.version}</Fact>
        <Fact k="Data"><Origin o={data.origin} /></Fact>
      </div>
      {user.capabilities.includes("incidents:update") && (
        <TransitionForm incident={data} onDone={setData} />
      )}
      <h3>Alerts ({data.alerts.length})</h3>
      {data.alerts.map((a) => (
        <div key={a.alert_id} className="card alert">
          <div className="row">
            <Sev s={a.severity} /> <strong>{a.title}</strong>
            <span className="spacer" />
            <span className="muted mono">{a.rule_id} r{a.rule_revision}</span>
          </div>
          <p>{a.explanation}</p>
          <div className="muted small">
            Confidence {Math.round(a.confidence * 100)}% (rule metadata) ·
            {" "}{a.mitre.map((m) => `${m.framework} ${m.id} ${m.name}`).join(", ") || "no ATT&CK label"}
            {" "}· evaluated <span className="mono">{utc(a.evaluated_at)}</span>
          </div>
        </div>
      ))}
      <h3>Timeline (UTC)</h3>
      <ol className="timeline">
        {data.timeline.map((t) => (
          <li key={`${t.kind}-${t.ref_id}`} className={t.kind}>
            <span className="mono when">{utc(t.at)}</span>
            <span className={`kind ${t.kind}`}>{t.kind}</span>
            <span className="what">
              {t.kind === "event" ? (
                <a href={`#/events/${t.ref_id}/${data.incident_id}`}>{t.summary}</a>
              ) : t.summary}
              {t.kind === "event" && (
                <span className="muted small times">
                  {" "}source {utc(t.times.occurred_at)} · collector {utc(t.times.observed_at)} · ingested {utc(t.times.ingested_at)}
                </span>
              )}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

function TransitionForm({ incident, onDone }: { incident: IncidentDetail; onDone: (d: IncidentDetail) => void }) {
  const options = NEXT_STATES[incident.status] ?? [];
  const [to, setTo] = useState(options[0] ?? "");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setTo((NEXT_STATES[incident.status] ?? [])[0] ?? ""), [incident.status]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      onDone(await api.transition(incident.incident_id, to as IncidentStatus, incident.version, reason));
      setReason("");
    } catch (err) {
      if (err instanceof ApiError && err.code === "version_conflict")
        setError("Someone else changed this incident. Reload the page to see the latest version.");
      else setError(err instanceof ApiError ? err.message : "Update failed");
    }
  };
  return (
    <form className="card transition row" onSubmit={submit}>
      <span>Move to</span>
      <select value={to} onChange={(e) => setTo(e.target.value)} aria-label="Next status">
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
      <input placeholder="Reason (required, recorded in history)" value={reason}
        onChange={(e) => setReason(e.target.value)} minLength={3} required className="grow" />
      <button type="submit">Update</button>
      {error && <div className="error" role="alert">{error}</div>}
    </form>
  );
}

function EventView({ id, from }: { id: string; from?: string }) {
  const { data, error, loading } = useLoad<EventOut>(() => api.event(id), [id]);
  return (
    <section>
      {from ? <a className="back" href={`#/incidents/${from}`}>← Back to incident</a> : <Back />}
      {loading && !data && <p className="muted">Loading event…</p>}
      {error && <ErrorBox error={error} />}
      {data && (
        <>
          <h2>{data.event_category}/{data.event_type} <Origin o={data.origin} /></h2>
          <div className="facts">
            <Fact k="Event ID"><span className="mono">{data.event_id}</span></Fact>
            <Fact k="Source time (UTC)"><span className="mono">{utc(data.occurred_at)}</span>{!data.occurred_at && <span className="muted"> not provided by source</span>}</Fact>
            <Fact k="Collector time (UTC)"><span className="mono">{utc(data.observed_at)}</span></Fact>
            <Fact k="Ingested (UTC)"><span className="mono">{utc(data.ingested_at)}</span></Fact>
            <Fact k="Source"><span className="mono">{data.source.adapter} v{data.source.adapter_version} · {data.source.native_id}</span></Fact>
            <Fact k="Producer"><span className="mono">{data.producer_id}</span></Fact>
            <Fact k="Asset"><span className="mono">{data.asset_id ?? "—"}</span></Fact>
            <Fact k="Network"><span className="mono">{data.source_ip ?? "?"}:{data.source_port ?? "*"} → {data.destination_ip ?? "?"}:{data.destination_port ?? "*"} {data.protocol ?? ""}</span></Fact>
            <Fact k="Principal"><span className="mono">{data.principal ?? "—"}</span></Fact>
            <Fact k="Schema">{data.schema_version}</Fact>
          </div>
          <h3>Attributes</h3>
          {/* Rendered as text: React escapes it, so attacker-controlled event content cannot inject markup. */}
          <pre>{JSON.stringify(data.attributes, null, 2)}</pre>
          <h3>Provenance</h3>
          <pre>{JSON.stringify(data.provenance, null, 2)}</pre>
        </>
      )}
    </section>
  );
}

function Back() {
  return <a className="back" href="#/incidents">← Incidents</a>;
}
function Fact({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="fact">
      <div className="k">{k}</div>
      <div className="v">{children}</div>
    </div>
  );
}
