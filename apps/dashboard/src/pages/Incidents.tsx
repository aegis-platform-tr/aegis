import { useEffect, useState, type FormEvent } from "react";
import {
  api,
  ApiError,
  post,
  type EventOut,
  type Fixture,
  type IncidentDetail,
  type IncidentOut,
  type IncidentStatus,
  type Page as PageT,
  type User,
} from "../api";
import { NEXT_STATES, relative, utc } from "../format";
import { can, ErrorBox, Fact, go, Json, message, Origin, Page, Sev, Status, useLoad } from "../ui";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "new", "investigating", "contained", "resolved", "closed"];

export function IncidentList({ user }: { user: User }) {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [cursor, setCursor] = useState<string | null>(null);
  const [history, setHistory] = useState<(string | null)[]>([]);
  const { data, error, loading, reload, loadedAt } = useLoad<PageT<IncidentOut>>(
    () => {
      const p = new URLSearchParams({ limit: "25" });
      if (status) p.set("status", status);
      if (severity) p.set("severity", severity);
      if (cursor) p.set("cursor", cursor);
      return api.incidents(p);
    },
    [status, severity, cursor],
  );
  const resetPaging = () => {
    setCursor(null);
    setHistory([]);
  };
  return (
    <Page
      title={`Incidents${data ? ` (${data.total})` : ""}`}
      loadedAt={loadedAt}
      actions={
        <>
          <select value={status} onChange={(e) => { setStatus(e.target.value); resetPaging(); }} aria-label="Status filter">
            {STATUSES.map((s) => <option key={s} value={s}>{s || "any status"}</option>)}
          </select>
          <select value={severity} onChange={(e) => { setSeverity(e.target.value); resetPaging(); }} aria-label="Severity filter">
            {SEVERITIES.map((s) => <option key={s} value={s}>{s || "any severity"}</option>)}
          </select>
          <button className="ghost" onClick={() => void reload()}>Refresh</button>
        </>
      }
    >
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
              <th>Assignee</th><th>Last activity (UTC)</th><th>Data</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((i) => (
              <tr key={i.incident_id} className="click" tabIndex={0}
                onKeyDown={(e) => e.key === "Enter" && go(`#/incidents/${i.incident_id}`)}
                onClick={() => go(`#/incidents/${i.incident_id}`)}>
                <td className="mono">{i.priority}</td>
                <td><Sev s={i.severity} /></td>
                <td>{i.title}</td>
                <td><Status s={i.status} /></td>
                <td>{i.alert_count}</td>
                <td className="muted">{i.assigned_to ?? "—"}</td>
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
    </Page>
  );
}

function EmptyState({ user, filtered, onImported }: { user: User; filtered: boolean; onImported: () => Promise<void> }) {
  const canImport = can(user, "fixtures:import");
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
        "The worker evaluates events in the background; refreshing shortly…");
      setTimeout(() => void onImported(), 3000);
    } catch (e) {
      setMsg(message(e));
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

export function IncidentView({ id, user }: { id: string; user: User }) {
  const { data, error, loading, setData } = useLoad<IncidentDetail>(() => api.incident(id), [id]);
  if (loading && !data) return <p className="muted">Loading incident…</p>;
  if (error && !data) return <><a className="back" href="#/incidents">← Incidents</a><ErrorBox error={error} /></>;
  if (!data) return null;
  const canEdit = can(user, "incidents:update");
  return (
    <section>
      <a className="back" href="#/incidents">← Incidents</a>
      <h2>{data.title}</h2>
      <div className="facts">
        <Fact k="Status"><Status s={data.status} /></Fact>
        <Fact k="Severity"><Sev s={data.severity} /></Fact>
        <Fact k="Priority">{data.priority}</Fact>
        <Fact k="Assignee">{data.assigned_to ?? "unassigned"}</Fact>
        <Fact k="Correlation"><span className="mono">{data.correlation_key}</span> <span className="muted">({data.correlation_rule})</span></Fact>
        <Fact k="Created (UTC)"><span className="mono">{utc(data.created_at)}</span></Fact>
        <Fact k="Version">{data.version}</Fact>
        <Fact k="Data"><Origin o={data.origin} /></Fact>
      </div>
      {canEdit && <TransitionForm incident={data} onDone={setData} />}
      {canEdit && <NoteForm incident={data} user={user} onDone={setData} />}
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
            Confidence {Math.round(a.confidence * 100)}% (rule metadata) · evidence {a.evidence_quality} ·{" "}
            {a.mitre.map((m) => `${m.framework} ${m.id} ${m.name}`).join(", ") || "no ATT&CK label"} · evaluated{" "}
            <span className="mono">{utc(a.evaluated_at)}</span>
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
              {t.kind === "event" ? <a href={`#/events/${t.ref_id}/${data.incident_id}`}>{t.summary}</a> : t.summary}
              {t.kind === "event" && (
                <span className="muted small times">
                  source {utc(t.times.occurred_at)} · collector {utc(t.times.observed_at)} · ingested {utc(t.times.ingested_at)}
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
      else setError(message(err));
    }
  };
  return (
    <form className="card transition row" onSubmit={submit}>
      <label htmlFor="next-status">Move to</label>
      <select id="next-status" value={to} onChange={(e) => setTo(e.target.value)}>
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
      <input aria-label="Reason" placeholder="Reason (required, recorded in history)" value={reason}
        onChange={(e) => setReason(e.target.value)} minLength={3} required className="grow" />
      <button type="submit">Update</button>
      {error && <ErrorBox error={error} />}
    </form>
  );
}

function NoteForm({ incident, user, onDone }: { incident: IncidentDetail; user: User; onDone: (d: IncidentDetail) => void }) {
  const [kind, setKind] = useState("note");
  const [body, setBody] = useState("");
  const [error, setError] = useState<string | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      onDone(await post<IncidentDetail>(`/api/v1/incidents/${incident.incident_id}/notes`, { kind, body }));
      setBody("");
      setError(null);
    } catch (err) {
      setError(message(err));
    }
  };
  const assignMe = async () => {
    try {
      onDone(await post<IncidentDetail>(`/api/v1/incidents/${incident.incident_id}/assign`, {
        assignee: incident.assigned_to === user.username ? null : user.username, version: incident.version,
      }));
    } catch (err) {
      setError(message(err));
    }
  };
  return (
    <form className="card row" onSubmit={submit}>
      <select aria-label="Note type" value={kind} onChange={(e) => setKind(e.target.value)}>
        <option value="note">note</option>
        <option value="containment_verification">containment verification</option>
        <option value="closure_reason">closure reason</option>
      </select>
      <input aria-label="Note" className="grow" placeholder="Add to the timeline" value={body}
        onChange={(e) => setBody(e.target.value)} required />
      <button type="submit">Add</button>
      <button type="button" className="ghost" onClick={() => void assignMe()}>
        {incident.assigned_to === user.username ? "Unassign me" : "Assign to me"}
      </button>
      {error && <ErrorBox error={error} />}
    </form>
  );
}

export function EventView({ id, from }: { id: string; from?: string }) {
  const { data, error, loading } = useLoad<EventOut>(() => api.event(id), [id]);
  return (
    <section>
      {from ? <a className="back" href={`#/incidents/${from}`}>← Back to incident</a> : <a className="back" href="#/events">← Events</a>}
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
          <Json value={data.attributes} />
          <h3>Provenance</h3>
          <Json value={data.provenance} />
        </>
      )}
    </section>
  );
}
