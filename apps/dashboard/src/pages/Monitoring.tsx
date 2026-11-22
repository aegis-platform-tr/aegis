import { useState, type ReactNode } from "react";
import { get, type AlertOut, type EventOut, type Page as PageT } from "../api";
import { utc } from "../format";
import { Counts, Empty, ErrorBox, go, Origin, Page, Sev, useLoad } from "../ui";

interface Overview {
  incidents_by_status: Record<string, number>;
  open_incidents_by_severity: Record<string, number>;
  alerts_by_severity: Record<string, number>;
  suppressed_alerts: number;
  events_total: number;
  events_by_origin: Record<string, number>;
  last_event_ingested_at: string | null;
  agents: { total: number; by_health: Record<string, number> };
  network: { latest_evaluated_minute: string | null; status: string };
  pipeline: { pending: number; dead: number; retried: number; oldest_pending_age_seconds: number };
}

export function OverviewPage() {
  const { data, error, loadedAt } = useLoad<Overview>(() => get("/api/v1/overview"), [], 15000);
  return (
    <Page title="Overview" loadedAt={loadedAt}>
      {error && <ErrorBox error={error} />}
      {data && (
        <div className="tiles">
          <Tile title="Open incidents by severity" href="#/incidents">
            <Counts data={data.open_incidents_by_severity} empty="none open" />
          </Tile>
          <Tile title="Incidents by status" href="#/incidents">
            <Counts data={data.incidents_by_status} empty="no incidents" />
          </Tile>
          <Tile title="Alerts by severity (not suppressed)" href="#/alerts">
            <Counts data={data.alerts_by_severity} empty="no alerts" />
            {data.suppressed_alerts > 0 && <div className="muted small">{data.suppressed_alerts} suppressed</div>}
          </Tile>
          <Tile title="Events" href="#/events">
            <div><strong>{data.events_total}</strong> stored</div>
            <Counts data={data.events_by_origin} empty="no data ingested" />
            <div className="muted small">last ingested {utc(data.last_event_ingested_at)}</div>
          </Tile>
          <Tile title="Agents" href="#/agents">
            {data.agents.total === 0 ? <span className="muted">no agents enrolled</span> : <Counts data={data.agents.by_health} empty="" />}
          </Tile>
          <Tile title="Network baselines" href="#/network">
            <span className={data.network.latest_evaluated_minute ? "" : "muted"}>{data.network.status}</span>
            {data.network.latest_evaluated_minute && <div className="muted small">latest minute {utc(data.network.latest_evaluated_minute)}</div>}
          </Tile>
          <Tile title="Pipeline" href="#/health">
            <div>{data.pipeline.pending} pending · {data.pipeline.retried} retried · {data.pipeline.dead} dead</div>
            <div className="muted small">oldest pending {data.pipeline.oldest_pending_age_seconds}s</div>
          </Tile>
        </div>
      )}
    </Page>
  );
}

function Tile({ title, href, children }: { title: string; href: string; children: ReactNode }) {
  return (
    <a className="card tile" href={href}>
      <div className="k">{title}</div>
      <div className="v">{children}</div>
    </a>
  );
}

export function EventsPage() {
  const [type, setType] = useState("");
  const [origin, setOrigin] = useState("");
  const [live, setLive] = useState(true);
  const { data, error, loadedAt, reload } = useLoad<PageT<EventOut>>(() => {
    const p = new URLSearchParams({ limit: "50" });
    if (type) p.set("event_type", type);
    if (origin) p.set("origin", origin);
    return get(`/api/v1/events?${p.toString()}`);
  }, [type, origin], live ? 10000 : undefined);
  return (
    <Page title={`Live security events${data ? ` (${data.total})` : ""}`} loadedAt={loadedAt}
      actions={<>
        <input aria-label="Event type filter" placeholder="event type, e.g. login_failure" value={type}
          onChange={(e) => setType(e.target.value.trim())} />
        <select aria-label="Origin filter" value={origin} onChange={(e) => setOrigin(e.target.value)}>
          <option value="">any origin</option><option value="observed">observed</option><option value="synthetic">synthetic</option>
        </select>
        <label className="row small"><input type="checkbox" checked={live} onChange={(e) => setLive(e.target.checked)} /> auto-refresh 10s</label>
        <button className="ghost" onClick={() => void reload()}>Refresh</button>
      </>}>
      {error && <ErrorBox error={error} />}
      {data && data.items.length === 0 && <Empty>No events match. Import a fixture or enroll an agent.</Empty>}
      {data && data.items.length > 0 && (
        <table>
          <thead><tr><th>Ingested (UTC)</th><th>Source time (UTC)</th><th>Type</th><th>Source → Destination</th><th>Asset</th><th>Producer</th><th>Data</th></tr></thead>
          <tbody>
            {data.items.map((e) => (
              <tr key={e.event_id} className="click" tabIndex={0} onClick={() => go(`#/events/${e.event_id}`)}
                onKeyDown={(k) => k.key === "Enter" && go(`#/events/${e.event_id}`)}>
                <td className="mono">{utc(e.ingested_at)}</td>
                <td className="mono">{utc(e.occurred_at)}</td>
                <td>{e.event_category}/{e.event_type} {e.severity && <Sev s={e.severity} />}</td>
                <td className="mono">{e.source_ip ?? "—"} → {e.destination_ip ?? "—"}{e.destination_port ? `:${e.destination_port}` : ""}</td>
                <td className="mono">{e.asset_id ?? "—"}</td>
                <td className="mono small">{e.producer_id}</td>
                <td><Origin o={e.origin} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Page>
  );
}

export function AlertsPage({ idsOnly }: { idsOnly?: boolean }) {
  const { data, error, loadedAt } = useLoad<PageT<AlertOut>>(() => get("/api/v1/alerts?limit=200"), [], 15000);
  const items = (data?.items ?? []).filter((a) => !idsOnly || a.rule_id.startsWith("ids."));
  return (
    <Page title={idsOnly ? "IDS/IPS alerts (Suricata)" : `Alerts${data ? ` (${data.total})` : ""}`} loadedAt={loadedAt}>
      {idsOnly && <p className="muted small">Alerts derived from Suricata EVE signatures. AEGIS is passive: the sensor's "allowed/blocked" action is reported, AEGIS does not block traffic inline.</p>}
      {error && <ErrorBox error={error} />}
      {data && items.length === 0 && <Empty>{idsOnly ? "No IDS alerts. Configure a suricata_eve source on an agent or import ids-correlation-demo." : "No alerts."}</Empty>}
      {items.length > 0 && (
        <table>
          <thead><tr><th>Evaluated (UTC)</th><th>Severity</th><th>Rule</th><th>Group</th><th>Events</th><th>Incident</th><th>State</th></tr></thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.alert_id}>
                <td className="mono">{utc(a.evaluated_at)}</td>
                <td><Sev s={a.severity} /></td>
                <td className="mono small">{a.rule_id} r{a.rule_revision}</td>
                <td className="mono small">{Object.entries(a.group_key).map(([k, v]) => `${k}=${v}`).join(" ")}</td>
                <td>{a.event_count}</td>
                <td>{a.incident_id ? <a href={`#/incidents/${a.incident_id}`}>open</a> : "—"}</td>
                <td>{a.suppressed ? <span className="status closed" title={a.explanation}>suppressed</span> : <Origin o={a.origin} />}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Page>
  );
}
