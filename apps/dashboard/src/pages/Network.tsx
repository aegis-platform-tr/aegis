import { useState } from "react";
import { get } from "../api";
import { utc } from "../format";
import { Counts, Empty, ErrorBox, Page, useLoad } from "../ui";

interface Service {
  service_key: string;
  max_seen_minute: string;
  last_evaluated_minute: string | null;
  late_events: number;
  classification_counts: Record<string, number>;
  coverage: string;
}
interface Minute {
  minute: string;
  classification: string;
  requests: number;
  unique_sources: number;
  error_rate: number;
  baseline_median: number | null;
  volume_score: number | null;
  new_source_fraction: number | null;
  alert_id: string | null;
}

const CLASS_MARK: Record<string, string> = {
  normal: "●", warming_up: "○", expected_burst: "◆", anomaly: "▲", missing_telemetry: "✕",
};

export function NetworkPage() {
  const { data, error, loadedAt } = useLoad<Service[]>(() => get("/api/v1/network/services"), [], 30000);
  const [selected, setSelected] = useState<string | null>(null);
  const key = selected ?? data?.[0]?.service_key ?? null;
  return (
    <Page title="Network monitoring & DDoS baselines" loadedAt={loadedAt}>
      <p className="muted small">
        Passive, per-service request-rate baselines from http_request/flow telemetry (event-time minutes, UTC).
        Single vantage point; low-confidence signals are pending corroboration.
      </p>
      {error && <ErrorBox error={error} />}
      {data && data.length === 0 && <Empty>No network telemetry yet. Import <span className="mono">ddos-baseline-demo</span> or collect Suricata/Zeek flows with an agent.</Empty>}
      {data && data.length > 0 && (
        <table>
          <thead><tr><th>Service</th><th>Classified minutes</th><th>Last evaluated (UTC)</th><th>Late events</th><th>Coverage</th></tr></thead>
          <tbody>
            {data.map((s) => (
              <tr key={s.service_key} className={`click ${s.service_key === key ? "selected" : ""}`} tabIndex={0}
                onClick={() => setSelected(s.service_key)} onKeyDown={(e) => e.key === "Enter" && setSelected(s.service_key)}>
                <td className="mono">{s.service_key}</td>
                <td><Counts data={s.classification_counts} empty="none yet" /></td>
                <td className="mono">{utc(s.last_evaluated_minute)}</td>
                <td>{s.late_events}</td>
                <td className="muted small">{s.coverage}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {key && <ServiceChart serviceKey={key} />}
    </Page>
  );
}

function ServiceChart({ serviceKey }: { serviceKey: string }) {
  const { data, error } = useLoad<{ minutes: Minute[]; timezone: string; aggregation: string }>(
    () => get(`/api/v1/network/services/${encodeURIComponent(serviceKey)}/minutes?limit=240`), [serviceKey]);
  if (error) return <ErrorBox error={error} />;
  if (!data) return null;
  const pts = data.minutes;
  if (pts.length === 0) return <Empty>No closed minutes evaluated yet.</Empty>;
  const W = 900, H = 260, L = 50, B = 30, T = 10;
  const maxY = Math.max(1, ...pts.map((p) => Math.max(p.requests, p.baseline_median ?? 0)));
  const x = (i: number) => L + (i / Math.max(1, pts.length - 1)) * (W - L - 10);
  const y = (v: number) => T + (1 - v / maxY) * (H - T - B);
  const line = pts.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p.requests).toFixed(1)}`).join(" ");
  const base = pts.map((p, i) => (p.baseline_median == null ? null : `${x(i).toFixed(1)},${y(p.baseline_median).toFixed(1)}`))
    .filter(Boolean).join(" L");
  return (
    <>
      <h3>{serviceKey} · requests per minute ({data.timezone}, {data.aggregation})</h3>
      <svg viewBox={`0 0 ${W} ${H}`} className="chart" role="img"
        aria-label={`Requests per minute for ${serviceKey}; anomalies marked with triangles`}>
        <line x1={L} y1={H - B} x2={W - 10} y2={H - B} className="axis" />
        <line x1={L} y1={T} x2={L} y2={H - B} className="axis" />
        <text x={L - 6} y={y(maxY) + 4} className="tick" textAnchor="end">{maxY}</text>
        <text x={L - 6} y={H - B + 4} className="tick" textAnchor="end">0</text>
        <text x={L} y={H - 8} className="tick">{utc(pts[0]!.minute).slice(11)}</text>
        <text x={W - 10} y={H - 8} className="tick" textAnchor="end">{utc(pts[pts.length - 1]!.minute).slice(11)}</text>
        {base && <path d={`M${base}`} className="baseline" />}
        <path d={line} className="series" />
        {pts.map((p, i) => (
          <text key={p.minute} x={x(i)} y={y(p.requests) - 6} textAnchor="middle" className={`mark ${p.classification}`}>
            <title>{`${utc(p.minute)} ${p.classification}: ${p.requests} req, ${p.unique_sources} sources, ${Math.round(p.error_rate * 100)}% errors`}</title>
            {p.classification === "normal" || p.classification === "warming_up" ? "" : CLASS_MARK[p.classification]}
          </text>
        ))}
      </svg>
      <div className="legend small">
        <span><span className="swatch series" /> requests/min</span>
        <span><span className="swatch baseline" /> baseline median (prior 30 min, anomalies excluded)</span>
        <span className="mark expected_burst">◆ expected burst (known sources)</span>
        <span className="mark anomaly">▲ anomaly</span>
        <span className="mark missing_telemetry">✕ missing telemetry</span>
      </div>
      <table>
        <thead><tr><th>Minute (UTC)</th><th>Class</th><th>Requests</th><th>Sources</th><th>Errors</th><th>Volume score</th><th>New-source share</th><th>Alert</th></tr></thead>
        <tbody>
          {pts.filter((p) => p.classification !== "normal" && p.classification !== "warming_up").map((p) => (
            <tr key={p.minute}>
              <td className="mono">{utc(p.minute)}</td><td>{p.classification}</td><td>{p.requests}</td>
              <td>{p.unique_sources}</td><td>{Math.round(p.error_rate * 100)}%</td><td>{p.volume_score ?? "—"}</td>
              <td>{p.new_source_fraction == null ? "—" : `${Math.round(p.new_source_fraction * 100)}%`}</td>
              <td className="mono small">{p.alert_id ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
