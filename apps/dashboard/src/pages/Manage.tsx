import { useState, type FormEvent } from "react";
import { get, post, put, type User } from "../api";
import { utc } from "../format";
import { can, Counts, Empty, ErrorBox, Fact, Json, message, Page, Sev, Status, useLoad } from "../ui";

// ---- Detection rules -----------------------------------------------------------------------

interface Rule {
  rule_id: string; revision: number; name: string; status: string; scope: string;
  enabled_for_tenant: boolean; severity: string; confidence: number; description: string;
  definition: Record<string, unknown>; author: string; change_reason: string;
  published_at: string | null;
}

export function RulesPage({ user }: { user: User }) {
  const { data, error, reload, loadedAt } = useLoad<Rule[]>(() => get("/api/v1/rules"), []);
  const [msg, setMsg] = useState<string | null>(null);
  const [test, setTest] = useState<Record<string, unknown> | null>(null);
  const writer = can(user, "rules:write");
  const toggle = async (r: Rule) => {
    const reason = window.prompt(`Reason to ${r.enabled_for_tenant ? "disable" : "enable"} ${r.rule_id}?`);
    if (!reason) return;
    try {
      await post(`/api/v1/rules/${encodeURIComponent(r.rule_id)}/${r.enabled_for_tenant ? "disable" : "enable"}`, { reason });
      setMsg(`Rule ${r.rule_id} ${r.enabled_for_tenant ? "disabled" : "enabled"} (audited).`);
      await reload();
    } catch (e) { setMsg(message(e)); }
  };
  const runTest = async (r: Rule, fixture: string) => {
    try {
      setTest(await post(`/api/v1/rules/${encodeURIComponent(r.rule_id)}/revisions/${r.revision}/test`, { fixture }));
    } catch (e) { setMsg(message(e)); }
  };
  return (
    <Page title="Detection rules" loadedAt={loadedAt}>
      <p className="muted small">Declarative, versioned rules. Built-ins are read-only; tenants can disable them for themselves or add their own revisions (API). Dry-run tests persist nothing.</p>
      {error && <ErrorBox error={error} />}
      {msg && <div className="info">{msg}</div>}
      {data && (
        <table>
          <thead><tr><th>Rule</th><th>Rev</th><th>Status</th><th>Severity</th><th>Scope</th><th>Tenant</th><th>Actions</th></tr></thead>
          <tbody>
            {data.map((r) => (
              <tr key={`${r.rule_id}@${r.revision}`}>
                <td><div>{r.name}</div><div className="mono small muted">{r.rule_id}</div></td>
                <td>{r.revision}</td>
                <td><Status s={r.status} /></td>
                <td><Sev s={r.severity} /> <span className="muted small">{Math.round(r.confidence * 100)}%</span></td>
                <td>{r.scope}</td>
                <td>{r.enabled_for_tenant ? "enabled" : <strong>disabled</strong>}</td>
                <td className="row">
                  {(r.definition as { kind?: string }).kind === "threshold" && (
                    <button className="ghost" onClick={() => void runTest(r, "auth-bruteforce-demo")}>Test on fixture</button>
                  )}
                  {writer && r.status === "active" && r.scope === "built-in" && (
                    <button className="ghost" onClick={() => void toggle(r)}>{r.enabled_for_tenant ? "Disable" : "Enable"}</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {test && <><h3>Dry-run result (nothing persisted)</h3><Json value={test} /></>}
    </Page>
  );
}

// ---- Agents ---------------------------------------------------------------------------------

interface AgentRow {
  agent_id: string; hostname: string; platform: string; agent_version: string; health: string;
  last_seen_at: string | null; clock_skew_ms: number | null; queue_depth: number | null;
  quarantined_lines: number | null; sent_events: number | null; spool_full: boolean | null;
  sources: { name: string; type: string; status: string; lag_seconds?: number; error?: string }[];
}

export function AgentsPage({ user }: { user: User }) {
  const { data, error, reload, loadedAt } = useLoad<{ items: AgentRow[]; total: number }>(() => get("/api/v1/agents"), [], 15000);
  const [token, setToken] = useState<{ enrollment_token: string; expires_at: string } | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const manage = can(user, "agents:manage");
  const mint = async () => {
    try { setToken(await post("/api/v1/agents/enrollment-tokens", { label: "dashboard", ttl_minutes: 60 })); }
    catch (e) { setMsg(message(e)); }
  };
  const revoke = async (a: AgentRow) => {
    const reason = window.prompt(`Revoke ${a.hostname}? Reason:`);
    if (!reason) return;
    try { await post(`/api/v1/agents/${a.agent_id}/revoke`, { reason }); await reload(); }
    catch (e) { setMsg(message(e)); }
  };
  return (
    <Page title={`Agent management${data ? ` (${data.total})` : ""}`} loadedAt={loadedAt}
      actions={manage && <button onClick={() => void mint()}>New enrollment token</button>}>
      {error && <ErrorBox error={error} />}
      {msg && <div className="info">{msg}</div>}
      {token && (
        <div className="card">
          <strong>Single-use enrollment token</strong> (shown once, expires {utc(token.expires_at)}):
          <pre>{token.enrollment_token}</pre>
          <div className="muted small">Save it to a file readable only by root, then run <span className="mono">aegis-agent enroll -config agent.json -token-file FILE</span> and delete the file.</div>
        </div>
      )}
      {data && data.items.length === 0 && <Empty>No agents enrolled. See <span className="mono">agent/README.md</span>.</Empty>}
      {data && data.items.length > 0 && (
        <table>
          <thead><tr><th>Host</th><th>Health</th><th>Version</th><th>Last seen (UTC)</th><th>Skew</th><th>Queue</th><th>Quarantined</th><th>Sources</th><th /></tr></thead>
          <tbody>
            {data.items.map((a) => (
              <tr key={a.agent_id}>
                <td><div>{a.hostname}</div><div className="mono small muted">{a.platform} · {a.agent_id}</div></td>
                <td><Status s={a.health} /></td>
                <td className="mono">{a.agent_version}</td>
                <td className="mono">{utc(a.last_seen_at)}</td>
                <td>{a.clock_skew_ms == null ? "—" : `${a.clock_skew_ms} ms`}</td>
                <td>{a.queue_depth ?? "unknown"}{a.spool_full ? " (full)" : ""}</td>
                <td>{a.quarantined_lines ?? "—"}</td>
                <td className="small">{a.sources.map((s) => (
                  <div key={s.name}>{s.name}: {s.status}{s.lag_seconds != null ? `, lag ${Math.round(s.lag_seconds)}s` : ""}{s.error ? ` (${s.error})` : ""}</div>
                ))}</td>
                <td>{manage && a.health !== "revoked" && <button className="ghost" onClick={() => void revoke(a)}>Revoke</button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Page>
  );
}

// ---- AI Security Gateway ----------------------------------------------------------------------

interface AiResponse {
  request_id: string; decision: string; status: string; label: string | null; output: string | null;
  provider: string | null; model: string | null; provider_called: boolean; policy_version: string;
  observed_evidence: { ref: string; kind: string; fact: string }[]; uncertainty: string | null;
  input_checks: { check: string; kind: string; location: string }[];
  output_checks: { check: string; kind: string; location: string }[];
  tool_calls: { name: string; decision: string; reason: string; executed: boolean }[];
}

export function AiPage({ user }: { user: User }) {
  const [capability, setCapability] = useState("ask");
  const [prompt, setPrompt] = useState("");
  const [incident, setIncident] = useState("");
  const [doc, setDoc] = useState("");
  const [result, setResult] = useState<AiResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const policy = useLoad<Record<string, unknown>>(() => get("/api/v1/ai/policy"), []);
  const audit = useLoad<Record<string, unknown>[]>(
    () => (can(user, "ai:audit") ? get("/api/v1/ai/requests") : Promise.resolve([])), [result]);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    try {
      setResult(await post<AiResponse>("/api/v1/ai/requests", {
        capability, prompt, ...(incident ? { incident_id: incident } : {}), documents: doc ? [doc] : [],
      }));
    } catch (e2) { setErr(message(e2)); }
  };
  return (
    <Page title="AI Security Gateway">
      <p className="muted small">Every request passes deterministic policy (budget, provider policy, secret redaction, injection signals on untrusted data, tool brokering, output inspection). AI output is optional, labeled and never grants permissions.</p>
      {policy.data && <div className="facts">
        {Object.entries(policy.data).map(([k, v]) => <Fact key={k} k={k}>{String(v)}</Fact>)}
      </div>}
      {can(user, "ai:use") ? (
        <form className="card col" onSubmit={submit}>
          <div className="row">
            <select aria-label="Request type" value={capability} onChange={(e) => setCapability(e.target.value)}>
              <option value="ask">ask</option><option value="summarize_incident">summarize_incident</option><option value="draft_response">draft_response</option>
            </select>
            <input aria-label="Incident ID" placeholder="incident id (inc_…)" value={incident} onChange={(e) => setIncident(e.target.value.trim())} className="grow" />
          </div>
          <textarea aria-label="Prompt" placeholder="Question for the assistant" value={prompt} onChange={(e) => setPrompt(e.target.value)} rows={3} />
          <textarea aria-label="Untrusted document" placeholder="Optional untrusted document (treated as data, never instructions)" value={doc} onChange={(e) => setDoc(e.target.value)} rows={3} />
          <div><button type="submit">Send through gateway</button></div>
        </form>
      ) : <Empty>Your role cannot use the AI gateway.</Empty>}
      {err && <ErrorBox error={err} />}
      {result && (
        <div className="card">
          <div className="row"><Status s={result.decision} /> <span className="muted small">{result.status} · {result.policy_version} · provider {result.provider ?? "—"} ({result.provider_called ? "called" : "not called"}) · model {result.model ?? "—"}</span></div>
          {result.label && <div className="info">{result.label}</div>}
          {result.output && <p>{result.output}</p>}
          {result.uncertainty && <p className="muted small">{result.uncertainty}</p>}
          {result.observed_evidence.length > 0 && <><h3>Observed evidence (from stored records)</h3>
            <ul>{result.observed_evidence.map((o) => <li key={o.ref} className="small"><span className="mono">{o.ref}</span> {o.fact}</li>)}</ul></>}
          <div className="facts">
            <Fact k="Input checks">{result.input_checks.map((c) => `${c.kind}@${c.location}`).join(", ") || "none"}</Fact>
            <Fact k="Output checks">{result.output_checks.map((c) => c.kind).join(", ") || "none"}</Fact>
            <Fact k="Tool calls">{result.tool_calls.map((t) => `${t.name}: ${t.decision}`).join("; ") || "none"}</Fact>
          </div>
        </div>
      )}
      {audit.data && audit.data.length > 0 && (<>
        <h3>Recent gateway decisions (redacted audit: prompt hash and length only)</h3>
        <table><thead><tr><th>Time (UTC)</th><th>Capability</th><th>Decision</th><th>Provider called</th><th>Checks</th><th>Prompt</th></tr></thead>
          <tbody>{audit.data.slice(0, 20).map((r) => (
            <tr key={String(r.request_id)}>
              <td className="mono">{utc(String(r.created_at))}</td><td>{String(r.capability)}</td>
              <td><Status s={String(r.decision)} /></td><td>{r.provider_called ? "yes" : "no"}</td>
              <td className="small">{(r.input_checks as { kind: string }[]).map((c) => c.kind).join(", ")}</td>
              <td className="mono small">{String(r.prompt_sha256).slice(0, 12)}… ({String(r.prompt_chars)} chars)</td>
            </tr>))}</tbody></table>
      </>)}
    </Page>
  );
}

// ---- Response actions -----------------------------------------------------------------------

interface Proposal {
  proposal_id: string; resource_id: string; payload: { cidr: string; minutes: number }; status: string;
  status_reason: string | null; author: string; author_kind: string; reason: string; diff_sha256: string;
  preview: null | { coverage: string; addresses_affected: number; protected_path_conflicts: string[];
    conflicting_rules: string[]; rendered_change: { format: string; text: string };
    automatic_apply_allowed: boolean; host_state: string };
  approvals: { approver: string; decision: string; reason: string }[];
  executions: { kind: string; status: string; verification: unknown }[];
  created_at: string; expires_at: string;
}
interface Resource { resource_id: string; name: string; adapter: string; mode: string; policy_revision: number;
  protected_cidrs: string[]; policy_snapshot: { rules: { rule_id: string; cidr: string; expires_at: string }[] } }

export function ResponsesPage({ user }: { user: User }) {
  const props = useLoad<Proposal[]>(() => get("/api/v1/responses"), []);
  const res = useLoad<Resource[]>(() => get("/api/v1/response/resources"), [props.data]);
  const [form, setForm] = useState({ cidr: "", minutes: 60, reason: "" });
  const [err, setErr] = useState<string | null>(null);
  const act = async (fn: () => Promise<unknown>) => {
    setErr(null);
    try { await fn(); await props.reload(); } catch (e) { setErr(message(e)); }
  };
  const resource = res.data?.[0];
  const propose = (e: FormEvent) => {
    e.preventDefault();
    if (!resource) return;
    void act(() => post("/api/v1/responses", { resource_id: resource.resource_id, ...form }));
  };
  const askReason = (what: string) => window.prompt(`Reason to ${what}:`) ?? "";
  return (
    <Page title="Response actions" loadedAt={props.loadedAt}>
      <p className="muted small">Typed, time-limited blocks on managed resources. Proposal → preview → independent approval → execute (idempotent) → verify → rollback. Simulation mode: host network configuration is never touched.</p>
      {err && <ErrorBox error={err} />}
      {res.data?.map((r) => (
        <div key={r.resource_id} className="card">
          <strong>{r.name}</strong> <span className="muted small">{r.adapter} · {r.mode} · policy r{r.policy_revision} · protected {r.protected_cidrs.join(", ")}</span>
          <div className="small">Active rules: {r.policy_snapshot.rules.length === 0 ? "none" : r.policy_snapshot.rules.map((x) => `${x.cidr} until ${utc(x.expires_at)}`).join("; ")}</div>
        </div>
      ))}
      {can(user, "responses:propose") && resource && (
        <form className="card row" onSubmit={propose}>
          <input aria-label="CIDR" placeholder="CIDR, e.g. 203.0.113.0/24" value={form.cidr} onChange={(e) => setForm({ ...form, cidr: e.target.value })} required />
          <input aria-label="Minutes" type="number" min={5} max={1440} value={form.minutes} onChange={(e) => setForm({ ...form, minutes: Number(e.target.value) })} />
          <input aria-label="Reason" className="grow" placeholder="Reason / evidence" value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} required minLength={3} />
          <button type="submit">Propose</button>
        </form>
      )}
      {props.data && props.data.length === 0 && <Empty>No proposals.</Empty>}
      {props.data?.map((p) => (
        <div key={p.proposal_id} className="card">
          <div className="row">
            <Status s={p.status} /> <strong>block {p.payload.cidr} for {p.payload.minutes} min</strong>
            <span className="muted small">by {p.author} ({p.author_kind}) · {utc(p.created_at)}</span>
          </div>
          <div className="small">{p.reason}{p.status_reason ? ` — ${p.status_reason}` : ""}</div>
          {p.preview && (
            <div className="facts">
              <Fact k={`Exact change (${p.preview.rendered_change.format})`}><span className="mono small">{p.preview.rendered_change.text}</span></Fact>
              <Fact k="Addresses affected">{p.preview.addresses_affected}</Fact>
              <Fact k="Coverage">{p.preview.coverage}</Fact>
              <Fact k="Protected-path conflicts">{p.preview.protected_path_conflicts.join(", ") || "none"}</Fact>
              <Fact k="Conflicting rules">{p.preview.conflicting_rules.join(", ") || "none"}</Fact>
              <Fact k="Host state">{p.preview.host_state}</Fact>
              <Fact k="Diff hash"><span className="mono small">{p.diff_sha256.slice(0, 16)}…</span></Fact>
            </div>
          )}
          {p.approvals.map((a, i) => <div key={i} className="small">{a.decision} by {a.approver}: {a.reason}</div>)}
          {p.executions.map((x, i) => <div key={i} className="small">{x.kind}: {x.status}</div>)}
          <div className="row">
            {can(user, "responses:propose") && ["proposed", "approval_pending"].includes(p.status) &&
              <button className="ghost" onClick={() => void act(() => post(`/api/v1/responses/${p.proposal_id}/preview`))}>Preview</button>}
            {can(user, "responses:approve") && p.status === "approval_pending" && (<>
              <button onClick={() => { const r = askReason("approve"); if (r) void act(() => post(`/api/v1/responses/${p.proposal_id}/approve`, { reason: r })); }}>Approve</button>
              <button className="ghost" onClick={() => { const r = askReason("deny"); if (r) void act(() => post(`/api/v1/responses/${p.proposal_id}/deny`, { reason: r })); }}>Deny</button>
            </>)}
            {can(user, "responses:execute") && p.status === "approved" &&
              <button onClick={() => void act(() => post(`/api/v1/responses/${p.proposal_id}/execute`, undefined, { "Idempotency-Key": `ui-${p.proposal_id}` }))}>Execute (simulation)</button>}
            {can(user, "responses:execute") && ["verified", "partial"].includes(p.status) &&
              <button className="ghost" onClick={() => { const r = askReason("roll back"); if (r) void act(() => post(`/api/v1/responses/${p.proposal_id}/rollback`, { reason: r }, { "Idempotency-Key": `ui-rb-${p.proposal_id}` })); }}>Roll back</button>}
          </div>
        </div>
      ))}
    </Page>
  );
}

// ---- Audit, health, settings, disabled modules ------------------------------------------------

export function AuditPage() {
  const { data, error, loadedAt } = useLoad<{ items: { id: number; actor: string; action: string; target_type: string | null; target_id: string | null; outcome: string; at: string; details: unknown }[]; total: number }>(
    () => get("/api/v1/audit?limit=200"), []);
  return (
    <Page title={`Audit log${data ? ` (${data.total})` : ""}`} loadedAt={loadedAt}>
      <p className="muted small">Append-only: the application database role cannot update or delete audit rows.</p>
      {error && <ErrorBox error={error} />}
      {data && (
        <table><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th><th>Details</th></tr></thead>
          <tbody>{data.items.map((a) => (
            <tr key={a.id}><td className="mono">{utc(a.at)}</td><td className="mono small">{a.actor}</td><td>{a.action}</td>
              <td className="mono small">{a.target_type ? `${a.target_type}:${a.target_id ?? ""}` : "—"}</td><td>{a.outcome}</td>
              <td className="mono small">{JSON.stringify(a.details)}</td></tr>))}</tbody></table>
      )}
    </Page>
  );
}

export function HealthPage() {
  const ready = useLoad<{ status: string; checks: Record<string, string>; profile: string }>(() => get("/api/v1/ready"), [], 10000);
  const sys = useLoad<{ components: { name: string; status: string; required: boolean; detail?: string }[]; queue: Record<string, number> }>(
    () => get("/api/v1/system/status"), [], 10000);
  return (
    <Page title="System health" loadedAt={sys.loadedAt}>
      {ready.error && <ErrorBox error={ready.error} />}
      {ready.data && <div className="facts">
        <Fact k="Readiness"><Status s={ready.data.status} /></Fact>
        <Fact k="Profile">{ready.data.profile}</Fact>
        {Object.entries(ready.data.checks).map(([k, v]) => <Fact key={k} k={k}>{v}</Fact>)}
      </div>}
      {sys.data && (<>
        <table><thead><tr><th>Component</th><th>Required</th><th>Status</th><th>Detail</th></tr></thead>
          <tbody>{sys.data.components.map((c) => (
            <tr key={c.name}><td>{c.name}</td><td>{c.required ? "yes" : "optional"}</td><td><Status s={c.status} /></td><td className="small muted">{c.detail ?? ""}</td></tr>))}</tbody></table>
        <h3>Processing queue</h3>
        <Counts data={sys.data.queue} empty="" />
      </>)}
    </Page>
  );
}

export function SettingsPage({ user }: { user: User }) {
  const policy = useLoad<Record<string, unknown>>(() => get("/api/v1/ai/policy"), []);
  const [msg, setMsg] = useState<string | null>(null);
  const toggleWrites = async () => {
    if (!policy.data) return;
    try {
      await put("/api/v1/ai/policy", { provider: policy.data.provider, allow_tools: policy.data.allow_tools,
        allow_write_proposals: !policy.data.allow_write_proposals, share_principals: policy.data.share_principals,
        max_requests_per_day: policy.data.max_requests_per_day, reason: "changed from dashboard settings" });
      await policy.reload();
      setMsg("AI policy updated (new revision, audited).");
    } catch (e) { setMsg(message(e)); }
  };
  return (
    <Page title="Settings">
      <div className="facts">
        <Fact k="User">{user.username}</Fact>
        <Fact k="Tenant"><span className="mono">{user.tenant_id}</span></Fact>
        <Fact k="Roles">{user.roles.join(", ")}</Fact>
      </div>
      <h3>Capabilities granted by your roles</h3>
      <p className="small">{user.capabilities.join(", ")}</p>
      <h3>Tenant AI policy</h3>
      {policy.data && <Json value={policy.data} />}
      {can(user, "ai:policy") && policy.data && (
        <button className="ghost" onClick={() => void toggleWrites()}>
          {policy.data.allow_write_proposals ? "Disallow" : "Allow"} AI-drafted response proposals
        </button>
      )}
      {msg && <div className="info">{msg}</div>}
    </Page>
  );
}

export function DisabledPage({ title, reason }: { title: string; reason: string }) {
  return (
    <Page title={title}>
      <div className="card disabled-module">
        <Status s="disabled" /> <strong>This module is not implemented in this release.</strong>
        <p>{reason}</p>
        <p className="muted small">Nothing on this page is simulated or estimated. See docs/handoff/RELEASE.md for status and next steps.</p>
      </div>
    </Page>
  );
}
