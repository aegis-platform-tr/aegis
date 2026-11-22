import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError, setToken, setUnauthorizedHandler, type User } from "./api";
import { EventView, IncidentList, IncidentView } from "./pages/Incidents";
import {
  AgentsPage, AiPage, AuditPage, DisabledPage, HealthPage, ResponsesPage, RulesPage, SettingsPage,
} from "./pages/Manage";
import { AlertsPage, EventsPage, OverviewPage } from "./pages/Monitoring";
import { NetworkPage } from "./pages/Network";
import { can, go } from "./ui";

interface NavItem { key: string; label: string; capability?: string; disabled?: boolean }

const NAV: NavItem[] = [
  { key: "overview", label: "Overview" },
  { key: "network", label: "Network monitoring", capability: "network:read" },
  { key: "assets", label: "Network assets", disabled: true },
  { key: "events", label: "Live security events", capability: "events:read" },
  { key: "ids", label: "IDS/IPS alerts", capability: "alerts:read" },
  { key: "ddos", label: "DDoS monitoring", capability: "network:read" },
  { key: "firewall", label: "Firewall management", capability: "responses:read" },
  { key: "ai", label: "AI security gateway", capability: "ai:use" },
  { key: "ai-intel", label: "AI threat intelligence", disabled: true },
  { key: "intel", label: "Threat intelligence", disabled: true },
  { key: "incidents", label: "Incidents", capability: "incidents:read" },
  { key: "alerts", label: "All alerts", capability: "alerts:read" },
  { key: "responses", label: "Response actions", capability: "responses:read" },
  { key: "rules", label: "Detection rules", capability: "rules:read" },
  { key: "agents", label: "Agent management", capability: "agents:read" },
  { key: "audit", label: "Audit logs", capability: "audit:read" },
  { key: "health", label: "System health" },
  { key: "settings", label: "Settings" },
];

const DISABLED: Record<string, string> = {
  assets: "Asset inventory and inferred topology (DHCP/inventory context, interface/VLAN, edge age and evidence) are planned. Today assets are only the asset_id strings carried on events.",
  "ai-intel": "ML-based threat intelligence is intentionally not shipped: there is no labeled data to train or evaluate a model honestly. Explainable statistical signals live under Network monitoring.",
  intel: "External threat-intelligence feeds require connectors, licensing review and an outbound data policy. No feed is integrated and no indicator data is shown.",
};

type Route = { view: string; id?: string; from?: string };

function parseRoute(): Route {
  const [view = "overview", id, from] = window.location.hash.replace(/^#\/?/, "").split("/");
  return { view: view || "overview", id: id ? decodeURIComponent(id) : undefined, from };
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
    try { await api.logout(); } finally { setToken(null); setUser(null); }
  };
  return (
    <div className="shell">
      <header className="topbar">
        <button className="brand" onClick={() => go("#/overview")}>AEGIS</button>
        <ModeBadge />
        <span className="spacer" />
        <span className="who">{user.username} · <span className="mono">{user.tenant_id}</span> · {user.roles.join(", ")}</span>
        <button className="ghost" onClick={logout}>Sign out</button>
      </header>
      <div className="layout">
        <nav aria-label="Modules">
          {NAV.map((n) => {
            const allowed = !n.capability || can(user, n.capability);
            const active = route.view === n.key;
            return (
              <a key={n.key} href={`#/${n.key}`} className={`${active ? "active" : ""} ${!allowed || n.disabled ? "off" : ""}`}
                aria-current={active ? "page" : undefined}
                title={n.disabled ? "Not implemented in this release" : !allowed ? "Your role lacks access" : undefined}>
                {n.label}{n.disabled && <span className="tag">disabled</span>}
              </a>
            );
          })}
        </nav>
        <main><Routed route={route} user={user} /></main>
      </div>
    </div>
  );
}

function Routed({ route, user }: { route: Route; user: User }) {
  const item = NAV.find((n) => n.key === route.view);
  if (item?.disabled) return <DisabledPage title={item.label} reason={DISABLED[item.key] ?? ""} />;
  if (item?.capability && !can(user, item.capability))
    return <DisabledPage title={item.label} reason={`Your role does not grant ${item.capability}.`} />;
  switch (route.view) {
    case "incidents": return route.id ? <IncidentView id={route.id} user={user} /> : <IncidentList user={user} />;
    case "events": return route.id ? <EventView id={route.id} from={route.from} /> : <EventsPage />;
    case "alerts": return <AlertsPage />;
    case "ids": return <AlertsPage idsOnly />;
    case "network": case "ddos": return <NetworkPage />;
    case "firewall": case "responses": return <ResponsesPage user={user} />;
    case "ai": return <AiPage user={user} />;
    case "rules": return <RulesPage user={user} />;
    case "agents": return <AgentsPage user={user} />;
    case "audit": return <AuditPage />;
    case "health": return <HealthPage />;
    case "settings": return <SettingsPage user={user} />;
    default: return <OverviewPage />;
  }
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
      {state.profile.toUpperCase()} · {state.ok ? "API ready" : "API degraded"}
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
        <label>Username<input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" /></label>
        <label>Password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required /></label>
        {error && <div className="error" role="alert">{error}</div>}
        <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}
