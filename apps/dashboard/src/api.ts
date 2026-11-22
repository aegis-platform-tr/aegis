// Typed client for the AEGIS M1 API. Types mirror backend/aegis/api/schemas.py.
// The access token is held in memory only (never localStorage), so a reload requires login.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type IncidentStatus = "new" | "investigating" | "contained" | "resolved" | "closed";

export interface User {
  username: string;
  tenant_id: string;
  roles: string[];
  capabilities: string[];
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
  total: number;
}

export interface EventOut {
  event_id: string;
  schema_version: string;
  event_category: string;
  event_type: string;
  severity: Severity | null;
  occurred_at: string | null;
  observed_at: string;
  ingested_at: string;
  source: { adapter: string; adapter_version: string; native_id: string };
  producer_id: string;
  asset_id: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  principal: string | null;
  attributes: Record<string, unknown>;
  origin: "synthetic" | "observed";
  raw_event_reference: string | null;
  provenance: Record<string, unknown>;
}

export interface AlertOut {
  alert_id: string;
  rule_id: string;
  rule_revision: number;
  title: string;
  severity: Severity;
  confidence: number;
  group_key: Record<string, string>;
  window_start: string;
  window_end: string;
  event_count: number;
  first_event_at: string;
  last_event_at: string;
  evaluated_at: string;
  explanation: string;
  mitre: { framework: string; id: string; name: string; note?: string }[];
  origin: string;
  incident_id: string | null;
  event_ids: string[] | null;
}

export interface IncidentOut {
  incident_id: string;
  title: string;
  status: IncidentStatus;
  severity: Severity;
  priority: string;
  correlation_rule: string;
  correlation_key: string;
  origin: string;
  version: number;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
  last_activity_at: string;
  alert_count: number;
}

export interface TimelineEntry {
  kind: "event" | "alert" | "transition";
  at: string;
  ref_id: string;
  summary: string;
  times: Record<string, string | null>;
  origin: string | null;
}

export interface IncidentDetail extends IncidentOut {
  alerts: AlertOut[];
  timeline: TimelineEntry[];
}

export interface Fixture {
  name: string;
  version: string;
  origin: string;
  description: string;
  event_count: number;
}

export interface IngestResult {
  accepted: number;
  duplicate: number;
  rejected: number;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public correlationId: string | null,
  ) {
    super(message);
  }
}

let token: string | null = null;
let onUnauthorized: () => void = () => {};

export function setToken(t: string | null): void {
  token = t;
}
export function setUnauthorizedHandler(fn: () => void): void {
  onUnauthorized = fn;
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "network_error", "The AEGIS API is unreachable.", null);
  }
  if (res.status === 204) return undefined as T;
  const data: unknown = await res.json().catch(() => null);
  if (!res.ok) {
    const err = (data as { error?: { code?: string; message?: string; correlation_id?: string } })
      ?.error;
    if (res.status === 401 && path !== "/api/v1/auth/login") onUnauthorized();
    throw new ApiError(
      res.status,
      err?.code ?? "http_error",
      err?.message ?? `Request failed (${res.status})`,
      err?.correlation_id ?? null,
    );
  }
  return data as T;
}

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; expires_at: string; user: User }>(
      "POST",
      "/api/v1/auth/login",
      { username, password },
    ),
  logout: () => request<void>("POST", "/api/v1/auth/logout"),
  ready: () =>
    request<{ status: string; checks: Record<string, string>; profile: string }>(
      "GET",
      "/api/v1/ready",
    ),
  incidents: (params: URLSearchParams) =>
    request<Page<IncidentOut>>("GET", `/api/v1/incidents?${params.toString()}`),
  incident: (id: string) =>
    request<IncidentDetail>("GET", `/api/v1/incidents/${encodeURIComponent(id)}`),
  transition: (id: string, status: IncidentStatus, version: number, reason: string) =>
    request<IncidentDetail>("PATCH", `/api/v1/incidents/${encodeURIComponent(id)}`, {
      status,
      version,
      reason,
    }),
  event: (id: string) => request<EventOut>("GET", `/api/v1/events/${encodeURIComponent(id)}`),
  fixtures: () => request<Fixture[]>("GET", "/api/v1/fixtures"),
  importFixture: (name: string) =>
    request<IngestResult>("POST", `/api/v1/fixtures/${encodeURIComponent(name)}/import`),
};
