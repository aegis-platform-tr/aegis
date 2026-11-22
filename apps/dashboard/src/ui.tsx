import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, type User } from "./api";

export function go(hash: string): void {
  window.location.hash = hash;
}

export function can(user: User, capability: string): boolean {
  return user.capabilities.includes(capability);
}

export function useLoad<T>(loader: () => Promise<T>, deps: unknown[], pollMs?: number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadedAt, setLoadedAt] = useState<Date | null>(null);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      setData(await loaderRef.current());
      setError(null);
      setLoadedAt(new Date());
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "unknown", String(e), null));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  useEffect(() => {
    void reload();
    if (!pollMs) return;
    const id = window.setInterval(() => void reload(), pollMs);
    return () => window.clearInterval(id);
  }, [reload, pollMs]);
  return { data, error, loading, reload, setData, loadedAt };
}

export function ErrorBox({ error }: { error: ApiError | string }) {
  const msg = typeof error === "string" ? error : error.message;
  const ref = typeof error === "string" ? null : error.correlationId;
  return (
    <div className="error" role="alert">
      {msg}
      {ref && <span className="mono muted"> · ref {ref}</span>}
    </div>
  );
}

export function Sev({ s }: { s: string }) {
  // Text label plus color: severity stays readable without color.
  return <span className={`sev ${s}`}>{s}</span>;
}

export function Origin({ o }: { o: string }) {
  return <span className={`origin ${o}`} title="Data provenance">{o}</span>;
}

export function Status({ s }: { s: string }) {
  return <span className={`status ${s.replace(/[^a-z_]/g, "")}`}>{s}</span>;
}

export function Fact({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="fact">
      <div className="k">{k}</div>
      <div className="v">{children}</div>
    </div>
  );
}

export function Page({
  title,
  children,
  actions,
  loadedAt,
}: {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
  loadedAt?: Date | null;
}) {
  return (
    <section>
      <div className="row">
        <h2>{title}</h2>
        <span className="spacer" />
        {loadedAt && (
          <span className="muted small" title="Data freshness">
            updated {loadedAt.toISOString().slice(11, 19)}Z
          </span>
        )}
        {actions}
      </div>
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="card empty muted">{children}</div>;
}

export function Json({ value }: { value: unknown }) {
  // Rendered as text: React escapes it, so attacker-controlled content cannot inject markup.
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

export function Counts({ data, empty }: { data: Record<string, number>; empty: string }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return <span className="muted">{empty}</span>;
  return (
    <span className="counts">
      {entries.map(([k, v]) => (
        <span key={k} className="count">
          <strong>{v}</strong> {k}
        </span>
      ))}
    </span>
  );
}

export function message(e: unknown): string {
  return e instanceof ApiError ? e.message : "Request failed";
}
