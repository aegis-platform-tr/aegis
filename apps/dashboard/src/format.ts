// All times are shown in UTC and labeled, so analysts never guess the timezone.
export function utc(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "invalid";
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

export function relative(ts: string): string {
  const diff = Date.now() - new Date(ts).getTime();
  const min = Math.round(diff / 60000);
  if (Math.abs(min) < 60) return `${min} min ago`;
  const h = Math.round(min / 60);
  if (Math.abs(h) < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} d ago`;
}

export const NEXT_STATES: Record<string, string[]> = {
  new: ["investigating", "contained", "resolved", "closed"],
  investigating: ["contained", "resolved", "closed"],
  contained: ["investigating", "resolved", "closed"],
  resolved: ["investigating", "closed"],
  closed: ["investigating"],
};
