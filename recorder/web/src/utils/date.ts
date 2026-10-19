import dayjs from "dayjs";
import relativeTime from "dayjs/plugin/relativeTime";
import utc from "dayjs/plugin/utc";

dayjs.extend(relativeTime);
dayjs.extend(utc);

export function fmtDate(iso?: string): string {
  if (!iso) return "—";
  const d = dayjs.utc(iso);
  return d.isValid() ? `${d.format("YYYY-MM-DD HH:mm:ss")} UTC` : iso;
}

export function timeAgo(iso?: string): string {
  if (!iso) return "—";
  const d = dayjs(iso);
  return d.isValid() ? d.fromNow() : iso;
}

export function duration(start?: string, end?: string): string {
  if (!start || !end) return "—";
  const ms = dayjs(end).diff(dayjs(start));
  if (isNaN(ms) || ms < 0) return "—";
  const s = Math.round(ms / 1000);
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return m > 0 ? `${m}m ${rem}s` : `${rem}s`;
}
