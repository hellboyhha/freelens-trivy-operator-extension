/** Short age like "5m", "3h", "12d" from an ISO timestamp; "N/A" when there is none. */
export function formatAge(timestamp: string | undefined, now: Date = new Date()): string {
  if (!timestamp) return "N/A";
  const then = Date.parse(timestamp);
  if (Number.isNaN(then)) return "N/A";
  const seconds = Math.max(0, Math.floor((now.getTime() - then) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return days < 365 ? `${days}d` : `${Math.floor(days / 365)}y`;
}

/** The first `max` items and how many were left out. */
export function limited<T>(items: T[], max: number): { shown: T[]; hidden: number } {
  return items.length <= max ? { shown: items, hidden: 0 } : { shown: items.slice(0, max), hidden: items.length - max };
}
