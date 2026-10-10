/** Runs `wrapped` and returns null when it throws; for host lookups that may not exist in this cluster. */
export function maybe<T>(wrapped: () => T): T | null {
  try {
    return wrapped();
  } catch {
    return null;
  }
}
