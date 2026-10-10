import styles from "./severity-count.module.scss";
import stylesInline from "./severity-count.module.scss?inline";

import type { SeverityKey } from "../api/trivy/report-model";

/** Render once per page or drawer so the classes below exist. */
export function SeverityStyles() {
  return <style>{stylesInline}</style>;
}

export interface SeverityCountProps {
  severity: SeverityKey;
  count: number;
}

/** A finding count as a pill in the severity's colour; a muted dash when there is none. */
export function SeverityCount({ severity, count }: SeverityCountProps) {
  if (count === 0) return <span className={[styles.pill, styles.zero].join(" ")}>–</span>;
  return <span className={[styles.pill, styles[severity]].join(" ")}>{count}</span>;
}

/** The severity as the operator writes it ("CRITICAL"), as a pill. */
export function SeverityLabel({ severity }: { severity?: string }) {
  const key = (severity ?? "unknown").toLowerCase();
  const known = key === "critical" || key === "high" || key === "medium" || key === "low";
  return <span className={[styles.pill, styles[known ? key : "unknown"]].join(" ")}>{severity ?? "UNKNOWN"}</span>;
}
