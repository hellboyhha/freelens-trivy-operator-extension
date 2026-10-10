// Small shared pieces: the severity bar, chips, tabs, banners, empty states, and the cells the
// lists use. Plain elements and theme variables only, so they look right in any Freelens theme.

import React from "react";
import { type SeverityCounts, totalCount } from "../api/trivy/report-model";
import { TrivyIcon } from "../icons";
import styles from "./ui.module.scss";
import stylesInline from "./ui.module.scss?inline";

/** Render once per page or drawer so the classes exist. */
export function UiStyles() {
  return <style>{stylesInline}</style>;
}

const cx = (...names: (string | false | undefined)[]) => names.filter(Boolean).join(" ");

/** Widths in percent of a severity bar, with a floor so a rare finding stays visible. */
export function barSegments(counts: SeverityCounts): { key: keyof SeverityCounts; percent: number }[] {
  const keys: (keyof SeverityCounts)[] = ["critical", "high", "medium", "low", "unknown"];
  const total = keys.reduce((sum, key) => sum + counts[key], 0);
  if (total === 0) return [];
  const raw = keys.map((key) => ({ key, count: counts[key], percent: (counts[key] / total) * 100 }));
  const floor = 2;
  const boosted = raw.map((s) => (s.count > 0 ? { ...s, percent: Math.max(s.percent, floor) } : s));
  const sum = boosted.reduce((acc, s) => acc + s.percent, 0);
  return boosted.filter((s) => s.count > 0).map((s) => ({ key: s.key, percent: (s.percent / sum) * 100 }));
}

const SEGMENT_CLASS = {
  critical: styles.segCritical,
  high: styles.segHigh,
  medium: styles.segMedium,
  low: styles.segLow,
  unknown: styles.segLow,
};

export function SeverityBar({ counts }: { counts: SeverityCounts }) {
  return (
    <div className={styles.bar}>
      {barSegments(counts).map((segment) => (
        <i key={segment.key} className={SEGMENT_CLASS[segment.key]} style={{ width: `${segment.percent}%` }} />
      ))}
    </div>
  );
}

/**
 * The severity of one report in a table cell: a thin proportional bar and the four counts in the
 * order critical, high, medium, low. Only critical and high are coloured; zeros are faint.
 */
export function SeverityCell({ counts }: { counts: SeverityCounts }) {
  const keys = ["critical", "high", "medium", "low"] as const;
  if (totalCount(counts) === 0) return <span className={styles.muted}>no findings</span>;
  const label = [
    ...keys.map((key) => `${counts[key]} ${key}`),
    ...(counts.unknown > 0 ? [`${counts.unknown} unknown`] : []),
  ].join(", ");
  return (
    <div className={styles.sevCell} aria-label={label} title={label}>
      <SeverityBar counts={counts} />
      <span className={styles.sevNumbers}>
        {keys.map((key) => (
          <span key={key} className={cx(styles.sevNum, counts[key] === 0 ? styles.sevZero : styles[`sevNum_${key}`])}>
            {counts[key]}
          </span>
        ))}
        {counts.unknown > 0 ? <span className={styles.sevUnknown}>+{counts.unknown} unknown</span> : null}
      </span>
    </div>
  );
}

/** A two-part bar: the share that passes next to the share that fails. */
export function PassFailBar({ passing, failing }: { passing: number; failing: number }) {
  const total = passing + failing;
  return (
    <div className={styles.bar}>
      {total > 0 ? (
        <>
          <i className={styles.segOk} style={{ width: `${(passing / total) * 100}%` }} />
          <i className={styles.segCritical} style={{ width: `${(failing / total) * 100}%` }} />
        </>
      ) : null}
    </div>
  );
}

export function Dot({ tone }: { tone: "critical" | "high" | "medium" | "low" | "ok" }) {
  const toneClass = {
    critical: styles.segCritical,
    high: styles.segHigh,
    medium: styles.segMedium,
    low: styles.segLow,
    ok: styles.segOk,
  }[tone];
  return <i className={cx(styles.dot, toneClass)} />;
}

export function Legend({ children }: { children: React.ReactNode }) {
  return <div className={styles.legend}>{children}</div>;
}

export interface ChipOption {
  id: string;
  label: string;
}

/** A row of toggle chips. `selected` holds the ids that are on. */
export function Chips(props: {
  options: ChipOption[];
  selected: ReadonlySet<string>;
  onToggle: (id: string) => void;
  /** No outer margin: the parent spaces it. */
  flush?: boolean;
}) {
  return (
    <div className={styles.chips} style={props.flush ? { margin: 0 } : undefined} role="group" aria-label="Filters">
      {props.options.map((option) => (
        <button
          key={option.id}
          type="button"
          className={cx(styles.chip, props.selected.has(option.id) && styles.chipOn)}
          aria-pressed={props.selected.has(option.id)}
          onClick={() => props.onToggle(option.id)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Segmented<T extends string>(props: {
  /** What the switch chooses, read out by screen readers. */
  label: string;
  options: { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <span className={styles.segmented} role="group" aria-label={props.label}>
      {props.options.map((option) => (
        <button
          key={option.id}
          type="button"
          className={cx(styles.segmentedItem, props.value === option.id && styles.segmentedOn)}
          aria-pressed={props.value === option.id}
          onClick={() => props.onChange(option.id)}
        >
          {option.label}
        </button>
      ))}
    </span>
  );
}

export function Tabs<T extends string>(props: {
  tabs: { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className={styles.tabs} role="tablist">
      {props.tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          aria-selected={props.value === tab.id}
          className={cx(styles.tab, props.value === tab.id && styles.tabOn)}
          onClick={() => props.onChange(tab.id)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export function Banner({ children, tone = "warning" }: { children: React.ReactNode; tone?: "warning" | "info" }) {
  return (
    <div className={cx(styles.banner, tone === "info" && styles.bannerInfo)}>
      <span>{tone === "info" ? "ⓘ" : "⚠"}</span>
      <div>{children}</div>
    </div>
  );
}

/**
 * A message in place of content: the Trivy mark, a title, short paragraphs, and the action to take.
 * Paragraphs and the action are spaced here, so a page only supplies the words.
 */
export function EmptyState(props: {
  icon?: React.ReactNode;
  title: string;
  children?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className={styles.empty}>
      <div className={styles.emptyIcon}>{props.icon ?? <TrivyIcon size={44} />}</div>
      <h5>{props.title}</h5>
      <div className={styles.emptyBody}>{props.children}</div>
      {props.actions ? <div className={styles.emptyActions}>{props.actions}</div> : null}
    </div>
  );
}

export function Button(props: { onClick: () => void; primary?: boolean; children: React.ReactNode }) {
  return (
    <button type="button" className={cx(styles.button, props.primary && styles.buttonPrimary)} onClick={props.onClick}>
      {props.children}
    </button>
  );
}

export function CodeBlock({ children }: { children: string }) {
  return <code className={styles.code}>{children}</code>;
}

/** Name over `namespace · Kind`: what a row is about, in two lines. */
export function TwoLine({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className={styles.two} title={subtitle ? `${title}\n${subtitle}` : title}>
      <b>{title}</b>
      {subtitle ? <span>{subtitle}</span> : null}
    </div>
  );
}

/** `repository:tag` with the tag highlighted; the registry host stays out of the way. */
export function ImageName({ repository, tag, title }: { repository?: string; tag?: string; title?: string }) {
  if (!repository) return <span className={styles.muted}>N/A</span>;
  return (
    <span className={styles.image} title={title}>
      {repository}
      {tag ? (
        <>
          :<em>{tag}</em>
        </>
      ) : null}
    </span>
  );
}

export function Muted({ children }: { children: React.ReactNode }) {
  return <span className={styles.muted}>{children}</span>;
}

export function Fixable({ children }: { children: React.ReactNode }) {
  return <span className={styles.fixable}>{children}</span>;
}

export function Skeleton({ count = 4 }: { count?: number }) {
  return (
    <>
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className={styles.skeleton} />
      ))}
    </>
  );
}
