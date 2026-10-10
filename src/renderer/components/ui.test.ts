import { describe, expect, it } from "vitest";
import { barSegments } from "./ui";

const counts = (critical: number, high: number, medium: number, low: number) => ({
  critical,
  high,
  medium,
  low,
  unknown: 0,
});

describe("barSegments", () => {
  it("is empty when there are no findings", () => {
    expect(barSegments(counts(0, 0, 0, 0))).toEqual([]);
  });
  it("sums to 100 and skips empty severities", () => {
    const segments = barSegments(counts(1, 0, 3, 6));
    expect(segments.map((s) => s.key)).toEqual(["critical", "medium", "low"]);
    expect(segments.reduce((sum, s) => sum + s.percent, 0)).toBeCloseTo(100);
  });
  it("keeps a rare critical finding visible", () => {
    const [critical] = barSegments(counts(1, 0, 0, 5000));
    expect(critical.percent).toBeGreaterThan(1.5);
  });
  it("draws unknown severity last, so a report with only unknown findings still has a bar", () => {
    const only = barSegments({ critical: 0, high: 0, medium: 0, low: 0, unknown: 20 });
    expect(only.map((s) => s.key)).toEqual(["unknown"]);
    const mixed = barSegments({ critical: 1, high: 0, medium: 0, low: 1, unknown: 2 });
    expect(mixed.map((s) => s.key)).toEqual(["critical", "low", "unknown"]);
  });
});
