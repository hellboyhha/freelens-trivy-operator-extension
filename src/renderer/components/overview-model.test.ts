import { describe, expect, it } from "vitest";
import { fixture } from "../../../test/fixtures";
import {
  benchmarkRows,
  distinctImages,
  fixableTotal,
  fixFirst,
  headline,
  mostExposed,
  sourceState,
  summarizeKind,
  tileAvailability,
} from "./overview-model";

const item = (c: number, h: number, m = 0, l = 0) => ({
  report: { summary: { criticalCount: c, highCount: h, mediumCount: m, lowCount: l } },
});

describe("summarizeKind", () => {
  it("sums over several lists", () => {
    const s = summarizeKind([item(1, 2), item(0, 1)], [item(2, 0, 0, 5)]);
    expect(s.reports).toBe(3);
    expect(s.counts).toEqual({ critical: 3, high: 3, medium: 0, low: 5, unknown: 0 });
    expect(s.total).toBe(11);
  });
  it("copes with reports that have no summary", () => {
    expect(summarizeKind([{}, { report: {} }]).total).toBe(0);
  });
});

describe("fixableTotal", () => {
  it("counts vulnerabilities with a fixed version", () => {
    expect(fixableTotal([fixture("vulnerabilityreport")], [fixture("clustervulnerabilityreport")])).toBe(4);
  });
});

describe("mostExposed", () => {
  it("orders by critical, then high, and drops clean reports", () => {
    const a = item(0, 9);
    const b = item(1, 0);
    const c = item(1, 3);
    const clean = item(0, 0);
    expect(mostExposed([a, b, c, clean], 10)).toEqual([c, b, a]);
  });
  it("respects the limit", () => {
    expect(mostExposed([item(1, 0), item(2, 0), item(3, 0)], 2)).toHaveLength(2);
  });
});

describe("benchmarkRows", () => {
  it("lists the failing benchmarks first", () => {
    const rows = benchmarkRows([
      {
        metadata: { name: "ok" },
        spec: { compliance: { title: "OK" } },
        status: { summary: { failCount: 0, passCount: 9 } },
      },
      fixture("clustercompliancereport"),
    ]);
    expect(rows.map((r) => r.id)).toEqual(["demo-benchmark", "ok"]);
    expect(rows[0]).toMatchObject({ title: "Demo Benchmark v1.0", failing: 1, passing: 1 });
  });
});

describe("headline", () => {
  it("counts critical findings, the distinct images they are in, and the ones with a fix", () => {
    const h = headline([fixture("vulnerabilityreport")], [fixture("clustervulnerabilityreport")]);
    expect(h).toMatchObject({ critical: 2, criticalImages: 1, criticalFixable: 2, lastScan: "2026-01-15T10:00:00Z" });
  });
  it("is quiet when there is nothing", () => {
    expect(headline([])).toEqual({ critical: 0, criticalImages: 0, criticalFixable: 0, lastScan: undefined });
  });
});

describe("fixFirst", () => {
  const withFixes = (c: number, h: number, fixed: number) => ({
    report: {
      summary: { criticalCount: c, highCount: h },
      vulnerabilities: Array.from({ length: fixed }, () => ({ severity: "HIGH" as const, fixedVersion: "1" })),
    },
  });
  it("ranks by critical, then high, then fixable, and leaves out lower-severity-only reports", () => {
    const a = withFixes(0, 9, 1);
    const b = withFixes(2, 0, 0);
    const c = withFixes(2, 5, 3);
    const low = { report: { summary: { mediumCount: 40 } } };
    expect(fixFirst([a, b, c, low], 10).map((r) => r.item)).toEqual([c, b, a]);
  });
  it("reports how many findings an upgrade clears", () => {
    expect(fixFirst([fixture("vulnerabilityreport")], 5)[0]).toMatchObject({
      critical: 1,
      high: 1,
      total: 3,
      fixable: 2,
    });
  });
  it("respects the limit", () => {
    expect(fixFirst([withFixes(1, 0, 0), withFixes(2, 0, 0)], 1)).toHaveLength(1);
  });
});

describe("distinctImages", () => {
  const rep = (repository: string, tag: string, digest = "") => ({ report: { artifact: { repository, tag, digest } } });
  it("counts an image once however many workloads run it", () => {
    expect(
      distinctImages([rep("db", "1", "d1"), rep("db", "1", "d1"), rep("db", "1", "d1"), rep("web", "2", "d2")]),
    ).toBe(2);
  });
  it("tells two digests of one tag apart, and skips reports with no artifact", () => {
    expect(distinctImages([rep("db", "1", "d1"), rep("db", "1", "d2"), {}, { report: {} }])).toBe(2);
  });
});

describe("headline counts images, not reports", () => {
  const heavy = (digest: string) => ({
    report: {
      summary: { criticalCount: 2 },
      artifact: { repository: "db", tag: "1", digest },
      vulnerabilities: [{ severity: "CRITICAL" as const, fixedVersion: "2" }],
    },
  });
  it("counts three replicas of one image as one image", () => {
    expect(headline([heavy("d1"), heavy("d1"), heavy("d1")])).toMatchObject({ critical: 6, criticalImages: 1 });
  });
});

describe("sourceState", () => {
  it("tells a missing kind from one that failed, is loading, or is ready", () => {
    expect(sourceState(null)).toBe("unavailable");
    expect(sourceState({ isLoaded: false, failedLoading: true })).toBe("failed");
    expect(sourceState({ isLoaded: false, failedLoading: false })).toBe("loading");
    expect(sourceState({ isLoaded: true })).toBe("ok");
  });
});

describe("tileAvailability", () => {
  it("is available when every source is", () => {
    expect(tileAvailability(["ok", "ok"])).toEqual({ available: true, missing: 0, reason: undefined });
  });
  it("is unavailable when no source is, saying why", () => {
    expect(tileAvailability(["unavailable", "unavailable"])).toEqual({
      available: false,
      missing: 2,
      reason: "unavailable",
    });
    expect(tileAvailability(["failed", "unavailable"])).toEqual({ available: false, missing: 2, reason: "failed" });
  });
  it("shows what it has but counts the sources it lacks", () => {
    expect(tileAvailability(["ok", "unavailable", "failed", "ok"])).toEqual({
      available: true,
      missing: 2,
      reason: undefined,
    });
  });
  it("does not count a source that is still loading as missing", () => {
    expect(tileAvailability(["ok", "loading"])).toEqual({ available: true, missing: 0, reason: undefined });
  });
});

describe("fixFirst rows carry every severity", () => {
  it("keeps the full counts for the severity cell", () => {
    expect(fixFirst([item(1, 2, 3, 4)], 5)[0].counts).toMatchObject({ critical: 1, high: 2, medium: 3, low: 4 });
  });
});
