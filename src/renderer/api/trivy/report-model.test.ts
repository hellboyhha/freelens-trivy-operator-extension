import { describe, expect, it } from "vitest";
import { fixture } from "../../../../test/fixtures";
import {
  addCounts,
  avdUrl,
  compareFindings,
  compareVersions,
  countFixable,
  emptyCounts,
  failedChecks,
  groupByPackage,
  imageOf,
  latestTimestamp,
  matchPackages,
  passedChecks,
  pickFixedVersion,
  resourceLabel,
  resourceOf,
  severityCounts,
  severityRank,
  severityWeight,
  sortedVulnerabilities,
  ticketText,
  totalCount,
  versionKey,
  worstIssue,
} from "./report-model";

describe("severity counts", () => {
  it("reads the summary and defaults missing fields to zero", () => {
    expect(severityCounts({ criticalCount: 2, lowCount: 5 })).toEqual({
      critical: 2,
      high: 0,
      medium: 0,
      low: 5,
      unknown: 0,
    });
    expect(severityCounts(undefined)).toEqual(emptyCounts());
  });
  it("adds and totals", () => {
    const sum = addCounts(severityCounts({ highCount: 1 }), severityCounts({ highCount: 2, criticalCount: 1 }));
    expect(sum).toEqual({ critical: 1, high: 3, medium: 0, low: 0, unknown: 0 });
    expect(totalCount(sum)).toBe(4);
  });
});

describe("sorting", () => {
  it("ranks worst first and unknown values last", () => {
    expect(["LOW", "CRITICAL", "HIGH", "bogus", "MEDIUM"].sort((a, b) => severityRank(a) - severityRank(b))).toEqual([
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
      "bogus",
    ]);
  });
  it("orders vulnerabilities by severity, then score, then id", () => {
    const sorted = sortedVulnerabilities([
      { vulnerabilityID: "B", severity: "HIGH", score: 7 },
      { vulnerabilityID: "A", severity: "HIGH", score: 7 },
      { vulnerabilityID: "C", severity: "HIGH", score: 8 },
      { vulnerabilityID: "D", severity: "CRITICAL", score: 1 },
    ]);
    expect(sorted.map((v) => v.vulnerabilityID)).toEqual(["D", "C", "A", "B"]);
  });
  it("does not mutate its input", () => {
    const input = [{ severity: "LOW" as const }, { severity: "HIGH" as const }];
    sortedVulnerabilities(input);
    expect(input[0].severity).toBe("LOW");
    expect(compareFindings(input[0], input[1])).toBeGreaterThan(0);
  });
});

describe("vulnerability report fixture", () => {
  const { report } = fixture("vulnerabilityreport");
  it("sorts the three findings critical, high, low", () => {
    expect(sortedVulnerabilities(report.vulnerabilities).map((v) => v.severity)).toEqual(["CRITICAL", "HIGH", "LOW"]);
  });
  it("counts the ones with a published fix", () => {
    expect(countFixable(report.vulnerabilities)).toBe(2);
  });
  it("names the image", () => {
    expect(imageOf(report.artifact)).toBe("demo/web:1.4.2");
    expect(imageOf({ repository: "demo/web", digest: "sha256:1" })).toBe("demo/web@sha256:1");
    expect(imageOf(undefined)).toBe("");
  });
});

describe("checks", () => {
  const { report } = fixture("configauditreport");
  it("keeps only failed checks, worst first", () => {
    expect(failedChecks(report.checks).map((c) => c.checkID)).toEqual(["AVD-KSV-0014", "AVD-KSV-0015"]);
    expect(passedChecks(report.checks)).toBe(1);
  });
  it("links only ids from Aqua's database", () => {
    expect(avdUrl("AVD-KSV-0014")).toBe("https://avd.aquasec.com/misconfig/avd-ksv-0014");
    expect(avdUrl("custom-1")).toBeNull();
    expect(avdUrl(undefined)).toBeNull();
  });
});

describe("resourceOf", () => {
  it("reads the labels the operator writes", () => {
    const ref = resourceOf(fixture("vulnerabilityreport").metadata);
    expect(ref).toEqual({ kind: "ReplicaSet", name: "web-5d8f7c9b6", namespace: "demo", container: "web" });
    expect(resourceLabel(ref)).toBe("ReplicaSet/web-5d8f7c9b6");
  });
  it("falls back to the owner reference when the name label is a hash", () => {
    const ref = resourceOf({
      namespace: "demo",
      labels: { "trivy-operator.resource.kind": "Role", "trivy-operator.resource.name-hash": "abc" },
      ownerReferences: [{ kind: "Role", name: "a-very-long-role-name" }],
    });
    expect(ref.name).toBe("a-very-long-role-name");
  });
  it("leaves the name empty for a hashed cluster scoped report", () => {
    const ref = resourceOf({
      labels: { "trivy-operator.resource.kind": "ClusterRole", "trivy-operator.resource.name-hash": "abc" },
    });
    expect(ref).toMatchObject({ kind: "ClusterRole", name: "", namespace: "" });
    expect(resourceLabel(ref)).toBe("ClusterRole");
  });
});

describe("compareVersions", () => {
  it("orders numbers numerically, not as text", () => {
    expect(compareVersions("3.0.9", "3.0.15")).toBeLessThan(0);
    expect(compareVersions("1.10", "1.9")).toBeGreaterThan(0);
    expect(compareVersions("2.0", "2.0")).toBe(0);
  });
  it("treats a longer version as newer and handles Debian suffixes", () => {
    expect(compareVersions("1.2", "1.2.1")).toBeLessThan(0);
    expect(compareVersions("7.88.1-10+deb12u8", "7.88.1-10+deb12u5")).toBeGreaterThan(0);
  });
});

describe("pickFixedVersion", () => {
  it("returns undefined when there is no fix", () => {
    expect(pickFixedVersion("1.0.0", "")).toBeUndefined();
    expect(pickFixedVersion("1.0.0", undefined)).toBeUndefined();
  });
  it("prefers the release line the package is on", () => {
    expect(pickFixedVersion("1.4.0", "1.4.9, 2.0.1")).toBe("1.4.9");
    expect(pickFixedVersion("3.0.0", "1.4.9, 2.0.1")).toBe("2.0.1");
  });
});

describe("groupByPackage", () => {
  const vulns = [
    {
      vulnerabilityID: "CVE-1",
      resource: "libssl3",
      installedVersion: "3.0.11",
      fixedVersion: "3.0.13",
      severity: "HIGH" as const,
      primaryLink: "https://example.com/1",
    },
    {
      vulnerabilityID: "CVE-2",
      resource: "libssl3",
      installedVersion: "3.0.11",
      fixedVersion: "3.0.15",
      severity: "CRITICAL" as const,
    },
    {
      vulnerabilityID: "CVE-3",
      resource: "zlib",
      installedVersion: "1.2.13",
      fixedVersion: "",
      severity: "MEDIUM" as const,
    },
    {
      vulnerabilityID: "CVE-4",
      resource: "curl",
      installedVersion: "7.88",
      fixedVersion: "7.89",
      severity: "HIGH" as const,
    },
  ];
  const groups = groupByPackage(vulns);
  it("groups by package and version, worst package first", () => {
    expect(groups.map((g) => g.name)).toEqual(["libssl3", "curl", "zlib"]);
  });
  it("names the version that clears every fixable finding", () => {
    expect(groups[0]).toMatchObject({ installed: "3.0.11", fixed: "3.0.15", clears: 2, severity: "CRITICAL" });
    expect(groups[0].ids).toEqual(["CVE-2", "CVE-1"]);
    expect(groups[0].findings[1]).toEqual({ id: "CVE-1", link: "https://example.com/1", severity: "HIGH" });
  });
  it("keeps packages without a fix, marked as such", () => {
    expect(groups[2]).toMatchObject({ name: "zlib", fixed: undefined, clears: 0 });
  });
  it("counts severities per package", () => {
    expect(groups[0].counts).toMatchObject({ critical: 1, high: 1 });
  });
  it("is empty for no findings", () => {
    expect(groupByPackage(undefined)).toEqual([]);
  });
});

describe("ticketText", () => {
  it("lists the upgrades and leaves out packages with no fix", () => {
    const groups = groupByPackage([
      {
        vulnerabilityID: "CVE-1",
        resource: "libssl3",
        installedVersion: "3.0.11",
        fixedVersion: "3.0.15",
        severity: "HIGH",
      },
      { vulnerabilityID: "CVE-3", resource: "zlib", installedVersion: "1.2", fixedVersion: "", severity: "LOW" },
    ]);
    const text = ticketText(groups, { workload: "ReplicaSet/web", image: "demo/web:1" });
    expect(text).toContain("Upgrades for ReplicaSet/web (demo/web:1):");
    expect(text).toContain("- libssl3 3.0.11 -> 3.0.15: clears 1 CVE (CVE-1)");
    expect(text).not.toContain("zlib");
  });
  it("says when nothing can be fixed", () => {
    expect(ticketText([], { workload: "w", image: "i" })).toContain("nothing has a published fix");
  });
});

describe("worstIssue and latestTimestamp", () => {
  it("names the worst failed check and counts the rest", () => {
    expect(worstIssue(fixture("configauditreport").report.checks)).toEqual({
      title: "Root file system is not read-only",
      more: 1,
    });
    expect(worstIssue([])).toBeNull();
  });
  it("picks the newest valid timestamp", () => {
    expect(latestTimestamp(["2026-01-01T00:00:00Z", undefined, "garbage", "2026-02-01T00:00:00Z"])).toBe(
      "2026-02-01T00:00:00Z",
    );
    expect(latestTimestamp([])).toBeUndefined();
  });
});

describe("severityWeight", () => {
  const w = (criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0) =>
    severityWeight(severityCounts({ criticalCount, highCount, mediumCount, lowCount }));
  it("ranks a single critical above any number of highs, and so on down", () => {
    expect(w(1)).toBeGreaterThan(w(0, 5000));
    expect(w(0, 1)).toBeGreaterThan(w(0, 0, 5000));
    expect(w(0, 0, 1)).toBeGreaterThan(w(0, 0, 0, 5000));
  });
  it("puts a report with only unknown findings above a clean one and below any real severity", () => {
    const unknownOnly = severityWeight(severityCounts({ unknownCount: 500 }));
    expect(unknownOnly).toBeGreaterThan(w());
    expect(unknownOnly).toBeLessThan(w(0, 0, 0, 1));
  });
  it("breaks ties within a severity by count and gives a clean report zero", () => {
    expect(w(3)).toBeGreaterThan(w(2));
    expect(w()).toBe(0);
  });
});

describe("matchPackages", () => {
  const components = [
    { name: "openssl", version: "3.0.11", purl: "pkg:deb/debian/openssl@3.0.11?distro=debian-12" },
    { name: "libssl3", version: "3.0.11", purl: "pkg:deb/debian/libssl3@3.0.11" },
    { name: "openssl", version: "1.1.1k", purl: "pkg:apk/alpine/openssl@1.1.1k" },
    { name: "zlib", version: "1.2.13", purl: "pkg:deb/debian/zlib@1.2.13" },
  ];
  const names = (query: string) => matchPackages(components, query).map((m) => `${m.name} ${m.version}`);

  it("matches on the name, ignoring case, and lists each match once", () => {
    expect(names("OPENSSL")).toEqual(["openssl 1.1.1k", "openssl 3.0.11"]);
    expect(names("ssl")).toEqual(["libssl3 3.0.11", "openssl 1.1.1k", "openssl 3.0.11"]);
  });
  it("matches on the version", () => {
    expect(names("1.2.13")).toEqual(["zlib 1.2.13"]);
  });
  it("matches on the purl, so an ecosystem or a distro can be searched", () => {
    expect(names("pkg:apk")).toEqual(["openssl 1.1.1k"]);
    expect(names("debian-12")).toEqual(["openssl 3.0.11"]);
  });
  it("needs every word to match the same component", () => {
    expect(names("openssl 3.0")).toEqual(["openssl 3.0.11"]);
    expect(names("zlib 3.0")).toEqual([]);
  });
  it("finds nothing for an empty query or a report without components", () => {
    expect(names("")).toEqual([]);
    expect(names("   ")).toEqual([]);
    expect(matchPackages(undefined, "x")).toEqual([]);
  });
  it("orders matches by name, then oldest version first", () => {
    expect(matchPackages(components, "openssl").map((m) => m.version)).toEqual(["1.1.1k", "3.0.11"]);
  });
});

describe("pre-releases", () => {
  const ordered = ["1.0.0alpha2", "1.0.0beta1", "1.0.0rc1", "1.0.0", "1.0.0-1", "1.0.1"];
  it("sort before the release they lead to, and a packaging revision sorts after it", () => {
    const sorted = [...ordered].reverse().sort((a, b) => versionKey(a).localeCompare(versionKey(b)));
    expect(sorted).toEqual(ordered);
  });
  it("compare the same way in compareVersions", () => {
    expect(compareVersions("1.0.0rc1", "1.0.0")).toBeLessThan(0);
    expect(compareVersions("1.0.0", "1.0.0rc1")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0-1", "1.0.0")).toBeGreaterThan(0);
    expect(compareVersions("2.0.0-rc.1", "2.0.0")).toBeLessThan(0);
  });
  it("leave letter suffixes such as 1.1.1k after the plain release", () => {
    expect(compareVersions("1.1.1k", "1.1.1")).toBeGreaterThan(0);
    expect(compareVersions("1.1.1k", "1.1.1l")).toBeLessThan(0);
  });
});

describe("versionKey", () => {
  it("sorts versions as people read them, not as text", () => {
    const sorted = ["1.10", "1.9", "3.0.15", "3.0.9", "2"].sort((a, b) => versionKey(a).localeCompare(versionKey(b)));
    expect(sorted).toEqual(["1.9", "1.10", "2", "3.0.9", "3.0.15"]);
  });
  it("copes with a missing version", () => {
    expect(versionKey(undefined)).toBe("");
  });
});
