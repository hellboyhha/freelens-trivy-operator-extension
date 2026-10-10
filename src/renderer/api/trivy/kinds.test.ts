import { describe, expect, it } from "vitest";
import { fixture } from "../../../../test/fixtures";
import { ALL_REPORT_KINDS } from "./index";

describe("the 12 Trivy Operator kinds", () => {
  it("covers every kind the CRDs define", () => {
    expect(ALL_REPORT_KINDS.map((k) => k.kind).sort()).toEqual(
      [
        "ClusterComplianceReport",
        "ClusterConfigAuditReport",
        "ClusterInfraAssessmentReport",
        "ClusterRbacAssessmentReport",
        "ClusterSbomReport",
        "ClusterVulnerabilityReport",
        "ConfigAuditReport",
        "ExposedSecretReport",
        "InfraAssessmentReport",
        "RbacAssessmentReport",
        "SbomReport",
        "VulnerabilityReport",
      ].sort(),
    );
  });

  for (const Kind of ALL_REPORT_KINDS) {
    describe(Kind.kind, () => {
      it("has a consistent CRD descriptor", () => {
        expect(Kind.apiBase).toBe(`/apis/aquasecurity.github.io/v1alpha1/${Kind.crd.plural}`);
        expect(Kind.crd.apiVersions).toEqual(["aquasecurity.github.io/v1alpha1"]);
        expect(Kind.crd.title).not.toBe("");
        // the operator names every cluster scoped kind "Cluster…"
        expect(Kind.namespaced).toBe(!Kind.kind.startsWith("Cluster"));
      });

      it("matches its fixture", () => {
        const sample = fixture(Kind.kind);
        expect(sample.kind).toBe(Kind.kind);
        expect(sample.apiVersion).toBe(Kind.crd.apiVersions[0]);
        expect(Boolean(sample.metadata.namespace)).toBe(Kind.namespaced);
      });

      it("keeps the report data the host assigns in the constructor", () => {
        const sample = fixture(Kind.kind);
        const object = new Kind(sample) as unknown as { report?: unknown; spec?: unknown };
        if (Kind.kind === "ClusterComplianceReport") expect(object.spec).toEqual(sample.spec);
        else expect(object.report).toEqual(sample.report);
      });
    });
  }
});
