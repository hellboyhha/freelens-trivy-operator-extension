import { describe, expect, it, vi } from "vitest";
import { classifyError, rescanAcross, rescanReports } from "./rescan";

const item = (name: string, namespace = "demo") => ({ metadata: { name, namespace, uid: name } });

describe("classifyError", () => {
  it("recognises a forbidden answer however the host words it", () => {
    expect(classifyError({ code: 403, message: "nope" }).reason).toBe("forbidden");
    expect(
      classifyError(new Error('vulnerabilityreports.aquasecurity.github.io "x" is forbidden: User "a" cannot delete'))
        .reason,
    ).toBe("forbidden");
    expect(classifyError({ status: 403 }).reason).toBe("forbidden");
  });
  it("recognises a report that is already gone", () => {
    expect(classifyError({ code: 404 }).reason).toBe("gone");
    expect(classifyError(new Error('vulnerabilityreports "x" not found')).reason).toBe("gone");
  });
  it("reads the shape the host really throws: a wrapper holding the cluster's Status object", () => {
    const wrapped = (status: object, messages: string[]) => ({ error: status, messages });
    const forbidden = classifyError(
      wrapped(
        {
          kind: "Status",
          code: 403,
          reason: "Forbidden",
          message: 'vulnerabilityreports "x" is forbidden: cannot delete',
        },
        ['vulnerabilityreports "x" is forbidden: cannot delete'],
      ),
    );
    expect(forbidden.reason).toBe("forbidden");
    expect(forbidden.message).toContain("is forbidden");
    expect(
      classifyError(wrapped({ kind: "Status", code: 404, reason: "NotFound" }, ['vulnerabilityreports "x" not found']))
        .reason,
    ).toBe("gone");
    expect(classifyError(wrapped({ reason: "Forbidden" }, [])).reason).toBe("forbidden");
    expect(classifyError(wrapped({ kind: "Status", code: 500 }, ["etcd timeout", "retry"]))).toEqual({
      reason: "other",
      message: "etcd timeout. retry",
    });
  });

  it("keeps the cluster's own wording for anything else", () => {
    expect(classifyError(new Error("connection refused"))).toEqual({ reason: "other", message: "connection refused" });
    expect(classifyError("plain text")).toEqual({ reason: "other", message: "plain text" });
    expect(classifyError(undefined).message).toBe("Unknown error");
  });
});

describe("rescanReports", () => {
  it("deletes each report through the store and says which were requested", async () => {
    const remove = vi.fn(async () => {});
    const a = item("a");
    const b = item("b");
    const result = await rescanReports({ remove }, [a, b]);
    expect(remove).toHaveBeenCalledTimes(2);
    expect(result.requested).toEqual([a, b]);
    expect(result.gone).toEqual([]);
    expect(result.failed).toEqual([]);
  });

  it("sorts the outcome per report: requested, already gone, failed with a reason", async () => {
    const remove = vi.fn(async (o: ReturnType<typeof item>) => {
      if (o.metadata.name === "gone") throw { code: 404 };
      if (o.metadata.name === "denied") throw new Error("is forbidden: cannot delete");
      if (o.metadata.name === "broken") throw new Error("boom");
    });
    const [ok, gone, denied, broken] = [item("ok"), item("gone"), item("denied"), item("broken")];
    const result = await rescanReports({ remove }, [ok, gone, denied, broken]);
    expect(result.requested).toEqual([ok]);
    expect(result.gone).toEqual([gone]);
    expect(result.failed.map((f) => [f.item.metadata.name, f.reason])).toEqual([
      ["denied", "forbidden"],
      ["broken", "other"],
    ]);
    expect(result.failed[1].message).toBe("boom");
  });

  it("carries on after one failure, so one bad report does not stop the rest", async () => {
    const remove = vi.fn(async (o: ReturnType<typeof item>) => {
      if (o.metadata.name === "a") throw new Error("boom");
    });
    const result = await rescanReports({ remove }, [item("a"), item("b"), item("c")]);
    expect(remove).toHaveBeenCalledTimes(3);
    expect(result.requested).toHaveLength(2);
  });

  it("does nothing for an empty selection", async () => {
    const remove = vi.fn();
    expect(await rescanReports({ remove }, [])).toEqual({ requested: [], gone: [], failed: [] });
    expect(remove).not.toHaveBeenCalled();
  });
});

describe("rescanAcross", () => {
  it("sends each report to the store of its own kind and joins the outcomes", async () => {
    const vuln = { remove: vi.fn(async () => {}) };
    const config = { remove: vi.fn(async () => {}) };
    const a = { ...item("a"), kind: "VulnerabilityReport" };
    const b = { ...item("b"), kind: "ConfigAuditReport" };
    const c = { ...item("c"), kind: "VulnerabilityReport" };
    const result = await rescanAcross((i) => (i.kind === "ConfigAuditReport" ? config : vuln), [a, b, c]);
    expect(vuln.remove).toHaveBeenCalledTimes(2);
    expect(config.remove).toHaveBeenCalledTimes(1);
    expect(result.requested).toEqual([a, c, b]);
  });

  it("fails a report whose kind has no store instead of dropping it silently", async () => {
    const a = item("a");
    const result = await rescanAcross(() => undefined, [a]);
    expect(result.requested).toEqual([]);
    expect(result.failed).toEqual([
      { item: a, reason: "other", message: "This kind of report is not available in this cluster" },
    ]);
  });
});
