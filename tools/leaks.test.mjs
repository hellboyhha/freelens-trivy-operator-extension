import { describe, expect, it } from "vitest";
import { scanText } from "./leaks.mjs";

const rules = (text, denylist) => scanText("f.txt", text, denylist).map((h) => h.rule);

describe("leaks", () => {
  it("flags private IPs", () => {
    expect(rules("host: 10.20.30.40")).toEqual(["private-ip"]); // leak-check:allow
    expect(rules("host: 172.20.1.1")).toEqual(["private-ip"]); // leak-check:allow
    expect(rules("host: 192.168.0.5")).toEqual(["private-ip"]); // leak-check:allow
  });
  it("does not flag public or non-private ranges", () => {
    expect(rules("1.1.1.1 and 172.32.0.1 and version 10.2.3")).toEqual([]);
  });
  it("flags tokens and keys", () => {
    expect(rules("-----BEGIN RSA PRIVATE KEY-----")).toEqual(["private-key"]); // leak-check:allow
    expect(rules(`t = "ghp_${"a".repeat(30)}"`)).toEqual(["github-token"]); // leak-check:allow
    expect(rules("client-key-data: abc")).toEqual(["kube-credential"]); // leak-check:allow
  });
  it("flags internal hostnames", () => {
    expect(rules("api.example.internal")).toEqual(["internal-hostname"]); // leak-check:allow
  });
  it("honours the local denylist, case-insensitively", () => {
    expect(rules("Some SecretWord here", ["secretword"])).toEqual(["denylist"]);
  });
  it("honours the allow marker", () => {
    expect(rules("10.1.1.1 // leak-check:allow")).toEqual([]);
  });
});
