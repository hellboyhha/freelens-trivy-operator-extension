import { describe, expect, it } from "vitest";
import { extensionPageUrl } from "./navigation";

describe("extensionPageUrl", () => {
  it("drops the @ and turns the scope slash into a dash", () => {
    expect(extensionPageUrl("@hellboyhha/freelens-trivy-operator-extension", "trivy-overview")).toBe(
      "/extension/hellboyhha--freelens-trivy-operator-extension/trivy-overview",
    );
  });
  it("leaves an unscoped name alone", () => {
    expect(extensionPageUrl("plain-extension", "p")).toBe("/extension/plain-extension/p");
  });
});
