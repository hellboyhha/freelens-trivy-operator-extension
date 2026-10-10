import { describe, expect, it } from "vitest";
import { maybe } from "./utils";

describe("maybe", () => {
  it("returns the value", () => {
    expect(maybe(() => 3)).toBe(3);
  });
  it("returns null when the function throws", () => {
    expect(
      maybe(() => {
        throw new Error("x");
      }),
    ).toBeNull();
  });
});
