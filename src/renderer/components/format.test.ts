import { describe, expect, it } from "vitest";
import { formatAge, limited } from "./format";

const now = new Date("2026-01-15T12:00:00Z");

describe("formatAge", () => {
  it("picks the largest unit", () => {
    expect(formatAge("2026-01-15T11:59:30Z", now)).toBe("30s");
    expect(formatAge("2026-01-15T11:15:00Z", now)).toBe("45m");
    expect(formatAge("2026-01-15T09:00:00Z", now)).toBe("3h");
    expect(formatAge("2026-01-03T12:00:00Z", now)).toBe("12d");
    expect(formatAge("2024-01-15T12:00:00Z", now)).toBe("2y");
  });
  it("is N/A for missing or invalid input and never negative", () => {
    expect(formatAge(undefined, now)).toBe("N/A");
    expect(formatAge("garbage", now)).toBe("N/A");
    expect(formatAge("2026-01-15T13:00:00Z", now)).toBe("0s");
  });
});

describe("limited", () => {
  it("cuts a long list and counts the rest", () => {
    expect(limited([1, 2, 3, 4], 2)).toEqual({ shown: [1, 2], hidden: 2 });
    expect(limited([1, 2], 5)).toEqual({ shown: [1, 2], hidden: 0 });
  });
});
