// CSS modules here use `localsConvention: "camelCaseOnly"`, so `.sevNum_critical` is exposed as
// `styles.sevNumCritical`. A class looked up with a built-up name (`styles[`sevNum_${key}`]`) silently
// returns undefined, TypeScript does not object, and the style is never applied. Look classes up by their
// exact property name, or through a typed map.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL(".", import.meta.url));
const walk = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
  );
const sources = walk(root).filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f) && !f.endsWith(".d.scss.ts"));

describe("CSS module class lookups", () => {
  it("never build a class name with a template string", () => {
    const offenders = sources
      .filter((file) => /styles\[\s*`/.test(readFileSync(file, "utf8")))
      .map((file) => file.slice(root.length));
    expect(offenders).toEqual([]);
  });

  it("colour the critical and high counts through their exported classes", () => {
    const ui = readFileSync(join(root, "components/ui.tsx"), "utf8");
    expect(ui).toMatch(/styles\.sevNumCritical/);
    expect(ui).toMatch(/styles\.sevNumHigh/);
  });
});
