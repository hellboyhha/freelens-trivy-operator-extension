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

  it("colour every severity count through its own exported class", () => {
    const ui = readFileSync(join(root, "components/ui.tsx"), "utf8");
    for (const name of ["sevNumCritical", "sevNumHigh", "sevNumMedium", "sevNumLow"])
      expect(ui, name).toMatch(new RegExp(`styles\\.${name}`));
  });

  it("give the four counts the colours the bars and tiles use, so a level looks the same everywhere", () => {
    const scss = readFileSync(join(root, "components/ui.module.scss"), "utf8");
    const rule = (name: string) => new RegExp(`\\.${name}\\s*\\{([^}]*)\\}`).exec(scss)?.[1] ?? "";
    expect(rule("sevNumCritical")).toMatch(/color:\s*var\(--colorError\)/);
    expect(rule("sevNumHigh")).toMatch(/color:\s*var\(--colorWarning\)/);
    expect(rule("sevNumMedium")).toMatch(
      /color:\s*color-mix\(in srgb, var\(--colorWarning\) 40%, var\(--textColorSecondary\)\)/,
    );
    expect(rule("sevNumLow")).toMatch(/color:/);
  });
});
