// The extension uses Freelens' own font and sizes: nothing here may set a typeface of its own.
//
// Freelens sets Roboto once on the page (`--font-main`) and gives sizes and weights as tokens
// (`--font-size`, `--font-size-small`, `--font-size-big`, `--font-weight-*`). A stylesheet that names its
// own font, or sizes text in fixed units, makes the extension look different from the host around it.
// This reads every stylesheet and the TSX, so a custom font cannot come back unnoticed.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = fileURLToPath(new URL(".", import.meta.url));

const walk = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
  );

const files = walk(root);
const styles = files.filter((f) => f.endsWith(".scss"));
const sources = files.filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f));

interface Declaration {
  file: string;
  property: string;
  value: string;
}

const declarations: Declaration[] = styles.flatMap((file) => {
  const text = readFileSync(file, "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\/\/.*$/gm, "");
  return [...text.matchAll(/([a-z-]+)\s*:\s*([^;{}]+);/g)].map((m) => ({
    file: file.slice(root.length),
    property: m[1],
    value: m[2].trim().replace(/\s+/g, " "),
  }));
});

const offenders = (keep: (d: Declaration) => boolean, wanted?: string) =>
  declarations
    .filter((d) => (wanted ? d.property === wanted : true))
    .filter((d) => !keep(d))
    .map((d) => `${d.file}: ${d.property}: ${d.value}`);

const SIZE = /^(inherit|var\(--font-size(-small|-big)?\)|calc\(var\(--font-size(-small|-big)?\) \* [\d.]+\))$/;
const WEIGHT = /^(inherit|var\(--font-weight-(normal|medium|semibold|bold)\))$/;

describe("the extension's stylesheets follow the Freelens font", () => {
  it("reads the stylesheets it is meant to check", () => {
    expect(styles.length).toBeGreaterThan(5);
    expect(declarations.length).toBeGreaterThan(100);
  });

  it("never sets a typeface; the page's Roboto is inherited", () => {
    expect(offenders(() => false, "font-family")).toEqual([]);
    expect(offenders(() => false, "font-feature-settings")).toEqual([]);
  });

  it("uses `font` only to inherit it, which is how buttons and inputs take the page's font", () => {
    expect(offenders((d) => d.value === "inherit", "font")).toEqual([]);
  });

  it("sizes text from the host's tokens, or as a multiple of the host's size", () => {
    expect(offenders((d) => SIZE.test(d.value), "font-size")).toEqual([]);
  });

  it("takes weights from the host's tokens", () => {
    expect(offenders((d) => WEIGHT.test(d.value), "font-weight")).toEqual([]);
  });

  it("adds no spacing, case or digit styling the host does not use", () => {
    for (const property of ["letter-spacing", "text-transform", "font-variant-numeric", "line-height"]) {
      expect(
        offenders(() => false, property),
        property,
      ).toEqual([]);
    }
  });

  it("leaves the table header to Freelens, so every list's header looks like the host's own", () => {
    const restyled = styles.filter((file) => /TableHead/.test(readFileSync(file, "utf8")));
    expect(restyled.map((file) => file.slice(root.length))).toEqual([]);
  });
});

describe("the components do not style type inline", () => {
  it("has no fontFamily, fontSize, fontWeight, letterSpacing or textTransform in the TSX or TS", () => {
    const found = sources.flatMap((file) =>
      readFileSync(file, "utf8")
        .split("\n")
        .flatMap((line, index) =>
          /\b(fontFamily|fontSize|fontWeight|letterSpacing|textTransform|lineHeight)\b/.test(line)
            ? [`${file.slice(root.length)}:${index + 1}: ${line.trim()}`]
            : [],
        ),
    );
    expect(found).toEqual([]);
  });
});
