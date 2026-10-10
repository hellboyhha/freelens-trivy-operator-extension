import { readFileSync } from "node:fs";
import { join } from "node:path";

/** A synthetic report from test/fixtures/<name>.json. Tests run from the repository root. */
export function fixture(name: string): any {
  return JSON.parse(readFileSync(join(process.cwd(), "test", "fixtures", `${name.toLowerCase()}.json`), "utf8"));
}
