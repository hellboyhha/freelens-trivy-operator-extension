// Conventional Commits check. Used by the commit-msg hook and by CI on PR titles.
//   node tools/commit-msg.mjs <message-file>
//   git log --format=%s main..HEAD | node tools/commit-msg.mjs --stdin
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const TYPES = ["feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert"];
const HEADER = new RegExp(`^(${TYPES.join("|")})(\\([a-z0-9._/-]+\\))?!?: \\S.*$`);
const MAX_HEADER = 72;

/** @returns {string[]} problems, empty when the message is fine */
export function validateMessage(message) {
  const lines = message.split("\n").filter((l) => !l.startsWith("#"));
  const header = (lines[0] ?? "").trimEnd();
  if (/^(Merge |Revert ")/.test(header)) return [];
  const problems = [];
  if (!HEADER.test(header)) {
    problems.push(`header must look like "type(scope): subject" with type one of: ${TYPES.join(", ")}`);
  }
  if (header.length > MAX_HEADER) problems.push(`header is ${header.length} characters, the limit is ${MAX_HEADER}`);
  if (/[.]$/.test(header)) problems.push("header must not end with a period");
  if (lines.length > 1 && lines[1].trim() !== "") problems.push("leave a blank line between the header and the body");
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const arg = process.argv[2];
  const messages =
    arg === "--stdin" ? readFileSync(0, "utf8").split("\n").filter(Boolean) : [readFileSync(arg, "utf8")];
  let failed = 0;
  for (const m of messages) {
    const problems = validateMessage(m);
    for (const p of problems) console.error(`commit message "${m.split("\n")[0]}": ${p}`);
    failed += problems.length ? 1 : 0;
  }
  process.exit(failed ? 1 : 0);
}
