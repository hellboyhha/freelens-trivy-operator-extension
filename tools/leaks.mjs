// Scans every tracked and not-ignored file for secrets and internal identifiers.
// Run with `pnpm check:leaks`.
//
// Generic patterns are committed. Project- or employer-specific words go in
// .harness-local/denylist.txt (one case-insensitive substring per line), which is
// gitignored on purpose so the list itself never ships.
// Add `leak-check:allow` on a line to silence it there.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const PATTERNS = [
  [
    "private-ip",
    /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/,
  ],
  ["private-key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ["github-token", /\b(ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}/],
  ["npm-token", /\bnpm_[A-Za-z0-9]{36}\b/],
  ["aws-key", /\bAKIA[0-9A-Z]{16}\b/],
  ["slack-token", /\bxox[baprs]-[A-Za-z0-9-]{10,}/],
  ["jwt", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ["kube-credential", /\b(client-key-data|client-certificate-data|certificate-authority-data)\s*:/],
  ["internal-hostname", /\b[a-z0-9-]+(\.[a-z0-9-]+)*\.(internal|corp|lan)\b/i],
];

const SKIP_FILES = new Set(["pnpm-lock.yaml"]);

/**
 * @param {string} path
 * @param {string} text
 * @param {string[]} [denylist] lowercase substrings
 * @returns {{file: string, line: number, rule: string}[]}
 */
export function scanText(path, text, denylist = []) {
  const hits = [];
  text.split("\n").forEach((line, i) => {
    if (line.includes("leak-check:allow")) return;
    for (const [rule, re] of PATTERNS) if (re.test(line)) hits.push({ file: path, line: i + 1, rule });
    const lower = line.toLowerCase();
    if (denylist.some((w) => lower.includes(w))) hits.push({ file: path, line: i + 1, rule: "denylist" });
  });
  return hits;
}

function listFiles(root) {
  const raw = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { cwd: root });
  return raw.toString("utf8").split("\0").filter(Boolean);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const listPath = join(root, ".harness-local", "denylist.txt");
  const denylist = existsSync(listPath)
    ? readFileSync(listPath, "utf8")
        .split("\n")
        .map((l) => l.trim().toLowerCase())
        .filter((l) => l && !l.startsWith("#"))
    : [];
  let scanned = 0;
  const hits = [];
  for (const rel of listFiles(root)) {
    if (SKIP_FILES.has(rel)) continue;
    const abs = join(root, rel);
    let stat;
    try {
      stat = statSync(abs);
    } catch {
      continue; // deleted but still listed
    }
    if (!stat.isFile() || stat.size > 1_000_000) continue;
    const buf = readFileSync(abs);
    if (buf.includes(0)) continue; // binary
    scanned++;
    hits.push(...scanText(rel, buf.toString("utf8"), denylist));
  }
  for (const h of hits) console.error(`${h.file}:${h.line}  [${h.rule}]`);
  console.log(
    `leaks: ${scanned} files, ${hits.length} hit(s), local denylist ${denylist.length ? `${denylist.length} words` : "absent"}`,
  );
  process.exit(hits.length ? 1 : 0);
}
