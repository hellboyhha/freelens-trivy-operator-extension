// Release helper for the workflow in .github/workflows/release.yaml.
//
//   node tools/release-notes.mjs --check <tag>   fails unless the tag, package.json and CHANGELOG.md agree
//   node tools/release-notes.mjs <tag>           prints the changelog section of that version
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** The body of `## [<version>]` in a Keep-a-Changelog file, up to the next version heading. */
export function notesFor(changelog, version) {
  const heading = new RegExp(`^## \\[${escape(version)}\\](?:\\s.*)?$`, "m");
  const start = heading.exec(changelog);
  if (!start) return "";
  const rest = changelog.slice(start.index + start[0].length);
  const next = /^## \[/m.exec(rest);
  return (next ? rest.slice(0, next.index) : rest).trim();
}

/** @returns {string[]} what is wrong with releasing `tag`, empty when it can go out */
export function checkRelease({ tag, version, changelog }) {
  const problems = [];
  if (tag !== `v${version}`)
    problems.push(`tag ${tag} does not match package.json version ${version} (expected v${version})`);
  if (/-/.test(version)) problems.push(`version ${version} is a development version`);
  if (!notesFor(changelog, version)) problems.push(`CHANGELOG.md has no notes for ${version}`);
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const check = args[0] === "--check";
  const tag = check ? args[1] : args[0];
  const changelog = readFileSync("CHANGELOG.md", "utf8");
  const version = JSON.parse(readFileSync("package.json", "utf8")).version;
  if (!tag) {
    console.error("usage: node tools/release-notes.mjs [--check] <tag>");
    process.exit(2);
  }
  if (check) {
    const problems = checkRelease({ tag, version, changelog });
    for (const p of problems) console.error(`release: ${p}`);
    process.exit(problems.length ? 1 : 0);
  }
  process.stdout.write(`${notesFor(changelog, tag.replace(/^v/, ""))}\n`);
}
