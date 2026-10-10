// The single gate. `pnpm check` runs everything, `pnpm check:fast` the quick subset.
// The pre-commit hook, the pre-push hook and CI all call this; nothing else defines "passing".
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const fast = process.argv.includes("--fast");

const STEPS = [
  { name: "lint", cmd: ["pnpm", "biome:check"], fast: true },
  { name: "types", cmd: ["pnpm", "type:check"], fast: true },
  { name: "architecture", cmd: ["node", "tools/architecture.mjs"], fast: true },
  { name: "leaks", cmd: ["node", "tools/leaks.mjs"], fast: true },
  { name: "unused code", cmd: ["pnpm", "knip"], fast: false },
  { name: "tests", cmd: ["pnpm", "test"], fast: false },
  { name: "build", cmd: ["pnpm", "build"], fast: false },
  { name: "package", cmd: ["node", "tools/pack.mjs"], fast: false, needs: "build" },
];

const results = [];
for (const step of STEPS) {
  if (fast && !step.fast) continue;
  if (step.needs && results.find((r) => r.name === step.needs)?.status !== "pass") {
    results.push({ name: step.name, status: "skipped" });
    continue;
  }
  console.log(`\n── ${step.name} ${"─".repeat(Math.max(0, 60 - step.name.length))}`);
  const started = Date.now();
  const r = spawnSync(step.cmd[0], step.cmd.slice(1), { cwd: root, stdio: "inherit" });
  results.push({
    name: step.name,
    status: r.status === 0 ? "pass" : "FAIL",
    seconds: ((Date.now() - started) / 1000).toFixed(1),
  });
}

console.log("\n── summary ─────────────────────────────────────────────────");
for (const r of results) console.log(`${r.status.padEnd(8)} ${r.name}${r.seconds ? `  (${r.seconds}s)` : ""}`);
const failed = results.filter((r) => r.status === "FAIL");
console.log(failed.length ? `\n${failed.length} check(s) failed` : "\nall checks passed");
process.exit(failed.length ? 1 : 0);
