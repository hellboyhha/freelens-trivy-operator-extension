// Verifies the packed tarball is something Freelens can load and that nothing
// the host provides got bundled. Run `pnpm build` first. Run with `pnpm check:pack`.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ALLOWED = [/^package\/package\.json$/, /^package\/(LICENSE|NOTICE|README\.md)$/, /^package\/out\/.+/];
// Signatures of react and mobx internals: they appear only when the library itself was bundled.
const BUNDLED_LIBRARY = /__SECRET_INTERNALS_DO_NOT_USE|ReactCurrentOwner|Symbol\.for\(["']mobx/;
const HOST_SHIM = /\/_virtual\/_global-external_/;
const MAX_UNPACKED_BYTES = 2_000_000;

/** @returns {string[]} problems */
export function inspectPackage({ files, manifest, outSources, unpackedBytes }) {
  const problems = [];
  for (const f of files) if (!ALLOWED.some((re) => re.test(f))) problems.push(`unexpected file in tarball: ${f}`);
  for (const key of ["main", "renderer"]) {
    if (!manifest[key]) problems.push(`package.json has no "${key}"`);
    else if (!files.includes(`package/${manifest[key]}`))
      problems.push(`"${key}" points at ${manifest[key]}, which is not in the tarball`);
  }
  if (!/^\^1\.\d+/.test(manifest.engines?.freelens ?? "")) {
    problems.push(`engines.freelens must be a ^1.x range, found "${manifest.engines?.freelens}"`);
  }
  if (manifest.license !== "MIT") problems.push(`license must be MIT, found "${manifest.license}"`);
  if (Object.keys(manifest.dependencies ?? {}).length) {
    problems.push("runtime dependencies are not installed by Freelens; bundle them or provide them as host globals");
  }
  for (const [file, src] of Object.entries(outSources)) {
    // The build writes one shim per host global (global.React ...) that re-exports every
    // name of the library; those names include the internals, but the code is the host's.
    if (HOST_SHIM.test(file)) continue;
    if (BUNDLED_LIBRARY.test(src))
      problems.push(`${file} contains react or mobx internals; they must stay host globals`);
  }
  if (unpackedBytes > MAX_UNPACKED_BYTES)
    problems.push(`unpacked size ${unpackedBytes} bytes exceeds ${MAX_UNPACKED_BYTES}`);
  return problems;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const tmp = mkdtempSync(join(tmpdir(), "pack-check-"));
  try {
    execFileSync("pnpm", ["pack", "--pack-destination", tmp], { cwd: root, stdio: "pipe" });
    const tgz = join(
      tmp,
      readdirSync(tmp).find((f) => f.endsWith(".tgz")),
    );
    const files = execFileSync("tar", ["-tzf", tgz])
      .toString()
      .split("\n")
      .filter((f) => f && !f.endsWith("/"));
    execFileSync("tar", ["-xzf", tgz, "-C", tmp]);
    const manifest = JSON.parse(readFileSync(join(tmp, "package", "package.json"), "utf8"));
    const outSources = {};
    let unpackedBytes = 0;
    for (const f of files) {
      const buf = readFileSync(join(tmp, f));
      unpackedBytes += buf.length;
      if (f.endsWith(".js")) outSources[f] = buf.toString("utf8");
    }
    const problems = inspectPackage({ files, manifest, outSources, unpackedBytes });
    for (const p of problems) console.error(p);
    console.log(`pack: ${files.length} files, ${unpackedBytes} bytes, ${problems.length} problem(s)`);
    process.exitCode = problems.length ? 1 : 0;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
