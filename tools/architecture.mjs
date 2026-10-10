// Architecture rules for the extension source. Run with `pnpm check:arch`.
//
// Each rule exists because breaking it fails at runtime inside Freelens, not at
// build time. See docs/ARCHITECTURE.md for the reasons.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

// The extension only reads from the cluster, with one exception: Rescan deletes a report so the
// Trivy Operator scans the workload again. That write lives in a single module, listed here, so it
// can be reviewed in one place. Lifting the gate for everything is a deliberate, reviewed change:
// flip the flag in a commit of its own and say why in the message.
export const ALLOW_CLUSTER_WRITES = false;
export const WRITE_ALLOWLIST = ["src/renderer/api/trivy/rescan.ts"];

// withErrorPage itself, and the factories that render their page through it
const ERROR_BOUNDARIES = new Set(["withErrorPage", "createReportListPage"]);
// `remove*` are the store's own deletes (they call the API's delete).
const WRITE_METHODS = new Set([
  "patch",
  "delete",
  "create",
  "update",
  "apply",
  "remove",
  "removeItems",
  "removeSelectedItems",
  "removeWithOptions",
]);
const KUBE_OBJECT_BASE = /(^|\.)LensExtensionKubeObject$/;
const REQUIRED_STATICS = ["kind", "namespaced", "apiBase", "crd"];

const isTest = (path) => /\.(test|spec)\.tsx?$/.test(path);
const isGeneratedDts = (path) => path.endsWith(".d.scss.ts");

function layerOf(path) {
  const m = /^src\/([^/]+)\//.exec(path);
  return m ? m[1] : null;
}

function lineOf(sf, node) {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
}

function hasStatic(member) {
  return (ts.getCombinedModifierFlags(member) & ts.ModifierFlags.Static) !== 0;
}

function memberName(member) {
  return member.name && ts.isIdentifier(member.name) ? member.name.text : null;
}

/**
 * @param {{path: string, text: string}[]} files paths are repo-relative, "/" separated
 * @param {{allowWrites?: boolean}} [options]
 * @returns {{file: string, line: number, rule: string, message: string}[]}
 */
export function checkArchitecture(files, options = {}) {
  const allowWrites = options.allowWrites ?? ALLOW_CLUSTER_WRITES;
  const out = [];

  for (const { path, text } of files) {
    if (isGeneratedDts(path)) continue;
    const sf = ts.createSourceFile(
      path,
      text,
      ts.ScriptTarget.Latest,
      true,
      path.endsWith("x") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
    );
    const add = (node, rule, message) => out.push({ file: path, line: lineOf(sf, node), rule, message });
    const layer = layerOf(path);
    let callsErrorBoundary = false;

    const visit = (node) => {
      // layer-direction: main, renderer and common must not reach into each other
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier) &&
        node.moduleSpecifier.text.startsWith(".")
      ) {
        const target = layerOf(posix.join(posix.dirname(path), node.moduleSpecifier.text) + "/");
        const forbidden = { main: ["renderer"], renderer: ["main"], common: ["main", "renderer"] }[layer] ?? [];
        if (target && forbidden.includes(target)) {
          add(node, "layer-direction", `src/${layer} must not import from src/${target}`);
        }
      }

      // kubeobject-*: classes that model a CRD
      if (ts.isClassDeclaration(node) && node.heritageClauses) {
        const extendsKubeObject = node.heritageClauses.some(
          (h) =>
            h.token === ts.SyntaxKind.ExtendsKeyword &&
            h.types.some((t) => KUBE_OBJECT_BASE.test(t.expression.getText(sf))),
        );
        if (extendsKubeObject) {
          for (const m of node.members) {
            const instanceLogic =
              (ts.isMethodDeclaration(m) || ts.isGetAccessor(m) || ts.isSetAccessor(m)) && !hasStatic(m);
            if (instanceLogic) {
              add(
                m,
                "kubeobject-static-only",
                `"${memberName(m) ?? "member"}" is an instance method; Freelens hands out plain object copies, use a static method`,
              );
            }
          }
          const statics = new Set(node.members.filter(hasStatic).map(memberName));
          for (const required of REQUIRED_STATICS) {
            if (!statics.has(required)) {
              add(node, "kubeobject-shape", `${node.name?.text ?? "class"} is missing "static ${required}"`);
            }
          }
        }
      }

      // read-only-gate: no writes through stores or APIs
      if (
        !allowWrites &&
        !WRITE_ALLOWLIST.includes(path) &&
        !isTest(path) &&
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        WRITE_METHODS.has(node.expression.name.text) &&
        /store|api|apimanager/i.test(node.expression.expression.getText(sf))
      ) {
        add(
          node,
          "read-only-gate",
          `"${node.expression.name.text}" writes to the cluster; only ${WRITE_ALLOWLIST.join(", ")} may (Rescan)`,
        );
      }

      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && ERROR_BOUNDARIES.has(node.expression.text)) {
        callsErrorBoundary = true;
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);

    // page-error-boundary: a page that throws must not take Freelens' panel down
    if (/^src\/renderer\/pages\/[^/]+\.tsx$/.test(path) && !isTest(path) && !callsErrorBoundary) {
      out.push({
        file: path,
        line: 1,
        rule: "page-error-boundary",
        message: "page does not render through withErrorPage() or a factory that does",
      });
    }
  }
  return out;
}

function walk(dir, acc = []) {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) walk(p, acc);
    else if (/\.tsx?$/.test(e.name)) acc.push(p);
  }
  return acc;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const root = join(dirname(fileURLToPath(import.meta.url)), "..");
  const files = walk(join(root, "src")).map((p) => ({
    path: p
      .slice(root.length + 1)
      .split("\\")
      .join("/"),
    text: readFileSync(p, "utf8"),
  }));
  const violations = checkArchitecture(files);
  for (const v of violations) console.error(`${v.file}:${v.line}  [${v.rule}]  ${v.message}`);
  console.log(`architecture: ${files.length} files, ${violations.length} violation(s)`);
  process.exit(violations.length ? 1 : 0);
}
