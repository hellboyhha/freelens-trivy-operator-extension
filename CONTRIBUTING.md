# Contributing

## Ground rules

- **One gate.** `pnpm check` must pass before anything is merged. It runs lint, types, the architecture
  rules, the leak scan, unused-code detection, the tests, the build and a package check.
- **Reads, with one write.** The only cluster write is Rescan (deleting a report so the operator scans
  again), and it lives in `src/renderer/api/trivy/rescan.ts`. `tools/architecture.mjs` fails the build for a
  write anywhere else (`WRITE_ALLOWLIST`). Any new write is a deliberate change of its own.
- **No real data.** Fixtures in `test/fixtures` are synthetic. Do not commit cluster names, hostnames,
  registry addresses or anything that identifies a company or a person. `pnpm check:leaks` looks for it.
- **Tests first.** Write the failing test, see it fail, then write the code.

## Branches and commits

- `main` plus short-lived branches named `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`,
  `ci/<topic>`, `refactor/<topic>` or `test/<topic>`.
- Commit messages follow Conventional Commits, `type(scope): subject`, header at most 72 characters.
  A hook rejects anything else. Put detail in the body.
- Install the hooks once with `pnpm hooks:install`.

## A change, step by step

1. Branch from `main`.
2. Write the test, run `pnpm test`, watch it fail.
3. Write the code.
4. Run `pnpm check`.
5. Commit.

Tests run against a stub of the Freelens host (`test/freelens-extensions.ts`). They prove wiring and
logic, not how the page looks in Freelens, so describe what you saw in the real app in the change.

## Releasing

1. Move the notes from `## [Unreleased]` in `CHANGELOG.md` under a new `## [x.y.z] - <date>` heading and
   set the same version in `package.json`.
2. Merge to `main`, then tag it: `git tag vx.y.z && git push origin vx.y.z`.
3. The `release` workflow checks that the tag, the package version and the changelog agree, runs
   `pnpm check`, packs the extension and publishes a GitHub release with the `.tgz` and `SHA256SUMS`.

Run the workflow by hand from the Actions tab to rehearse it: it does everything except publish.

### Publishing to npm, by hand

npm is published by a maintainer from a clean checkout of the tagged commit, not from CI, so nothing has
to be stored in the repository. `out/` is not in git, so build it first or npm would upload a stale bundle:

```sh
pnpm pack:dev      # writes out/ and a .tgz
npm publish        # needs a granular access token with Bypass 2FA in ~/.npmrc
```

The token must be **Read and write (publish and stage)** for the `@hellboyhha` scope with **Bypass 2FA**
ticked. A **"Read and write (stage only)"** token cannot publish directly: `npm publish` is accepted
(HTTP 202) and leaves only a `0.0.0-stage` placeholder on the registry while the version waits to be
approved, so check `npm view <package> versions` afterwards rather than trusting the `+` line.

Keep the token in the global `~/.npmrc`, never in a `.npmrc` inside the repository, which `.gitignore`
does not cover.
