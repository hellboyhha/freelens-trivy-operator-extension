# Development

## Toolchain

Node.js 22 (see `.nvmrc`) and pnpm 10 (see `packageManager` in `package.json`). If your global Node is
older, install both in a scratch folder and put it first on `PATH`:

```sh
mkdir -p /tmp/trivy-ext-tools && cd /tmp/trivy-ext-tools
npm init -y && npm i node@22 pnpm@10
export PATH=/tmp/trivy-ext-tools/node_modules/.bin:$PATH
```

## Everyday commands

| Command | What it does |
|---|---|
| `pnpm check` | Full gate: lint, types, architecture, leaks, unused code, tests, build, package |
| `pnpm check:fast` | Lint, types, architecture and leaks only (the pre-commit hook) |
| `pnpm test` | Unit tests |
| `pnpm biome:fix` | Format and fix lint |
| `pnpm pack:dev` | Build and write the `.tgz` to install in Freelens |

## Trying it in Freelens

There is no hot reload. The loop is: change, `pnpm pack:dev`, in Freelens (Extensions, `Cmd/Ctrl+Shift+E`)
remove the old copy and install the new `.tgz`, reopen the cluster. Bump the version in `package.json`
(`0.1.0-dev.N`) for each build you install, so Freelens does not treat it as the copy it already has.

## A local cluster with data

The pages need Trivy Operator reports. A small local cluster is enough:

```sh
minikube start -p trivy --cpus=4 --memory=8192
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm install trivy-operator aqua/trivy-operator -n trivy-system --create-namespace \
  --set operator.sbomGenerationEnabled=true
```

Then deploy a few workloads with known problems (an old `nginx`, an image that bakes in a secret, a
privileged pod, a ServiceAccount bound to `cluster-admin`). Reports appear after a few minutes. Use a
separate kubeconfig file for the cluster so a test run cannot reach a real one.

## Checking against real data

Dump the report kinds read-only (`kubectl get <kind> -A -o json`) into a scratch folder outside the
repository and render every list and drawer over them in a throwaway test. This catches data shapes the
fixtures do not have. Delete the test afterwards and never commit the dump.

## Tests and the stub host

`test/freelens-extensions.ts` replaces `@freelensapp/extensions`. Its list layout applies `filterItems`
and `customizeHeader` the way the host does; without that, tests of chips and headers pass without
proving anything. Layout problems (width, row height) only show in the real app.
