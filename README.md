# freelens-trivy-operator-extension

[Freelens](https://freelens.app/) extension for the
[Trivy Operator](https://aquasecurity.github.io/trivy-operator/): browse the
vulnerability, config audit, exposed secret, RBAC, infra assessment, SBOM and
compliance reports the operator writes to your cluster, without leaving Freelens.

> **Status: scaffold.** The extension builds and loads with a placeholder
> "Trivy" sidebar entry. Report pages are in development.

## Requirements

- Freelens 1.10 or later in the 1.x line (the 2.x API is not supported yet)
- Kubernetes with the Trivy Operator CRDs (`aquasecurity.github.io/v1alpha1`)

## Build from source

Node.js >= 22 and pnpm 10 are required.

```sh
pnpm install
pnpm build
pnpm pack:dev   # writes freelens-trivy-operator-extension-<version>.tgz
```

In Freelens open Extensions (`Cmd/Ctrl+Shift+E`) and drop the `.tgz` into the
window, or give it the file path.

## License

[MIT](LICENSE). Based on the Freelens example extension; see [NOTICE](NOTICE).
