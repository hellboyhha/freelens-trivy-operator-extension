# Security policy

## Reporting a vulnerability

Please report it privately through GitHub:
[Report a vulnerability](https://github.com/hellboyhha/freelens-trivy-operator-extension/security/advisories/new).
Do not open a public issue for it.

Include the extension and Freelens versions and the steps to reproduce. This is a one-person project, so
answers are on a best-effort basis, but a report is read and acknowledged.

## Supported versions

Only the latest release gets fixes.

## What the extension can do to a cluster

It reads the Trivy Operator report resources and, for scan status, the operator's Jobs and pods. It writes
in one case: **Rescan** deletes the report resources you select so the operator scans those workloads
again. That is a single module, `src/renderer/api/trivy/rescan.ts`, and the build fails if a cluster write
appears anywhere else. It makes no network requests of its own, collects no data, and has no runtime
dependencies.
