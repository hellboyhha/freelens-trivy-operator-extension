# Changelog

All notable changes are written here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.2] - 10 October 2026

### Fixed

- The Export menu no longer pushes the page down when it opens. It is positioned over the list again.

## [0.1.0] - 10 October 2026

First release.

### Added

- A **Trivy Operator** entry in the cluster sidebar with six pages: Overview, Vulnerabilities,
  Misconfigurations (config audit, RBAC and infrastructure), Secrets, SBOM and Compliance.
- An Overview with a one-sentence headline, tiles, the images where an upgrade pays off most, and the
  state of each compliance benchmark.
- Lists with severity bars, filter chips, namespaced and cluster-scoped views, and search.
- Report drawers that group vulnerabilities by package, with the version to upgrade to and a "Copy for
  ticket" action. A Trivy Operator section on Pod, Deployment, StatefulSet, DaemonSet, Job and CronJob
  drawers, with one card per container.
- SBOM package search: find a package by name, version or purl and see every workload that contains it.
- **Rescan**: tick workloads and rescan them from the toolbar, a report drawer or a workload's page. It asks
  first, and several at once need the cluster's name typed in.
- Scan status for a rescanned row: Queued, Starting scan, Scanning, or Scan failed with the reason.
- **Export** of the ticked reports as CSV (one row per report or per finding) or JSON.
