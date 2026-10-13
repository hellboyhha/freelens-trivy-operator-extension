# Changelog

All notable changes are written here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.4] - 14 October 2026

### Changed

- **Critical, High, Medium and Low are four columns.** Every report list (Vulnerabilities, Exposed Secrets,
  Config Audit, RBAC, Infra, and their cluster-scoped versions) and the Overview's *Fix first* table show a
  labelled column for each severity instead of a bar with four unlabelled numbers. Each column sorts on its
  own count, with ties broken by overall severity, and lists still open worst first. Findings Trivy cannot
  rate still count in totals and exports.
- **The Overview matches Freelens' own pages.** It opens with the same header bar (*Overview* at the left,
  the namespace selector at the right). *Fix first* and *Compliance* are stacked at the full width, so
  nothing is cut off, and *Compliance* is a table of Benchmark, Failing and Passing.
- **Freelens' own font, sizes and weights everywhere.** The extension no longer sets a typeface of its own,
  and table headers are the same size and colour as Freelens' tables. Number column headers (Components,
  Dependencies, Fixable, Scanned) leave room for the sort arrow.

### Fixed

- Critical and High counts are coloured. In every earlier version they were grey, because the colour class
  was never applied. All four severities now use the colours of the bars and tiles.

## [0.1.3] - 10 October 2026

### Fixed

- Rescan is no longer offered for SBOM reports. The operator does not regenerate an SBOM report that
  is deleted, so rescanning one only made it disappear. Vulnerabilities, Secrets, Config Audit and RBAC
  reports still rescan, and exporting an SBOM list is unchanged.

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
