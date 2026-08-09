# Changelog

## 0.4.0 - Unreleased

- Added offline Autonomous Campaign Mode with exact-host state, cumulative stage/request budgets, and an append-only audit trail.
- Added deterministic hypothesis ranking across risk, confidence, novelty, evidence quality, and request cost.
- Added bounded baseline proposal generation and explicit routing of authentication-dependent leads to manual Burp review.
- Added local Campaign CLI/API workflows and a responsive bilingual campaign dashboard.
- Campaign planning never grants target authorization, invokes Kali, sends HTTP, or confirms a vulnerability.

## 0.3.0 - 2026-08-09

- Added bounded HAR and Burp XML import with exact-host scope filtering and redaction before persistence.
- Added offline endpoint/role comparison, sensitive-field and verbose-error candidates, and same-code duplicate clustering.
- Added a human-governed finding lifecycle backed by SQLite; candidates are non-reportable by default.
- Added Chinese and English report rendering that is available only after human confirmation.
- Added CLI/API entry points and a responsive finding ledger in the local dashboard.

## 0.2.0 - 2026-08-09

- Added deterministic offline discovery of ranked vulnerability candidates and observations.
- Added manifest SHA-256 handoff verification on the Kali runner.
- Added one-time consumption of network-enabled job IDs to prevent replay.
- Added write-once evidence, evidence indexes, file hashes, and URL query-value redaction.
- Added reliable SSH step results, failure log recovery, and append-only audit events.
- Added local Web Host/Origin checks, security headers, and request-size limits.
- Added automatic post-dispatch evidence triage plus CLI and API analysis entry points.

## 0.1.0 - 2026-08-09

- Initial authorization-first dual-end architecture.
- Strict stage contracts and shared policy engine.
- Windows CLI/Web control plane and constrained Kali runner.
- SSH/SCP transport, dry-run demo, tests, and GitHub CI.
- Guarded Windows one-click launcher with isolated first-run setup.
- Responsive bilingual dashboard for local status, manifest validation, and audit history.
- Redesigned English and Chinese GitHub documentation and project artwork.
