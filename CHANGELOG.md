# Changelog

One entry per release, newest first. The detail of each change is in its commit
messages; open work is in [docs/BACKLOG.md](docs/BACKLOG.md).

## Unreleased

- `docs/BACKLOG.md` is the single work list (ids, states, dated notes); it
  replaces `docs/IMPROVEMENTS-BACKLOG.md`.
- Two identifiers from real cases left in a test and in a documentation example
  replaced with placeholders.

## v0.7.187 — 2026-11-05

- Every table is an alert (`alert_`, every row a finding) or an artifact
  (`art_`); the manifest key `kind: alert|artifact` replaces
  `alert: detect|flag|context`, and a test holds kind and prefix together.
- Twelve tables renamed to `alert_` (the hayabusa timeline and the Volatility
  checks that list only hits); `alert_collection` is now `art_collection`. Old
  tables are retired from parsed cases on the next run.
- The atlas lists Alerts and Artifacts in two tables; every parser and profile
  description rewritten in plain English, alerts with their fields and artifacts
  with what they flag.
