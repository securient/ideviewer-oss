---
title: Threat Intel & Drift
nav_order: 9
parent: Features
---

# Threat Intel & Drift Detection

Permission-based risk scoring answers "does this look risky?". These two subsystems answer different questions: "have we seen this exact thing is bad?" and "is something spreading across the fleet?".

## Threat intelligence

Where risk rules classify an extension by its declared permissions — a heuristic — threat intel matches against known-bad indicators. These are deterministic signals rather than inference.

Three indicator types are matched during scan-report ingestion:

| Indicator | Matches |
|-----------|---------|
| `malicious_publishers` | Extensions from a publisher known to have shipped malware |
| `banned_extension_ids` | Specific extension IDs on a denylist |
| `typosquat_targets` | Names impersonating a popular extension |

A match produces `{indicator_type, indicator, detail, severity}` and emits an `extension.threat_matched` event, which reaches webhooks, SOAR playbooks and the portal UI.

The feed is a versioned JSON document (`rules/threat_intel.json`) resolved from, in order: an environment override, the repository path, a portal-local copy, then embedded defaults. That means you can curate your own feed without forking.

Evaluation runs server-side during ingestion. Pushing the signed feed down to daemons over the command channel is a documented follow-up.

Threat-intel matches also feed composite risk scoring, so a host carrying a known-bad extension scores worse than permissions alone would suggest.

## Fleet drift detection

Per-host events cannot see fleet-level patterns. A sweep runs periodically and compares, per tenant, how many hosts carry each extension against the previous sweep.

Two deterministic signals are surfaced:

**`anomaly.new_risky_extension`** — a high or critical-risk extension appears anywhere in the fleet for the first time. A baseline sweep runs first, so enrolling a fleet does not flood you with alerts for everything already installed.

**`anomaly.rapid_propagation`** — an already-known extension's host count jumps sharply between sweeps. This is the worm-like spread signal: one developer installing something is noise, forty installing it within an hour is not.

Extension prevalence — how many hosts in your fleet carry a given extension — is tracked as a side effect and is useful on its own. An extension on one machine out of 300 is a different proposition from one on all 300.

## Host integrity

A separate sweep watches for hosts that have gone quiet. A daemon that stops heartbeating is itself a security signal: it may mean the daemon was stopped, uninstalled, or the machine was taken off the network.

The daemon also maintains SHA-256 checksums of its own binary, config and service files, and raises a tamper alert when one changes unexpectedly. Alerts appear in the portal and are emitted as events.

Stopping the daemon deliberately — via `ideviewer stop` or a signal — raises a `daemon_stopping` alert rather than passing unnoticed.
