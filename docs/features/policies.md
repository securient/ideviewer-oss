---
title: Policies & Enforcement
nav_order: 7
parent: Features
---

# Policies & Enforcement

Scanning tells you what is installed. Policies tell you what is *allowed*, and enforcement does something about it.

## Policy actions

Each policy matches extensions and applies one action:

| Action | Effect |
|--------|--------|
| `allow` | Explicitly permitted. Suppresses warnings from other rules — an allowlist entry. |
| `warn` | Recorded as a violation and surfaced in the portal. No action on the workstation. |
| `block-alert` | Recorded as a violation and emitted as an event, so it reaches webhooks and alerting. No action on the workstation. |
| `quarantine` | Issues a signed command instructing the daemon to move the extension out of the IDE's load path. |

`allow` is evaluated first, so a broad `warn` rule can be narrowed by specific exceptions.

Policies are managed under **Policies** in the portal. Violations appear under **Violations**, where they can be resolved or escalated to quarantine.

## Enforcement is off by default

Quarantine is the only action that changes a developer's machine, so it is deliberately opt-in at two levels:

1. The **daemon** must be registered with enforcement enabled:

   ```bash
   ideviewer register --portal-url https://portal.example.com \
                      --customer-key <uuid> \
                      --enable-enforcement
   ```

   Without that flag the daemon ignores quarantine commands.

2. The **policy** must specify the `quarantine` action. A policy set to `warn` or `block-alert` never touches the workstation.

## How a quarantine command is trusted

Enforcement is a remote-code-adjacent capability, so the command channel is signed rather than merely authenticated.

- The portal signs each command envelope with an **ed25519** key
- The daemon pins the portal's public key at registration and stores it in its config
- Every envelope carries `issued_at` and a `nonce`; the daemon rejects anything outside the replay window, and a per-process nonce cache rejects replays inside it
- **The daemon verifies the signature before acting.** An unsigned or badly signed command is discarded

A portal with no signing key configured can still enrol hosts and collect scans — it simply cannot issue enforcement commands, and `GET /api/signing-key` returns `503`. See [Configuration](../configuration.html) for `COMMAND_SIGNING_PRIVATE_KEY`.

## Quarantine and restore

A quarantined extension is moved to a quarantine directory rather than deleted, so the action is reversible. Enforcement actions are tracked through `pending → succeeded` / `failed`, and the portal's **Enforcement** page lists them with a restore control.

Restore issues a second signed command (`restore`) returning the extension to its original location.

## SOAR playbooks

Playbooks close the detect-to-respond loop automatically: when a trigger event fires, a matching playbook can auto-quarantine or notify, without an operator in the path.

Three safety controls are built in, because automated enforcement across a fleet is unforgiving:

- **Dry run by default.** A new playbook simulates — logging, emitting events and writing audit entries — until an operator explicitly activates it.
- **Per-hour rate limit.** Bounds how many auto-quarantines a playbook can issue, so a bad trigger cannot brick a fleet.
- **Deduplication.** Never stacks a second quarantine on an extension already being quarantined.

Playbooks are managed under **Playbooks** in the portal, where the mode toggle switches between simulate and active.

## Coverage

The **Coverage** page tracks expected hosts: machines that *should* be reporting. A host on the expected list that stops checking in is visible as a gap, which catches the failure mode where an endpoint silently drops off the fleet rather than reporting something bad.
