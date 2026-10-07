---
title: SBOM & Attestation
nav_order: 8
parent: Features
---

# SBOM & Attestation

IDEViewer exports a per-host software bill of materials in [CycloneDX](https://cyclonedx.org/) 1.5 format, optionally wrapped in a signed attestation.

## What the SBOM contains

Both halves of the workstation inventory, in one document:

| Component type | Source |
|----------------|--------|
| `library` | Packages from every detected manager, with a [purl](https://github.com/package-url/purl-spec) identifier |
| `application` | IDE extensions and plugins, carrying their computed risk level |

The host itself is the document's metadata component, typed `device`.

An extension installed in several IDEs appears once. Package components carry their package manager and source type (project, global, or bundled inside an extension) as properties.

## Vulnerabilities and VEX

Known vulnerabilities from [OSV.dev](https://osv.dev) correlation are included in the `vulnerabilities` block, each with its source, severity rating, description and the component it affects.

Every entry carries a lightweight VEX-style `analysis.state`:

- `resolved` — the finding has been resolved on this host
- `in_triage` — still open

A full VEX waiver workflow (who waived a finding, and the justification) is a documented follow-up, not something the current export provides.

## Downloading

From a host's detail page in the portal:

- **SBOM** — the plain CycloneDX document
- **Signed SBOM** — the same document wrapped in a signed attestation

Both download as `sbom-<hostname>.cdx.json`.

## What signing adds

A plain SBOM is a JSON file anyone can edit. Delete the row for a malicious extension and nothing reveals it. The signed form exists for when the document leaves your trust boundary — an auditor, a customer, a compliance artifact.

The signed export wraps the identical document under an `sbom` key and adds a `sig` block:

```json
{
  "sbom": { "bomFormat": "CycloneDX", "specVersion": "1.5", "...": "..." },
  "sig": {
    "alg": "ed25519",
    "key_id": "116445883a2806ac",
    "issued_at": 1791327600,
    "nonce": "aa9dfd07d489456e800edf5f4d73a45f",
    "body_b64": "eyJzYm9tIjp7...",
    "signature_b64": "4jkYwyDL38Ehi..."
  }
}
```

The body is canonicalised (compact, sorted keys) and base64-encoded; that exact string is what gets signed. `issued_at` and `nonce` bound replay, so a stale attestation cannot be passed off as current.

## Verifying an attestation

Fetch the portal's public key and verify the envelope against it:

```bash
curl -H "X-Customer-Key: <uuid>" \
     -H "X-Host-Token: <token>" \
     https://portal.example.com/api/signing-key
```

```json
{ "key_id": "116445883a2806ac", "algorithm": "ed25519", "public_key_b64": "..." }
```

The signed message is `"{issued_at}.{nonce}.{body_b64}"`. Verify the ed25519 signature over those exact bytes using the published key, then base64-decode `body_b64` to recover the document. Confirm `sig.key_id` matches the key you fetched.

## When signing is unavailable

If the portal has no command-signing key configured, the plain SBOM export still works and the signed export explains why it cannot sign rather than failing opaquely. Set `COMMAND_SIGNING_PRIVATE_KEY` or `COMMAND_SIGNING_PRIVATE_KEY_FILE` to enable it — see [Configuration](../configuration.html).

The same key signs enforcement commands, so a portal that can quarantine can also sign attestations.
