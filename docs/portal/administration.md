---
title: Administration
nav_order: 5
parent: Portal
---

# Administration

## Accounts and first login

On first boot the portal creates a single admin account.

- If `IDEVIEWER_ADMIN_PASSWORD` is set, that password is used
- If it is not set, a strong random password is generated and written to the startup log once — retrieve it from there

Either way the account is flagged to require a password change, and the first login redirects to the change-password form before anything else is reachable.

## Sign-in options

**Local username and password** is always available unless disabled.

**Google OAuth** can be configured with `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. The redirect URI is `/login/google/callback`.

`DISABLE_LOCAL_LOGIN` controls the interaction between them:

| Value | Behaviour |
|-------|-----------|
| `false` (default) | Local login always available |
| `auto` | Local login disabled once Google OAuth is configured |
| `true` | Local login always disabled — requires Google OAuth |

Setting `auto` with Google credentials present means the documented `admin` / password login stops working; sign in through Google instead.

SAML and generic OIDC are not currently supported.

## Roles

Three roles exist on the user model:

| Role | Intent |
|------|--------|
| `admin` | Full access, including destructive and configuration actions |
| `analyst` | Operate the platform: triage findings, manage policies |
| `viewer` | Read-only |

**Current limitations.** Role enforcement is incomplete, and it is better to know this than to rely on it:

- Role checks are applied to some administrative actions, but a number of mutating routes are currently guarded only by "is this user logged in" — including host deletion, host token revocation, customer key creation, webhook management and policy toggling.
- There is no user-management screen, so additional accounts and roles cannot currently be provisioned through the portal.

In practice this means **every account that can sign in should be treated as having administrator capability**. Until role enforcement is completed, restrict portal access accordingly and prefer a single operator account per deployment.

## Customer keys

Customer keys are the tenant boundary. Every host, scan report, finding and policy is scoped to the key that created it, and the schema enforces that a record's tenant agrees with its host's tenant.

Keys are managed under **Keys**, where they can be created, deactivated and deleted. Deactivating a key stops its daemons from authenticating without destroying the data; deleting a key removes the key and its hosts.

A daemon presents its customer key once at registration and receives a per-host token. After that, the host token is what authenticates it — so a leaked customer key cannot be used to impersonate an already-enrolled host.

## Host tokens

Each enrolled host holds its own token, stored in the daemon's config file with `0600` permissions. The portal stores only a hash.

Revoking a host's token from its detail page immediately invalidates it. The host re-enrols on its next check-in and receives a fresh token, which is the recovery path for a workstation believed to be compromised.

## Audit log

Administrative and security-relevant actions are recorded and viewable under **Audit**, including policy creation and changes, key management, host deletion, SBOM export, quarantine and restore, and SOAR playbook outcomes.

Each entry records the actor, the action, the target and the time. The log is append-only through the UI; there is no delete control.

## Transport security

Set `FORCE_HTTPS=true` in any deployment reachable over a network. It enables:

- `Strict-Transport-Security` response headers
- The `Secure` flag on session cookies
- `https` as the preferred URL scheme

It defaults to `false` so local development works over plain HTTP. **A production deployment that does not set it will serve session cookies without the `Secure` flag.** Set it explicitly.

Session cookies are `HttpOnly` and `SameSite=Lax` regardless, and CSRF protection is enabled on all form submissions.

Multi-factor authentication is not currently supported.
