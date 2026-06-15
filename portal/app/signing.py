"""Command-envelope signing (Phase 1 B1).

The daemon polls the portal for *commands* it will act on — most importantly
the enforcement actions returned by ``/api/enforcement-actions/pending``. Those
commands move files on a developer's machine, so they must be authenticated and
tamper-evident independent of the transport. We sign them with **ed25519**, the
same primitive the updater already pins (see ``pkg/updater/updater.go``): the
portal holds the private key, every daemon pins the public key, and a daemon
executes a command only if the signature verifies.

Wire format (a "signed command envelope")::

    {
      "actions": [...],            # redundant top-level copy for old daemons
      "sig": {
        "key_id": "ab12cd34ef567890",
        "alg": "ed25519",
        "issued_at": 1718200000,   # unix seconds (replay window)
        "nonce": "<uuid4 hex>",    # single-use within the window
        "body_b64": "<base64 of the canonical JSON body>",
        "signature_b64": "<base64 ed25519 signature>"
      }
    }

The signature is computed over the ASCII string ``f"{issued_at}.{nonce}.{body_b64}"``.
The daemon verifies over the *exact* ``body_b64`` it received and only then
base64-decodes + parses it — so there is no Python<->Go JSON canonicalization to
get wrong. ``issued_at``/``nonce`` are inside the signed message, so neither can
be altered to extend the replay window or replay a command.

Key management is pluggable behind ``Signer`` so a KMS-backed signer can slot in
later without changing the wire format or the daemon. The default
``LocalEd25519Signer`` keeps the private key in an env var or a 0600 file, and in
dev/local it auto-generates a stable key under ``instance/`` so the stack works
out of the box.
"""
import base64
import hashlib
import json
import logging
import os
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("ideviewer.signing")

# Daemons reject a command whose ``issued_at`` is older than this. Matches the
# webhook receiver's replay window so operators reason about one number.
REPLAY_WINDOW_SECONDS = 300

ALGORITHM = "ed25519"


def _key_id(public_bytes: bytes) -> str:
    """Short, stable fingerprint = first 8 bytes of sha256(public key)."""
    return hashlib.sha256(public_bytes).hexdigest()[:16]


class Signer:
    """Abstract command signer. Implementations sign raw bytes with ed25519."""

    key_id: str
    algorithm: str = ALGORITHM

    def sign(self, message: bytes) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError

    def public_key_b64(self) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class LocalEd25519Signer(Signer):
    """ed25519 signer holding the private key in-process."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        pub = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self._public_bytes = pub
        self.key_id = _key_id(pub)
        self.algorithm = ALGORITHM

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)

    def public_key_b64(self) -> str:
        return base64.standard_b64encode(self._public_bytes).decode("ascii")

    @classmethod
    def from_seed_b64(cls, seed_b64: str) -> "LocalEd25519Signer":
        seed = base64.standard_b64decode(seed_b64.strip())
        if len(seed) != 32:
            raise ValueError("ed25519 private seed must be 32 bytes (base64)")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def seed_b64(self) -> str:
        seed = self._private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.standard_b64encode(seed).decode("ascii")


class KmsSigner(Signer):  # pragma: no cover - future backend, not wired
    """Placeholder for an AWS KMS-backed signer.

    The wire format and daemon verification are identical (ed25519 over the same
    message), so a production deployment can move the private key into KMS by
    implementing ``sign``/``public_key_b64`` here and setting
    ``COMMAND_SIGNING_BACKEND=kms`` — no daemon change required.
    """

    def __init__(self, *_args, **_kwargs):
        raise NotImplementedError(
            "KMS command signing is not implemented yet; use the default "
            "'local' backend (COMMAND_SIGNING_BACKEND=local)."
        )


def _default_key_file(app) -> str:
    instance = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance"
    )
    return os.path.join(instance, "command_signing.key")


def _build_local_signer(app) -> LocalEd25519Signer:
    """Resolve a local ed25519 signer from env/file, generating one if needed.

    Resolution order:
      1. ``COMMAND_SIGNING_PRIVATE_KEY``      — base64 32-byte seed (env)
      2. ``COMMAND_SIGNING_PRIVATE_KEY_FILE`` — file holding the base64 seed
      3. default ``instance/command_signing.key`` — generated + persisted (0600)

    In ``TESTING`` we always use an ephemeral in-memory key (no file writes), so
    tests are isolated. In production a key MUST be provided explicitly via (1)
    or (2); we refuse to silently invent one.
    """
    seed_env = os.environ.get("COMMAND_SIGNING_PRIVATE_KEY")
    if seed_env:
        return LocalEd25519Signer.from_seed_b64(seed_env)

    key_file = os.environ.get("COMMAND_SIGNING_PRIVATE_KEY_FILE")

    if app.config.get("TESTING") and not key_file:
        return LocalEd25519Signer(Ed25519PrivateKey.generate())

    is_production = (app.config.get("FLASK_CONFIG") == "production") or (
        not app.config.get("DEBUG") and not app.config.get("TESTING")
    )
    if not key_file:
        if is_production:
            raise ValueError(
                "Command signing requires a key in production. Set "
                "COMMAND_SIGNING_PRIVATE_KEY (base64 32-byte ed25519 seed) or "
                "COMMAND_SIGNING_PRIVATE_KEY_FILE."
            )
        key_file = _default_key_file(app)

    if os.path.exists(key_file):
        with open(key_file, "r", encoding="ascii") as fh:
            return LocalEd25519Signer.from_seed_b64(fh.read())

    # Generate and persist a fresh key (dev/local convenience).
    signer = LocalEd25519Signer(Ed25519PrivateKey.generate())
    os.makedirs(os.path.dirname(key_file), exist_ok=True)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(signer.seed_b64())
    logger.warning(
        "Generated a local command-signing key at %s (key_id=%s). For "
        "production, set COMMAND_SIGNING_PRIVATE_KEY explicitly.",
        key_file, signer.key_id,
    )
    return signer


def get_signer(app=None) -> Signer:
    """Return the process-wide command signer, building it once per app."""
    if app is None:
        from flask import current_app
        app = current_app

    existing = app.extensions.get("command_signer")
    if existing is not None:
        return existing

    backend = os.environ.get("COMMAND_SIGNING_BACKEND", "local").lower()
    if backend == "kms":
        signer = KmsSigner()
    else:
        signer = _build_local_signer(app)

    app.extensions["command_signer"] = signer
    return signer


def public_key_info(app=None) -> dict:
    """Public key material the daemon pins, served by ``GET /api/signing-key``."""
    signer = get_signer(app)
    return {
        "key_id": signer.key_id,
        "algorithm": signer.algorithm,
        "public_key_b64": signer.public_key_b64(),
    }


def sign_envelope(body: dict, app=None) -> dict:
    """Wrap ``body`` in a signed command envelope (see module docstring).

    ``body`` is canonicalized (compact, sorted keys) and base64-encoded; that
    exact base64 string is what gets signed and what the daemon verifies over.
    """
    signer = get_signer(app)
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_b64 = base64.standard_b64encode(canonical).decode("ascii")
    issued_at = int(time.time())
    nonce = uuid.uuid4().hex
    message = f"{issued_at}.{nonce}.{body_b64}".encode("ascii")
    signature = signer.sign(message)

    envelope = dict(body)  # keep top-level keys (e.g. "actions") for old daemons
    envelope["sig"] = {
        "key_id": signer.key_id,
        "alg": signer.algorithm,
        "issued_at": issued_at,
        "nonce": nonce,
        "body_b64": body_b64,
        "signature_b64": base64.standard_b64encode(signature).decode("ascii"),
    }
    return envelope


def verify_envelope_body(envelope: dict, public_key_b64: str) -> dict:
    """Verify an envelope and return the decoded body. For tests/parity checks.

    Mirrors the daemon's verification (``pkg/api/signing.go``) so the Python and
    Go sides can be cross-checked. Raises ``ValueError`` on any failure.
    """
    sig = envelope.get("sig") or {}
    body_b64 = sig.get("body_b64")
    issued_at = sig.get("issued_at")
    nonce = sig.get("nonce")
    signature_b64 = sig.get("signature_b64")
    if not all([body_b64, signature_b64, nonce]) or issued_at is None:
        raise ValueError("envelope missing signature fields")

    if abs(int(time.time()) - int(issued_at)) > REPLAY_WINDOW_SECONDS:
        raise ValueError("envelope outside replay window")

    pub = Ed25519PublicKey.from_public_bytes(
        base64.standard_b64decode(public_key_b64)
    )
    message = f"{issued_at}.{nonce}.{body_b64}".encode("ascii")
    pub.verify(base64.standard_b64decode(signature_b64), message)  # raises on bad sig
    return json.loads(base64.standard_b64decode(body_b64))
