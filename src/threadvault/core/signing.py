"""Ed25519 signatures over records and exports (SPEC.md section 3.6), keys in the OS keychain.

The signature covers exactly the bytes the hash covers (canonical JSON without `hash` and
`signature`), so signing never changes a hash. `signature` = {"alg": "ed25519", "key_id", "sig"}
with `sig` the base64 of the 64-byte signature.

Which public keys count as *trusted* is the verifier's decision, never the vault file's: an
attacker with write access can add their own key to `manifest.signing_keys`. `verify` therefore
takes the trusted keys from the local key store when one is available.

Key storage: `KeyringKeyStore` keeps private keys in the OS keychain (Windows Credential Manager,
macOS Keychain, Secret Service) through the `keyring` package. `MemoryKeyStore` is for tests.
Per-vault keys (one signing key per key store namespace); per-thread keys are an open question
(SPEC section 14).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from threadvault.core.crypto_age import generate_identity, identity_from_str, identity_to_str
from threadvault.core.hashing import canonical_json

_EXCLUDED = ("hash", "signature")
KEYRING_SERVICE = "threadvault"


def signing_bytes(record: dict[str, Any]) -> bytes:
    return canonical_json({k: v for k, v in record.items() if k not in _EXCLUDED})


def public_key_b64(key: Ed25519PublicKey) -> str:
    return base64.b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def key_id_for(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:32]


def load_public_key(b64: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("invalid public key encoding") from None
    if len(raw) != 32:
        raise ValueError("invalid public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


class Signer:
    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key
        self.public_key = key.public_key()
        self.key_id = key_id_for(self.public_key)

    def signature(self, record: dict[str, Any]) -> dict[str, str]:
        sig = self._key.sign(signing_bytes(record))
        return {"alg": "ed25519", "key_id": self.key_id, "sig": base64.b64encode(sig).decode("ascii")}

    def manifest_entry(self) -> dict[str, str]:
        return {"key_id": self.key_id, "public_key": public_key_b64(self.public_key)}


def check_signature(record: dict[str, Any], trusted: dict[str, Ed25519PublicKey]) -> bool:
    """True if `record` carries a valid Ed25519 signature by one of the `trusted` keys."""
    sig = record.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") != "ed25519":
        return False
    key = trusted.get(str(sig.get("key_id")))
    if key is None:
        return False
    try:
        raw = base64.b64decode(str(sig.get("sig")), validate=True)
        key.verify(raw, signing_bytes(record))
    except (binascii.Error, ValueError, InvalidSignature):
        return False
    return True


def keys_from_manifest(manifest: dict[str, Any]) -> dict[str, Ed25519PublicKey]:
    """Keys a manifest *claims*. Only trust these when no local key store is available, and say so."""
    out: dict[str, Ed25519PublicKey] = {}
    for entry in manifest.get("signing_keys", []) or []:
        try:
            key = load_public_key(str(entry["public_key"]))
        except (KeyError, ValueError):
            continue
        if key_id_for(key) == entry.get("key_id"):  # a key_id that doesn't match its key is ignored
            out[entry["key_id"]] = key
    return out


# -- key stores ------------------------------------------------------------------------------------
class KeyStore(Protocol):
    def signer(self) -> Signer:
        """The signing key, created on first use."""
        ...

    def trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        """Public keys this machine trusts for verification."""
        ...

    def trust(self, key_id: str, public_key_b64: str) -> None:
        """Add another public key (e.g. a colleague's export key) to the trusted set."""
        ...

    def age_identity(self) -> X25519PrivateKey:
        """The encryption-at-rest identity, created on first use."""
        ...


class MemoryKeyStore:
    """In-process key store for tests. Never use for real vaults: keys vanish on exit."""

    def __init__(self) -> None:
        self._signer: Signer | None = None
        self._trusted: dict[str, Ed25519PublicKey] = {}
        self._age: X25519PrivateKey | None = None

    def signer(self) -> Signer:
        if self._signer is None:
            self._signer = Signer(Ed25519PrivateKey.generate())
            self._trusted[self._signer.key_id] = self._signer.public_key
        return self._signer

    def trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        self.signer()
        return dict(self._trusted)

    def trust(self, key_id: str, public_key_b64: str) -> None:
        key = load_public_key(public_key_b64)
        if key_id_for(key) != key_id:
            raise ValueError("key_id does not match the public key")
        self._trusted[key_id] = key

    def age_identity(self) -> X25519PrivateKey:
        if self._age is None:
            self._age = generate_identity()
        return self._age


class KeyringKeyStore:
    """Keys in the OS keychain via `keyring` (install the `keychain` extra).

    Entries (service "threadvault"): `<ns>:signing` (base64 raw Ed25519 private key),
    `<ns>:trusted` (JSON object key_id -> base64 public key), `<ns>:age` (age identity string).
    """

    def __init__(self, namespace: str = "default") -> None:
        import keyring  # imported lazily: optional dependency

        self._kr = keyring
        self._ns = namespace

    def _get(self, name: str) -> str | None:
        value = self._kr.get_password(KEYRING_SERVICE, f"{self._ns}:{name}")
        return value if isinstance(value, str) else None

    def _set(self, name: str, value: str) -> None:
        self._kr.set_password(KEYRING_SERVICE, f"{self._ns}:{name}", value)

    def signer(self) -> Signer:
        stored = self._get("signing")
        if stored is None:
            key = Ed25519PrivateKey.generate()
            raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            self._set("signing", base64.b64encode(raw).decode("ascii"))
        else:
            key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(stored, validate=True))
        return Signer(key)

    def _trusted_map(self) -> dict[str, str]:
        from threadvault.core.jsonio import loads

        stored = self._get("trusted")
        data = loads(stored) if stored else {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}

    def trusted_keys(self) -> dict[str, Ed25519PublicKey]:
        own = self.signer()
        out = {own.key_id: own.public_key}
        for key_id, b64 in self._trusted_map().items():
            try:
                key = load_public_key(b64)
            except ValueError:
                continue
            if key_id_for(key) == key_id:
                out[key_id] = key
        return out

    def trust(self, key_id: str, public_key_b64: str) -> None:
        from threadvault.core.hashing import canonical_json as cj

        key = load_public_key(public_key_b64)
        if key_id_for(key) != key_id:
            raise ValueError("key_id does not match the public key")
        data = self._trusted_map()
        data[key_id] = public_key_b64
        self._set("trusted", cj(data).decode("utf-8"))

    def age_identity(self) -> X25519PrivateKey:
        stored = self._get("age")
        if stored is None:
            ident = generate_identity()
            self._set("age", identity_to_str(ident))
            return ident
        return identity_from_str(stored)
