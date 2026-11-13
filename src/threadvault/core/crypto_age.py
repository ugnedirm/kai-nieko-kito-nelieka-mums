"""Encryption at rest in the age v1 format (https://age-encryption.org/v1), X25519 recipients.

`manifest.encryption.scheme` is "age" (schemas/manifest.schema.json), so we write real age files
rather than inventing a format: a blob can be decrypted with the `age` CLI and the identity string.

Only what threadvault needs is implemented: X25519 recipient stanzas, the header MAC and the
STREAM payload (ChaCha20-Poly1305, 64 KiB chunks). Passphrase (scrypt) stanzas and armor are not
supported. Decryption ignores stanza types it does not know, as the age spec requires.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

VERSION_LINE = b"age-encryption.org/v1"
_X25519_INFO = b"age-encryption.org/v1/X25519"
CHUNK = 64 * 1024
_TAG = 16
_MAX_HEADER = 64 * 1024


class DecryptionError(ValueError):
    """Wrong key, corrupted or tampered ciphertext. Never says which, never echoes data."""


class Cipher(Protocol):
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...


# -- bech32 (BIP 173), used for age key strings ----------------------------------------------------
_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = bits = 0
    out: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        raise ValueError("invalid bech32 padding")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    five = _convertbits(data, 8, 5, True)
    poly = _polymod(_hrp_expand(hrp) + five + [0] * 6) ^ 1
    checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[d] for d in five + checksum)


def bech32_decode(text: str) -> tuple[str, bytes]:
    if text.lower() != text and text.upper() != text:
        raise ValueError("mixed-case bech32")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text):
        raise ValueError("invalid bech32")
    hrp, rest = text[:pos], text[pos + 1:]
    try:
        data = [_CHARSET.index(c) for c in rest]
    except ValueError:
        raise ValueError("invalid bech32 character") from None
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad bech32 checksum")
    return hrp, bytes(_convertbits(data[:-6], 5, 8, False))


# -- keys ------------------------------------------------------------------------------------------
def generate_identity() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def identity_to_str(key: X25519PrivateKey) -> str:
    raw = key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return bech32_encode("age-secret-key-", raw).upper()


def identity_from_str(text: str) -> X25519PrivateKey:
    hrp, raw = bech32_decode(text.strip())
    if hrp != "age-secret-key-" or len(raw) != 32:
        raise ValueError("not an age X25519 identity")
    return X25519PrivateKey.from_private_bytes(raw)


def recipient_to_str(key: X25519PublicKey) -> str:
    return bech32_encode("age", key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def recipient_from_str(text: str) -> X25519PublicKey:
    hrp, raw = bech32_decode(text.strip())
    if hrp != "age" or len(raw) != 32:
        raise ValueError("not an age X25519 recipient")
    return X25519PublicKey.from_public_bytes(raw)


# -- helpers ---------------------------------------------------------------------------------------
def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _b64(data: bytes) -> bytes:
    return base64.b64encode(data).rstrip(b"=")


def _unb64(data: bytes) -> bytes:
    if b"=" in data or b"\r" in data:
        raise DecryptionError("malformed age header")
    try:
        return base64.b64decode(data + b"=" * (-len(data) % 4), validate=True)
    except ValueError:
        raise DecryptionError("malformed age header") from None


def _wrap_body(body: bytes) -> bytes:
    """age stanza body: base64 in 64-column lines; the last line is always shorter than 64."""
    enc = _b64(body)
    lines = [enc[i:i + 64] for i in range(0, len(enc), 64)]
    if not lines or len(lines[-1]) == 64:
        lines.append(b"")
    return b"\n".join(lines) + b"\n"


def _stream_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


# -- encrypt / decrypt -----------------------------------------------------------------------------
def encrypt(plaintext: bytes, recipients: list[X25519PublicKey]) -> bytes:
    if not recipients:
        raise ValueError("at least one recipient is required")
    file_key = os.urandom(16)
    header = VERSION_LINE + b"\n"
    for rcpt in recipients:
        eph = X25519PrivateKey.generate()
        share = eph.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        rcpt_raw = rcpt.public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = eph.exchange(rcpt)
        wrap_key = _hkdf(shared, share + rcpt_raw, _X25519_INFO)
        body = ChaCha20Poly1305(wrap_key).encrypt(b"\x00" * 12, file_key, None)
        header += b"-> X25519 " + _b64(share) + b"\n" + _wrap_body(body)
    header += b"---"
    mac = hmac.new(_hkdf(file_key, b"", b"header"), header, hashlib.sha256).digest()
    out = bytearray(header + b" " + _b64(mac) + b"\n")

    nonce = os.urandom(16)
    out += nonce
    aead = ChaCha20Poly1305(_hkdf(file_key, nonce, b"payload"))
    chunks = [plaintext[i:i + CHUNK] for i in range(0, len(plaintext), CHUNK)] or [b""]
    for i, chunk in enumerate(chunks):
        out += aead.encrypt(_stream_nonce(i, i == len(chunks) - 1), chunk, None)
    return bytes(out)


def decrypt(ciphertext: bytes, identity: X25519PrivateKey) -> bytes:
    end = ciphertext.find(b"\n---", 0, _MAX_HEADER)
    if not ciphertext.startswith(VERSION_LINE + b"\n") or end < 0:
        raise DecryptionError("not an age v1 file")
    mac_line_end = ciphertext.find(b"\n", end + 1)
    if mac_line_end < 0:
        raise DecryptionError("not an age v1 file")
    header = ciphertext[: end + 4]  # through "---"
    mac_line = ciphertext[end + 4: mac_line_end]
    if not mac_line.startswith(b" "):
        raise DecryptionError("malformed age header")
    mac = _unb64(mac_line[1:])

    lines = header.split(b"\n")[1:-1]  # drop version line and the "---" line
    file_key: bytes | None = None
    my_pub = identity.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    i = 0
    while i < len(lines):
        if not lines[i].startswith(b"-> "):
            raise DecryptionError("malformed age header")
        args = lines[i][3:].split(b" ")
        i += 1
        body_parts: list[bytes] = []
        while True:
            if i >= len(lines):
                raise DecryptionError("malformed age header")
            part = lines[i]
            i += 1
            if len(part) > 64:
                raise DecryptionError("malformed age header")
            body_parts.append(part)
            if len(part) < 64:
                break
        if args[0] == b"X25519" and len(args) != 2:
            raise DecryptionError("malformed age header")
        if args[0] != b"X25519" or file_key is not None:
            continue
        share = _unb64(args[1])
        body = _unb64(b"".join(body_parts))
        if len(share) != 32 or len(body) != 32:
            raise DecryptionError("malformed age header")
        try:
            shared = identity.exchange(X25519PublicKey.from_public_bytes(share))
        except ValueError:
            raise DecryptionError("malformed age header") from None
        wrap_key = _hkdf(shared, share + my_pub, _X25519_INFO)
        try:
            file_key = ChaCha20Poly1305(wrap_key).decrypt(b"\x00" * 12, body, None)
        except InvalidTag:
            continue  # stanza for another recipient
    if file_key is None:
        raise DecryptionError("no matching identity")
    expected = hmac.new(_hkdf(file_key, b"", b"header"), header, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise DecryptionError("header MAC mismatch")

    payload = ciphertext[mac_line_end + 1:]
    if len(payload) < 16 + _TAG:
        raise DecryptionError("truncated payload")
    aead = ChaCha20Poly1305(_hkdf(file_key, payload[:16], b"payload"))
    body = payload[16:]
    step = CHUNK + _TAG
    out = bytearray()
    n_chunks = max(1, -(-len(body) // step))
    for idx in range(n_chunks):
        chunk = body[idx * step:(idx + 1) * step]
        last = idx == n_chunks - 1
        if len(chunk) < _TAG or (last and len(chunk) == _TAG and idx > 0):
            raise DecryptionError("truncated payload")
        try:
            out += aead.decrypt(_stream_nonce(idx, last), chunk, None)
        except InvalidTag:
            raise DecryptionError("payload authentication failed") from None
    return bytes(out)


class AgeCipher:
    """Encrypts to the identity's own recipient (plus any extra recipients); decrypts with it."""

    def __init__(self, identity: X25519PrivateKey,
                 extra_recipients: list[X25519PublicKey] | None = None) -> None:
        self._identity = identity
        self._recipients = [identity.public_key(), *(extra_recipients or [])]

    @property
    def recipient(self) -> str:
        return recipient_to_str(self._identity.public_key())

    def encrypt(self, plaintext: bytes) -> bytes:
        return encrypt(plaintext, self._recipients)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return decrypt(ciphertext, self._identity)
