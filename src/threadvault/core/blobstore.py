"""Content-addressed file store (SPEC.md section 5).

A blob's name is the SHA-256 of its *plaintext* bytes. With encryption at rest the file on disk
holds age ciphertext, but the name and every reference still use the plaintext hash, so
encrypting a vault changes no record hash. Reading always re-hashes, so a swapped or corrupted
blob is never returned as if it were genuine.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from threadvault.core.crypto_age import VERSION_LINE, Cipher, DecryptionError
from threadvault.core.hashing import HASH_PREFIX, sha256_bytes
from threadvault.core.ids import check_hash, is_hash
from threadvault.core.jsonio import atomic_write_bytes


class BlobIntegrityError(ValueError):
    """Blob bytes do not match their name (SPEC code blob_hash_mismatch)."""


class BlobStore:
    def __init__(self, root: Path, cipher: Cipher | None = None) -> None:
        self.root = root
        self._cipher = cipher

    def _path(self, sha256: str) -> Path:
        return self.root / check_hash(sha256).removeprefix(HASH_PREFIX)

    def put(self, data: bytes) -> str:
        """Store bytes once; returns their `sha256:` id. Storing the same bytes again is a no-op."""
        sha = sha256_bytes(data)
        path = self._path(sha)
        if not path.exists():
            atomic_write_bytes(path, self._cipher.encrypt(data) if self._cipher else data)
        return sha

    def has(self, sha256: str) -> bool:
        return is_hash(sha256) and self._path(sha256).is_file()

    def get(self, sha256: str) -> bytes:
        path = self._path(sha256)
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            raise FileNotFoundError("no such file in vault") from None
        try:
            # A plaintext blob written before encryption was enabled is still accepted: it is
            # checked against its hash like any other, so it cannot be a substitute.
            encrypted = self._cipher is not None and raw.startswith(VERSION_LINE + b"\n")
            data = self._cipher.decrypt(raw) if (self._cipher and encrypted) else raw
        except DecryptionError:
            raise BlobIntegrityError("blob could not be decrypted") from None
        if sha256_bytes(data) != sha256:
            raise BlobIntegrityError("blob bytes do not match their hash")
        return data

    def check(self, sha256: str) -> str | None:
        """None if fine, else the SPEC error code: missing_blob or blob_hash_mismatch."""
        try:
            self.get(sha256)
        except FileNotFoundError:
            return "missing_blob"
        except BlobIntegrityError:
            return "blob_hash_mismatch"
        return None

    def delete(self, sha256: str) -> bool:
        """Remove the blob. Overwrites plaintext blobs first (best effort; SSDs and copy-on-write
        filesystems may keep old blocks, see THREAT_MODEL section 4)."""
        path = self._path(sha256)
        if not path.is_file():
            return False
        if self._cipher is None:
            try:
                size = path.stat().st_size
                with open(path, "r+b") as fh:
                    fh.write(b"\x00" * size)
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
        path.unlink()
        return True

    def __iter__(self) -> Iterator[str]:
        if not self.root.is_dir():
            return
        for p in sorted(self.root.iterdir()):
            sha = HASH_PREFIX + p.name
            if p.is_file() and is_hash(sha):
                yield sha
