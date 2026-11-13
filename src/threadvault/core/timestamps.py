"""Optional RFC 3161 timestamps for chain heads (THREAT_MODEL T2).

Timestamping a branch's head hash proves the whole chain up to that record existed at the TSA's
time: every earlier record is bound into the head through `prev_hash`.

What leaves the machine: only the 32-byte record hash (the imprint) and a random nonce, sent to a
TSA URL the user chose. Nothing is sent unless `request_timestamp` is called with a URL.

What is checked here: the response status, that the token's message imprint is our hash (SHA-256)
and that the nonce matches. NOT checked: the TSA's CMS signature and certificate chain, because that
needs the TSA's trust anchor; verify those with
``openssl ts -verify -data <...> -in <token> -CAfile <tsa-ca.pem>``. A stored token is therefore
evidence for a third party to check, not something `verify` trusts by itself.

Tokens are stored as DER at ``threads/<tid>/timestamps/<record hash hex>.tsr``.
"""

from __future__ import annotations

import secrets
import urllib.request
from collections.abc import Callable
from pathlib import Path

from pydantic import BaseModel

from threadvault.core.ids import check_hash
from threadvault.core.jsonio import atomic_write_bytes

Transport = Callable[[str, bytes], bytes]
MAX_RESPONSE = 1 << 20

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"


class TimestampError(ValueError):
    pass


class TimestampToken(BaseModel):
    record_hash: str
    gen_time: str  # as given by the TSA (GeneralizedTime, e.g. 20261114090000Z)
    serial: int
    policy: str
    token_der: bytes  # the full TimeStampResp


# -- minimal DER ------------------------------------------------------------------------------------
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def der_int(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, raw)


def der_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def seq(*items: bytes) -> bytes:
    return tlv(0x30, b"".join(items))


def parse(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """One TLV at `pos`: (tag, content, next position). DER only (no indefinite lengths)."""
    if pos + 2 > len(data):
        raise TimestampError("truncated DER")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise TimestampError("high tag numbers are not supported")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise TimestampError("bad DER length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    if pos + length > len(data):
        raise TimestampError("truncated DER")
    return tag, data[pos:pos + length], pos + length


def children(content: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    pos = 0
    while pos < len(content):
        tag, body, pos = parse(content, pos)
        out.append((tag, body))
    return out


def oid_str(body: bytes) -> str:
    if not body:
        raise TimestampError("empty OID")
    first = body[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for b in body[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


# -- request / response -----------------------------------------------------------------------------
def build_request(digest: bytes, nonce: int) -> bytes:
    """TimeStampReq (RFC 3161 section 2.4.1) for a SHA-256 digest, asking for the TSA cert."""
    if len(digest) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes")
    imprint = seq(seq(der_oid(OID_SHA256), b"\x05\x00"), tlv(0x04, digest))
    return seq(der_int(1), imprint, der_int(nonce), tlv(0x01, b"\xff"))


def parse_response(data: bytes, digest: bytes, nonce: int, record_hash: str) -> TimestampToken:
    """Check a TimeStampResp against our request. Raises TimestampError on anything unexpected."""
    try:
        return _parse_response(data, digest, nonce, record_hash)
    except (IndexError, UnicodeDecodeError) as e:
        raise TimestampError(f"malformed TSA response ({type(e).__name__})") from None


def _parse_response(data: bytes, digest: bytes, nonce: int, record_hash: str) -> TimestampToken:
    tag, body, end = parse(data)
    if tag != 0x30 or end != len(data):
        raise TimestampError("not a TimeStampResp")
    parts = children(body)
    status_info = children(parts[0][1]) if parts and parts[0][0] == 0x30 else []
    if not status_info or status_info[0][0] != 0x02:
        raise TimestampError("missing status")
    status = int.from_bytes(status_info[0][1], "big", signed=True)
    if status not in (0, 1) or len(parts) < 2:
        raise TimestampError(f"TSA refused the request (status {status})")
    content_info = children(parts[1][1])
    if oid_str(content_info[0][1]) != OID_SIGNED_DATA or content_info[1][0] != 0xA0:
        raise TimestampError("token is not CMS SignedData")
    signed_data = children(children(content_info[1][1])[0][1])
    encap = children(signed_data[2][1])
    if oid_str(encap[0][1]) != OID_TST_INFO or encap[1][0] != 0xA0:
        raise TimestampError("token does not contain TSTInfo")
    tst_der = children(encap[1][1])[0][1]  # [0] EXPLICIT OCTET STRING
    tst = children(children(tst_der)[0][1])
    policy = oid_str(tst[1][1])
    imprint = children(tst[2][1])
    alg = children(imprint[0][1])
    if oid_str(alg[0][1]) != OID_SHA256 or imprint[1][1] != digest:
        raise TimestampError("token imprint does not match the record hash")
    serial = int.from_bytes(tst[3][1], "big", signed=True)
    if tst[4][0] != 0x18:
        raise TimestampError("missing genTime")
    gen_time = tst[4][1].decode("ascii")
    token_nonce = next((int.from_bytes(b, "big", signed=True) for t, b in tst[5:] if t == 0x02),
                       None)
    if token_nonce != nonce:
        raise TimestampError("token nonce does not match the request")
    return TimestampToken(record_hash=record_hash, gen_time=gen_time, serial=serial,
                          policy=policy, token_der=data)


def _http_transport(url: str, body: bytes) -> bytes:
    if not url.startswith(("https://", "http://")):
        raise TimestampError("TSA URL must be http(s)")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/timestamp-query"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data: bytes = resp.read(MAX_RESPONSE + 1)
    if len(data) > MAX_RESPONSE:
        raise TimestampError("TSA response too large")
    return data


def request_timestamp(record_hash: str, url: str,
                      transport: Transport | None = None) -> TimestampToken:
    """Ask the TSA at `url` to timestamp `record_hash` (a record's `sha256:` hash)."""
    digest = bytes.fromhex(check_hash(record_hash).removeprefix("sha256:"))
    nonce = secrets.randbits(63)
    data = (transport or _http_transport)(url, build_request(digest, nonce))
    return parse_response(data, digest, nonce, record_hash)


# -- storage ----------------------------------------------------------------------------------------
def token_path(thread_dir: Path, record_hash: str) -> Path:
    return thread_dir / "timestamps" / (check_hash(record_hash).removeprefix("sha256:") + ".tsr")


def store_token(thread_dir: Path, token: TimestampToken) -> Path:
    path = token_path(thread_dir, token.record_hash)
    atomic_write_bytes(path, token.token_der)
    return path


def check_stored(thread_dir: Path, record_hash: str) -> str | None:
    """genTime of the stored token for `record_hash` if its imprint matches, else None.
    (Nonce is not re-checked: it only protects the live exchange.)"""
    path = token_path(thread_dir, record_hash)
    if not path.is_file():
        return None
    digest = bytes.fromhex(record_hash.removeprefix("sha256:"))
    data = path.read_bytes()
    try:
        _, body, _ = parse(data)
        parts = children(body)
        content_info = children(parts[1][1])
        signed_data = children(children(content_info[1][1])[0][1])
        encap = children(signed_data[2][1])
        tst = children(children(children(encap[1][1])[0][1])[0][1])
        imprint = children(tst[2][1])
        if imprint[1][1] != digest:
            return None
        return tst[4][1].decode("ascii")
    except (TimestampError, IndexError, UnicodeDecodeError):
        return None
