#!/usr/bin/env python3
"""Independently reproduce both committed deterministic wallet test vectors."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "vectors" / "built-in-v1.json"

EXPECTED_TOP_LEVEL_KEYS = frozenset(
    {"warning", "passwordUtf8", "democracyOsV2", "zeraEd25519V1"}
)
EXPECTED_DEMOCRACY_OS_KEYS = frozenset(
    {
        "profile",
        "username",
        "normalizedUsername",
        "saltHex",
        "challenge",
        "challengeDigestHex",
        "publicKeyHex",
        "address",
        "signatureHex",
    }
)
EXPECTED_ZERA_KEYS = frozenset(
    {
        "profile",
        "username",
        "normalizedUsername",
        "applicationId",
        "networkId",
        "messageUtf8",
        "publicSaltHex",
        "publicKeyHex",
        "publicKeyIdentifier",
        "address",
        "signatureHex",
    }
)
EXPECTED_WARNING = "TEST-ONLY CREDENTIALS. NEVER USE THESE VALUES FOR A REAL WALLET."
DEMOCRACY_OS_PROFILE = "democracyos-scrypt-sha512-secp256k1-v2"
ZERA_PROFILE = "web2ish-zera-ed25519-v1"
CONTEXT_PATTERN = re.compile(r"[a-z0-9][a-z0-9._:-]{0,79}", re.ASCII)
HEX_PATTERN = re.compile(r"[0-9a-f]+", re.ASCII)
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
JAVASCRIPT_TRIM_CHARACTERS = (
    "\u0009\u000a\u000b\u000c\u000d\u0020\u00a0\u1680\u2000\u2001\u2002"
    "\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f"
    "\u205f\u3000\ufeff"
)


class VerificationError(Exception):
    """A deterministic fixture or parity verification failure."""


def fail(message: str) -> NoReturn:
    raise VerificationError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"fixture contains duplicate key {key!r}")
        result[key] = value
    return result


def require_exact_object(
    value: Any, expected_keys: frozenset[str], location: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{location} must be an object")
    actual_keys = frozenset(value)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        unexpected = sorted(actual_keys - expected_keys)
        fail(
            f"{location} has an invalid shape "
            f"(missing={missing!r}, unexpected={unexpected!r})"
        )
    return value


def require_string(value: Any, location: str) -> str:
    if not isinstance(value, str):
        fail(f"{location} must be a string")
    return value


def require_hex(value: Any, byte_length: int, location: str) -> str:
    text = require_string(value, location)
    if len(text) != byte_length * 2 or HEX_PATTERN.fullmatch(text) is None:
        fail(f"{location} must be exactly {byte_length} lowercase-hex bytes")
    return text


def load_fixture() -> tuple[str, dict[str, Any], dict[str, Any]]:
    try:
        contents = FIXTURE_PATH.read_text(encoding="utf-8")
        decoded = json.loads(contents, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read strict JSON fixture: {error}")

    fixture = require_exact_object(decoded, EXPECTED_TOP_LEVEL_KEYS, "fixture")
    if require_string(fixture["warning"], "fixture.warning") != EXPECTED_WARNING:
        fail("fixture.warning does not contain the required test-only warning")

    password = require_string(fixture["passwordUtf8"], "fixture.passwordUtf8")
    password_bytes = password.encode("utf-8")
    if not 24 <= len(password_bytes) <= 1_024:
        fail("fixture.passwordUtf8 must encode to 24-1,024 UTF-8 bytes")

    democracy_os = require_exact_object(
        fixture["democracyOsV2"],
        EXPECTED_DEMOCRACY_OS_KEYS,
        "fixture.democracyOsV2",
    )
    for key in EXPECTED_DEMOCRACY_OS_KEYS:
        require_string(democracy_os[key], f"fixture.democracyOsV2.{key}")
    require_hex(democracy_os["saltHex"], 32, "fixture.democracyOsV2.saltHex")
    require_hex(
        democracy_os["challengeDigestHex"],
        32,
        "fixture.democracyOsV2.challengeDigestHex",
    )
    require_hex(
        democracy_os["publicKeyHex"], 33, "fixture.democracyOsV2.publicKeyHex"
    )
    require_hex(
        democracy_os["signatureHex"], 64, "fixture.democracyOsV2.signatureHex"
    )
    if democracy_os["profile"] != DEMOCRACY_OS_PROFILE:
        fail(f"fixture.democracyOsV2.profile must be {DEMOCRACY_OS_PROFILE!r}")
    if not democracy_os["challenge"]:
        fail("fixture.democracyOsV2.challenge must not be empty")

    zera = require_exact_object(
        fixture["zeraEd25519V1"], EXPECTED_ZERA_KEYS, "fixture.zeraEd25519V1"
    )
    for key in EXPECTED_ZERA_KEYS:
        require_string(zera[key], f"fixture.zeraEd25519V1.{key}")
    require_hex(zera["publicSaltHex"], 32, "fixture.zeraEd25519V1.publicSaltHex")
    require_hex(zera["publicKeyHex"], 32, "fixture.zeraEd25519V1.publicKeyHex")
    require_hex(zera["signatureHex"], 64, "fixture.zeraEd25519V1.signatureHex")
    if zera["profile"] != ZERA_PROFILE:
        fail(f"fixture.zeraEd25519V1.profile must be {ZERA_PROFILE!r}")

    return password, democracy_os, zera


def normalize_democracy_os_username(username: str) -> str:
    normalized = username.strip(JAVASCRIPT_TRIM_CHARACTERS).lower()
    if (
        not normalized
        or len(normalized) > 320
        or any(
            ord(character) <= 0x1F or ord(character) == 0x7F
            for character in normalized
        )
    ):
        fail("normalized DemocracyOS username is invalid")
    return normalized


def normalize_zera_username(username: str) -> str:
    normalized = username.strip("\t\n\f\r ")
    normalized = "".join(
        chr(ord(character) + 32) if "A" <= character <= "Z" else character
        for character in normalized
    )
    if not 3 <= len(normalized) <= 120:
        fail("normalized username must contain 3-120 characters")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in normalized):
        fail("normalized username must contain printable ASCII only")
    return normalized


def canonicalize_context(value: str, location: str) -> str:
    canonical = value.strip().lower()
    if CONTEXT_PATTERN.fullmatch(canonical) is None:
        fail(f"{location} is not a valid v1 derivation context identifier")
    return canonical


def base58_encode(value: bytes) -> str:
    leading_zeroes = len(value) - len(value.lstrip(b"\x00"))
    integer = int.from_bytes(value, "big")
    encoded = bytearray()
    while integer:
        integer, remainder = divmod(integer, 58)
        encoded.append(BASE58_ALPHABET[remainder])
    encoded.reverse()
    return (BASE58_ALPHABET[:1] * leading_zeroes + encoded).decode("ascii")


def verify_democracy_os_vector(
    password: str, democracy_os: dict[str, Any]
) -> None:
    normalized_username = normalize_democracy_os_username(
        democracy_os["username"]
    )
    if normalized_username != democracy_os["normalizedUsername"]:
        fail(
            "independent DemocracyOS username normalization does not match "
            "normalizedUsername"
        )

    password_bytes = password.encode("utf-8")
    if not 12 <= len(password_bytes) <= 1_024:
        fail("DemocracyOS fixture password must encode to 12-1,024 UTF-8 bytes")
    password_hash = hashlib.sha512(
        b"DemocracyOS password wallet password hash v2\n" + password_bytes
    ).digest()
    wallet_entropy = hashlib.sha512(
        (
            "DemocracyOS password wallet entropy v2\n"
            f"{normalized_username}\n"
            f"{password_hash.hex()}"
        ).encode("utf-8")
    ).digest()
    external_salt = bytes.fromhex(democracy_os["saltHex"])
    seed = hashlib.scrypt(
        wallet_entropy,
        salt=external_salt,
        n=32_768,
        r=8,
        p=1,
        dklen=32,
        maxmem=128 * 1_024 * 1_024,
    )
    secret_scalar = int.from_bytes(seed, "big")
    if not 1 <= secret_scalar < SECP256K1_ORDER:
        fail("independent DemocracyOS scrypt output is not a secp256k1 scalar")

    private_key = ec.derive_private_key(secret_scalar, ec.SECP256K1())
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint,
    )
    if public_key_bytes.hex() != democracy_os["publicKeyHex"]:
        fail(
            "independent DemocracyOS KDF/public-key derivation does not match "
            "publicKeyHex"
        )

    address = f"zera:{hashlib.sha256(public_key_bytes).digest()[:20].hex()}"
    if address != democracy_os["address"]:
        fail("independent DemocracyOS address does not match address")

    challenge_digest = hashlib.sha256(
        democracy_os["challenge"].encode("utf-8")
    ).digest()
    if challenge_digest.hex() != democracy_os["challengeDigestHex"]:
        fail("independent challenge digest does not match challengeDigestHex")

    compact_signature = bytes.fromhex(democracy_os["signatureHex"])
    r = int.from_bytes(compact_signature[:32], "big")
    s = int.from_bytes(compact_signature[32:], "big")
    if not (1 <= r < SECP256K1_ORDER and 1 <= s < SECP256K1_ORDER):
        fail("committed compact secp256k1 signature has an out-of-range scalar")
    der_signature = utils.encode_dss_signature(r, s)

    # Noble's DemocracyOS compatibility call receives challenge_digest as its
    # message and applies its default SHA-256 prehash before ECDSA. Compute that
    # second digest explicitly, then tell cryptography not to hash it again.
    noble_signing_digest = hashlib.sha256(challenge_digest).digest()
    try:
        public_key.verify(
            der_signature,
            noble_signing_digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
    except InvalidSignature:
        fail(
            "committed compact secp256k1 signature does not verify with Noble's "
            "default SHA-256 prehash semantics"
        )


def verify_zera_vector(password: str, zera: dict[str, Any]) -> None:
    normalized_username = normalize_zera_username(zera["username"])
    if normalized_username != zera["normalizedUsername"]:
        fail("independent username normalization does not match normalizedUsername")

    application_id = canonicalize_context(
        zera["applicationId"], "fixture.zeraEd25519V1.applicationId"
    )
    network_id = canonicalize_context(
        zera["networkId"], "fixture.zeraEd25519V1.networkId"
    )
    password_bytes = password.encode("utf-8")

    password_hash = hashlib.sha512(
        b"web2-ish-self-custody password hash v1\n" + password_bytes
    ).digest()
    entropy_transcript = "\n".join(
        (
            "web2-ish-self-custody ZERA Ed25519 entropy v1",
            application_id,
            network_id,
            normalized_username,
            password_hash.hex(),
        )
    ).encode("utf-8")
    wallet_entropy = hashlib.sha512(entropy_transcript).digest()

    salt_transcript = "\n".join(
        (
            "web2-ish-self-custody public username salt v1",
            application_id,
            network_id,
            normalized_username,
        )
    ).encode("utf-8")
    public_salt = hashlib.sha256(salt_transcript).digest()
    if public_salt.hex() != zera["publicSaltHex"]:
        fail("independent public salt does not match publicSaltHex")

    seed = hashlib.scrypt(
        wallet_entropy,
        salt=public_salt,
        n=65_536,
        r=8,
        p=1,
        dklen=32,
        maxmem=128 * 1_024 * 1_024,
    )
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if public_key_bytes.hex() != zera["publicKeyHex"]:
        fail("independent KDF/public-key derivation does not match publicKeyHex")

    address = base58_encode(public_key_bytes)
    if address != zera["address"]:
        fail("independent Base58 encoding does not match address")
    if f"A_{address}" != zera["publicKeyIdentifier"]:
        fail("independent public-key identifier does not match publicKeyIdentifier")

    message = zera["messageUtf8"].encode("utf-8")
    if not 1 <= len(message) <= 1_048_576:
        fail("fixture message must encode to 1-1,048,576 UTF-8 bytes")
    signature = private_key.sign(message)
    if signature.hex() != zera["signatureHex"]:
        fail("independent Ed25519 signature does not match signatureHex")
    try:
        public_key.verify(bytes.fromhex(zera["signatureHex"]), message)
    except InvalidSignature:
        fail("committed Ed25519 signature does not verify with the derived public key")


def main() -> int:
    try:
        password, democracy_os, zera = load_fixture()
        verify_democracy_os_vector(password, democracy_os)
        verify_zera_vector(password, zera)
    except VerificationError as error:
        print(f"Built-in vector verification failed: {error}", file=sys.stderr)
        return 1
    except (MemoryError, ValueError) as error:
        print(f"Built-in vector verification failed closed: {error}", file=sys.stderr)
        return 1

    print(
        "Independent Python verification passed for both built-in profiles: "
        "DemocracyOS normalization, transcripts, external salt, scrypt KDF, "
        "secp256k1 identity/address and double-prehash signature verification; "
        "ZERA normalization, transcripts, public salt, scrypt KDF, Ed25519 "
        "identity, Base58 address, deterministic signature and verification."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
