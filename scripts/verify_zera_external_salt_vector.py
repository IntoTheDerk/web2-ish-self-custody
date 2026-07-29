#!/usr/bin/env python3
"""Independently verify the external-salt ZERA Ed25519 profile vector."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "vectors" / "zera-ed25519-external-salt-v1.json"
PROFILE = "web2ish-zera-ed25519-external-salt-v1"
WARNING = "TEST-ONLY CREDENTIALS. NEVER USE THESE VALUES FOR A REAL WALLET."
EXPECTED_KEYS = frozenset(
    {
        "warning",
        "profile",
        "passwordUtf8",
        "username",
        "normalizedUsername",
        "applicationId",
        "networkId",
        "saltHex",
        "messageUtf8",
        "publicKeyHex",
        "publicKeyIdentifier",
        "address",
        "signatureHex",
    }
)
CONTEXT_PATTERN = re.compile(r"[a-z0-9][a-z0-9._:-]{0,79}", re.ASCII)
HEX_PATTERN = re.compile(r"[0-9a-f]+", re.ASCII)
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


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


def require_string(value: Any, location: str) -> str:
    if not isinstance(value, str):
        fail(f"{location} must be a string")
    return value


def require_hex(value: Any, byte_length: int, location: str) -> str:
    text = require_string(value, location)
    if len(text) != byte_length * 2 or HEX_PATTERN.fullmatch(text) is None:
        fail(f"{location} must be exactly {byte_length} lowercase-hex bytes")
    return text


def load_fixture() -> dict[str, str]:
    try:
        decoded = json.loads(
            FIXTURE_PATH.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read strict JSON fixture: {error}")
    if not isinstance(decoded, dict):
        fail("fixture must be an object")
    actual_keys = frozenset(decoded)
    if actual_keys != EXPECTED_KEYS:
        fail(
            "fixture has an invalid shape "
            f"(missing={sorted(EXPECTED_KEYS - actual_keys)!r}, "
            f"unexpected={sorted(actual_keys - EXPECTED_KEYS)!r})"
        )
    fixture = {
        key: require_string(decoded[key], f"fixture.{key}") for key in EXPECTED_KEYS
    }
    if fixture["warning"] != WARNING:
        fail("fixture.warning does not contain the required test-only warning")
    if fixture["profile"] != PROFILE:
        fail(f"fixture.profile must be {PROFILE!r}")
    require_hex(fixture["saltHex"], 32, "fixture.saltHex")
    require_hex(fixture["publicKeyHex"], 32, "fixture.publicKeyHex")
    require_hex(fixture["signatureHex"], 64, "fixture.signatureHex")
    return fixture


def normalize_username(username: str) -> str:
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


def verify_vector(fixture: dict[str, str]) -> None:
    normalized_username = normalize_username(fixture["username"])
    if normalized_username != fixture["normalizedUsername"]:
        fail("independent username normalization does not match normalizedUsername")
    application_id = canonicalize_context(
        fixture["applicationId"], "fixture.applicationId"
    )
    network_id = canonicalize_context(fixture["networkId"], "fixture.networkId")
    password = fixture["passwordUtf8"].encode("utf-8")
    if not 24 <= len(password) <= 1_024:
        fail("fixture password must encode to 24-1,024 UTF-8 bytes")

    password_hash = hashlib.sha512(
        b"web2-ish-self-custody password hash v1\n" + password
    ).digest()
    entropy_transcript = "\n".join(
        (
            "web2-ish-self-custody ZERA Ed25519 external salt entropy v1",
            application_id,
            network_id,
            normalized_username,
            password_hash.hex(),
        )
    ).encode("utf-8")
    wallet_entropy = hashlib.sha512(entropy_transcript).digest()
    seed = hashlib.scrypt(
        wallet_entropy,
        salt=bytes.fromhex(fixture["saltHex"]),
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
    if public_key_bytes.hex() != fixture["publicKeyHex"]:
        fail("independent KDF/public-key derivation does not match publicKeyHex")

    address = base58_encode(public_key_bytes)
    if address != fixture["address"]:
        fail("independent Base58 encoding does not match address")
    if f"A_{address}" != fixture["publicKeyIdentifier"]:
        fail("independent public-key identifier does not match publicKeyIdentifier")

    message = fixture["messageUtf8"].encode("utf-8")
    if not 1 <= len(message) <= 1_048_576:
        fail("fixture message must encode to 1-1,048,576 UTF-8 bytes")
    signature = private_key.sign(message)
    if signature.hex() != fixture["signatureHex"]:
        fail("independent Ed25519 signature does not match signatureHex")
    try:
        public_key.verify(bytes.fromhex(fixture["signatureHex"]), message)
    except InvalidSignature:
        fail("committed Ed25519 signature does not verify")


def main() -> int:
    try:
        verify_vector(load_fixture())
    except VerificationError as error:
        print(f"External-salt vector verification failed: {error}", file=sys.stderr)
        return 1
    except (MemoryError, ValueError) as error:
        print(
            f"External-salt vector verification failed closed: {error}",
            file=sys.stderr,
        )
        return 1
    print(
        "Independent Python verification passed for the external-salt ZERA "
        "Ed25519 profile: strict fixture shape, normalization, context-bound "
        "transcript, external salt, scrypt KDF, identity, address and signature."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
