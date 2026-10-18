#!/usr/bin/env python3
"""Independently verify the external-salt Kalvora Ed25519 profile vectors.

This reimplements the whole derivation, including SLIP-0010, from the standard
library and `cryptography` alone. It shares no code with kalvora.js or this
package, so agreement is evidence that both follow the specification.

Two fixtures are checked, each loaded by its explicit path with the same strict
shape checks: the wallet vector, and the application-secret vector, whose
HKDF-SHA256 over the same scrypt output is reimplemented with stdlib `hmac`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "vectors" / "kalvora-ed25519-external-salt-v1.json"
APPLICATION_SECRET_FIXTURE_PATH = (
    ROOT / "vectors" / "kalvora-ed25519-external-salt-v1.application-secret-v1.json"
)
PROFILE = "web2ish-kalvora-ed25519-external-salt-v1"
# SLIP-44 coin type 5258: account 0, change 0, address 0, all hardened.
KALVORA_PATH = (44, 5258, 0, 0, 0)
HARDENED = 0x8000_0000
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
# The credential fields the application-secret fixture shares with the wallet
# fixture; they must be identical, so both vectors describe one wallet.
SHARED_CREDENTIAL_KEYS = (
    "warning",
    "profile",
    "passwordUtf8",
    "username",
    "normalizedUsername",
    "applicationId",
    "networkId",
    "saltHex",
    "publicKeyHex",
    "publicKeyIdentifier",
)
APPLICATION_SECRET_DOMAIN = "web2-ish-self-custody application secret v1"
APPLICATION_SECRET_BYTES = 32
APPLICATION_SECRET_EXPECTED_KEYS = frozenset(
    {*SHARED_CREDENTIAL_KEYS, "construction", "prkHex", "secrets"}
)
APPLICATION_SECRET_ENTRY_KEYS = frozenset({"label", "infoUtf8", "secretHex"})
CONTEXT_PATTERN = re.compile(r"[a-z0-9][a-z0-9._:-]{0,79}", re.ASCII)
LABEL_PATTERN = re.compile(r"[a-z0-9][a-z0-9._:-]{2,79}", re.ASCII)
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


def read_strict_json(path: Path, location: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read strict JSON {location}: {error}")


def require_exact_keys(
    value: Any, expected: frozenset[str], location: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{location} must be an object")
    actual_keys = frozenset(value)
    if actual_keys != expected:
        fail(
            f"{location} has an invalid shape "
            f"(missing={sorted(expected - actual_keys)!r}, "
            f"unexpected={sorted(actual_keys - expected)!r})"
        )
    return value


def load_fixture() -> dict[str, str]:
    decoded = require_exact_keys(
        read_strict_json(FIXTURE_PATH, "fixture"), EXPECTED_KEYS, "fixture"
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


def load_application_secret_fixture() -> dict[str, Any]:
    """Load the application-secret fixture with the wallet fixture's strictness."""
    location = "application-secret fixture"
    decoded = require_exact_keys(
        read_strict_json(APPLICATION_SECRET_FIXTURE_PATH, location),
        APPLICATION_SECRET_EXPECTED_KEYS,
        location,
    )
    fixture: dict[str, Any] = {
        key: require_string(decoded[key], f"{location}.{key}")
        for key in APPLICATION_SECRET_EXPECTED_KEYS - {"secrets"}
    }
    if fixture["warning"] != WARNING:
        fail(f"{location}.warning does not contain the required test-only warning")
    if fixture["profile"] != PROFILE:
        fail(f"{location}.profile must be {PROFILE!r}")
    if fixture["construction"] != APPLICATION_SECRET_DOMAIN:
        fail(f"{location}.construction must be {APPLICATION_SECRET_DOMAIN!r}")
    require_hex(fixture["saltHex"], 32, f"{location}.saltHex")
    require_hex(fixture["publicKeyHex"], 32, f"{location}.publicKeyHex")
    require_hex(fixture["prkHex"], 32, f"{location}.prkHex")

    secrets = decoded["secrets"]
    if not isinstance(secrets, list) or len(secrets) == 0:
        fail(f"{location}.secrets must be a non-empty array")
    entries: list[dict[str, str]] = []
    for index, raw_entry in enumerate(secrets):
        entry_location = f"{location}.secrets[{index}]"
        entry = require_exact_keys(raw_entry, APPLICATION_SECRET_ENTRY_KEYS, entry_location)
        entries.append(
            {
                key: require_string(entry[key], f"{entry_location}.{key}")
                for key in APPLICATION_SECRET_ENTRY_KEYS
            }
        )
        require_hex(
            entries[-1]["secretHex"],
            APPLICATION_SECRET_BYTES,
            f"{entry_location}.secretHex",
        )
    fixture["secrets"] = entries
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


def slip10_ed25519(seed: bytes, path: tuple[int, ...]) -> bytes:
    """SLIP-0010 private-key derivation for ed25519, hardened segments only."""
    node = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    for index in path:
        data = b"\x00" + node[:32] + (index + HARDENED).to_bytes(4, "big")
        node = hmac.new(node[32:], data, hashlib.sha512).digest()
    return node[:32]


def check_slip10_reference() -> None:
    """Pin the SLIP-0010 implementation to the specification's test vector 1."""
    key = slip10_ed25519(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"), (0, 1, 2, 2, 1_000_000_000)
    )
    if key.hex() != (
        "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"
    ):
        fail("SLIP-0010 implementation does not reproduce the specification vector")


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 section 2.2: PRK = HMAC-Hash(salt, IKM)."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_sha256(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 section 2.3: T(i) = HMAC-Hash(PRK, T(i-1) | info | i)."""
    if not 0 < length <= 255 * 32:
        fail("HKDF-Expand length is out of range")
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes((counter,)), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


def check_hkdf_reference() -> None:
    """Pin the HKDF implementation to RFC 5869 appendix A.1 (test case 1)."""
    prk = hkdf_extract_sha256(bytes(range(13)), b"\x0b" * 22)
    if prk.hex() != (
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    ):
        fail("HKDF-Extract implementation does not reproduce RFC 5869 test case 1")
    okm = hkdf_expand_sha256(prk, bytes(range(0xF0, 0xFA)), 42)
    if okm.hex() != (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    ):
        fail("HKDF-Expand implementation does not reproduce RFC 5869 test case 1")


def derive_master_seed(
    fixture: dict[str, Any], location: str
) -> tuple[str, str, str, bytes]:
    """Steps 1-4 of the transcript: normalization, entropy, external salt, scrypt."""
    normalized_username = normalize_username(fixture["username"])
    if normalized_username != fixture["normalizedUsername"]:
        fail(
            f"independent username normalization does not match "
            f"{location}.normalizedUsername"
        )
    application_id = canonicalize_context(
        fixture["applicationId"], f"{location}.applicationId"
    )
    network_id = canonicalize_context(fixture["networkId"], f"{location}.networkId")
    # Python's len() on a str counts code points, which is exactly the unit of
    # the SDK's MINIMUM_PASSWORD_CHARACTERS; the ceiling is on encoded bytes.
    if len(fixture["passwordUtf8"]) < 10:
        fail("fixture password must be at least 10 characters (code points)")
    password = fixture["passwordUtf8"].encode("utf-8")
    if len(password) > 1_024:
        fail("fixture password must encode to at most 1,024 UTF-8 bytes")

    password_hash = hashlib.sha512(
        b"web2-ish-self-custody password hash v1\n" + password
    ).digest()
    entropy_transcript = "\n".join(
        (
            "web2-ish-self-custody Kalvora Ed25519 external salt entropy v1",
            application_id,
            network_id,
            normalized_username,
            password_hash.hex(),
        )
    ).encode("utf-8")
    wallet_entropy = hashlib.sha512(entropy_transcript).digest()
    master_seed = hashlib.scrypt(
        wallet_entropy,
        salt=bytes.fromhex(fixture["saltHex"]),
        n=65_536,
        r=8,
        p=1,
        dklen=32,
        maxmem=128 * 1_024 * 1_024,
    )
    return normalized_username, application_id, network_id, master_seed


def verify_vector(fixture: dict[str, str]) -> None:
    _, _, _, master_seed = derive_master_seed(fixture, "fixture")
    seed = slip10_ed25519(master_seed, KALVORA_PATH)
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


def verify_application_secret_vector(
    fixture: dict[str, Any], wallet_fixture: dict[str, str]
) -> None:
    location = "application-secret fixture"
    for key in SHARED_CREDENTIAL_KEYS:
        if fixture[key] != wallet_fixture[key]:
            fail(f"{location}.{key} differs from the wallet fixture")

    normalized_username, application_id, network_id, master_seed = derive_master_seed(
        fixture, location
    )
    seed = slip10_ed25519(master_seed, KALVORA_PATH)
    public_key_bytes = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    if public_key_bytes.hex() != fixture["publicKeyHex"]:
        fail(f"independent derivation does not match {location}.publicKeyHex")
    if f"A_{base58_encode(public_key_bytes)}" != fixture["publicKeyIdentifier"]:
        fail(f"independent derivation does not match {location}.publicKeyIdentifier")

    domain = APPLICATION_SECRET_DOMAIN.encode("utf-8")
    prk = hkdf_extract_sha256(domain, master_seed)
    if prk.hex() != fixture["prkHex"]:
        fail(f"independent HKDF-Extract does not match {location}.prkHex")

    seen_labels: set[str] = set()
    seen_secrets: set[bytes] = set()
    for index, entry in enumerate(fixture["secrets"]):
        entry_location = f"{location}.secrets[{index}]"
        label = entry["label"]
        if LABEL_PATTERN.fullmatch(label) is None:
            fail(f"{entry_location}.label is not a valid application secret label")
        if label in seen_labels:
            fail(f"{entry_location}.label repeats an earlier label")
        seen_labels.add(label)

        info = "\n".join(
            (
                APPLICATION_SECRET_DOMAIN,
                fixture["profile"],
                application_id,
                network_id,
                normalized_username,
                label,
            )
        ).encode("utf-8")
        if info != entry["infoUtf8"].encode("utf-8"):
            fail(f"independent info construction does not match {entry_location}.infoUtf8")
        secret = hkdf_expand_sha256(prk, info, APPLICATION_SECRET_BYTES)
        if secret.hex() != entry["secretHex"]:
            fail(f"independent HKDF-Expand does not match {entry_location}.secretHex")
        if secret in (master_seed, seed, prk, public_key_bytes) or secret in seen_secrets:
            fail(f"{entry_location}.secretHex is not separated from the other values")
        seen_secrets.add(secret)


def main() -> int:
    try:
        check_slip10_reference()
        check_hkdf_reference()
        wallet_fixture = load_fixture()
        verify_vector(wallet_fixture)
        verify_application_secret_vector(
            load_application_secret_fixture(), wallet_fixture
        )
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
        "Independent Python verification passed for the external-salt Kalvora "
        "Ed25519 profile: strict fixture shape, normalization, context-bound "
        "transcript, external salt, scrypt KDF, SLIP-0010 at m/44'/5258'/0'/0'/0', "
        "identity, address and signature; and for its application secrets: "
        "strict fixture shape, HKDF-SHA256 (checked against RFC 5869), PRK, "
        "info, labels and secrets."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
