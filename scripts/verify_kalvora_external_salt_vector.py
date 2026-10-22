#!/usr/bin/env python3
"""Independently verify the external-salt profile vectors.

This reimplements the whole derivation, including SLIP-0010, from the standard
library and `cryptography` alone. It shares no code with kalvora.js or this
package, so agreement is evidence that both follow the specification.

Four fixtures are checked, each loaded by its explicit path with the same strict
shape checks: the Kalvora wallet vector; the application-secret vector, whose
HKDF-SHA256 over the same scrypt output is reimplemented with stdlib `hmac`; the
sign-in vector, which runs the same credentials through the sign-in profile's
own transcript and HKDF key step, its application secrets, and the Kalvora
wallet opened from one of those secrets as a SLIP-0010 master seed; and the
sign-in v2 vector, the same construction under the v2 profile's own domains and
scrypt at N = 2^18, which must differ from v1 in every derived value.
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
SIGN_IN_FIXTURE_PATH = ROOT / "vectors" / "sign-in-ed25519-external-salt-v1.json"
SIGN_IN_V2_FIXTURE_PATH = ROOT / "vectors" / "sign-in-ed25519-external-salt-v2.json"
PROFILE = "web2ish-kalvora-ed25519-external-salt-v1"
KALVORA_PASSWORD_HASH_DOMAIN = b"web2-ish-self-custody password hash v1\n"
KALVORA_ENTROPY_DOMAIN = "web2-ish-self-custody Kalvora Ed25519 external salt entropy v1"
KALVORA_CODEC = "kalvora-ed25519-base58-v1"
KALVORA_PATH_TEXT = "m/44'/5258'/0'/0'/0'"
KALVORA_DERIVATION = f"slip10-ed25519:{KALVORA_PATH_TEXT}"
SIGN_IN_PROFILE = "web2ish-sign-in-ed25519-external-salt-v1"
SIGN_IN_ALGORITHM = "scrypt-sha512-hkdf-sha256-ed25519-external-32-v1"
SIGN_IN_PASSWORD_HASH_DOMAIN = b"web2-ish-self-custody sign-in password hash v1\n"
SIGN_IN_ENTROPY_DOMAIN = "web2-ish-self-custody sign-in Ed25519 external salt entropy v1"
SIGN_IN_KEY_DOMAIN = "web2-ish-self-custody sign-in key v1"
SIGN_IN_KEY_DERIVATION = "hkdf-sha256-sign-in-key-v1"
SIGN_IN_CODEC = "web2ish-sign-in-ed25519-hex-v1"
# scrypt parameters per profile. N is the only one that differs.
SCRYPT_N_V1 = 65_536
SCRYPT_N_V2 = 262_144
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
# hashlib's maxmem must exceed scrypt's 128 * r * N bytes (256 MiB at N = 2^18).
SCRYPT_MAXMEM = 512 * 1_024 * 1_024
# The sign-in profile v2: v1's construction, key step and codec, with its own
# id, algorithm label and transcript domains, and scrypt at N = 2^18.
SIGN_IN_V2_PROFILE = "web2ish-sign-in-ed25519-external-salt-v2"
SIGN_IN_V2_ALGORITHM = "scrypt-sha512-hkdf-sha256-ed25519-external-32-v2"
SIGN_IN_V2_PASSWORD_HASH_DOMAIN = b"web2-ish-self-custody sign-in password hash v2\n"
SIGN_IN_V2_ENTROPY_DOMAIN = "web2-ish-self-custody sign-in Ed25519 external salt entropy v2"
SIGN_IN_V2_KDF = {
    "name": "scrypt",
    "N": SCRYPT_N_V2,
    "r": SCRYPT_R,
    "p": SCRYPT_P,
    "dkLen": SCRYPT_DKLEN,
}
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
# The credential fields the sign-in fixture shares with the wallet fixture: the
# same password, username, context and salt, so the two vectors can be compared.
SIGN_IN_SHARED_CREDENTIAL_KEYS = (
    "warning",
    "passwordUtf8",
    "username",
    "normalizedUsername",
    "applicationId",
    "networkId",
    "saltHex",
)
SIGN_IN_EXPECTED_KEYS = frozenset(
    {
        *SIGN_IN_SHARED_CREDENTIAL_KEYS,
        "profile",
        "algorithm",
        "passwordHashHex",
        "entropyHex",
        "masterSeedHex",
        "signInKey",
        "applicationSecrets",
        "kalvoraWallet",
    }
)
# v2 adds one field, the KDF parameters, so a reimplementer reads them from the
# vector rather than from this script.
SIGN_IN_V2_EXPECTED_KEYS = frozenset({*SIGN_IN_EXPECTED_KEYS, "kdf"})
SIGN_IN_KDF_EXPECTED_KEYS = frozenset({"name", "N", "r", "p", "dkLen"})
SIGN_IN_KEY_EXPECTED_KEYS = frozenset(
    {
        "keyDerivation",
        "domain",
        "codec",
        "prkHex",
        "seedHex",
        "publicKeyHex",
        "publicKeyIdentifier",
        "address",
        "fingerprint",
        "messageUtf8",
        "signatureHex",
    }
)
SIGN_IN_SECRETS_EXPECTED_KEYS = frozenset({"construction", "prkHex", "secrets"})
SIGN_IN_WALLET_EXPECTED_KEYS = frozenset(
    {
        "masterSeedLabel",
        "path",
        "derivation",
        "codec",
        "publicKeyHex",
        "publicKeyIdentifier",
        "address",
        "fingerprint",
        "messageUtf8",
        "signatureHex",
    }
)
SIGN_IN_IDENTIFIER_PATTERN = re.compile(r"S_[0-9a-f]{64}", re.ASCII)
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

    fixture["secrets"] = load_secret_entries(decoded["secrets"], location)
    return fixture


def load_secret_entries(secrets: Any, location: str) -> list[dict[str, str]]:
    """Each entry of a fixture's `secrets` array, with the same strict shape."""
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
    return entries


def require_string_fields(
    value: dict[str, Any], keys: frozenset[str], location: str
) -> dict[str, str]:
    return {key: require_string(value[key], f"{location}.{key}") for key in keys}


def load_sign_in_fixture(
    path: Path = SIGN_IN_FIXTURE_PATH,
    location: str = "sign-in fixture",
    profile: str = SIGN_IN_PROFILE,
    algorithm: str = SIGN_IN_ALGORITHM,
    kdf: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Load a sign-in fixture, nested objects included, with the same strictness.

    v1 has no `kdf` field; v2 (`kdf` given) requires one equal to `kdf`, with
    integer parameters that are not booleans.
    """
    expected = SIGN_IN_EXPECTED_KEYS if kdf is None else SIGN_IN_V2_EXPECTED_KEYS
    decoded = require_exact_keys(read_strict_json(path, location), expected, location)
    nested = {"signInKey", "applicationSecrets", "kalvoraWallet", "kdf"}
    fixture: dict[str, Any] = require_string_fields(decoded, expected - nested, location)
    if fixture["warning"] != WARNING:
        fail(f"{location}.warning does not contain the required test-only warning")
    if fixture["profile"] != profile:
        fail(f"{location}.profile must be {profile!r}")
    if fixture["algorithm"] != algorithm:
        fail(f"{location}.algorithm must be {algorithm!r}")
    if kdf is not None:
        kdf_location = f"{location}.kdf"
        raw_kdf = require_exact_keys(decoded["kdf"], SIGN_IN_KDF_EXPECTED_KEYS, kdf_location)
        if require_string(raw_kdf["name"], f"{kdf_location}.name") != kdf["name"]:
            fail(f"{kdf_location}.name must be {kdf['name']!r}")
        for key in ("N", "r", "p", "dkLen"):
            value = raw_kdf[key]
            if type(value) is not int or value != kdf[key]:
                fail(f"{kdf_location}.{key} must be the integer {kdf[key]}")
        fixture["kdf"] = dict(raw_kdf)
    require_hex(fixture["saltHex"], 32, f"{location}.saltHex")
    require_hex(fixture["passwordHashHex"], 64, f"{location}.passwordHashHex")
    require_hex(fixture["entropyHex"], 64, f"{location}.entropyHex")
    require_hex(fixture["masterSeedHex"], 32, f"{location}.masterSeedHex")

    key_location = f"{location}.signInKey"
    sign_in_key = require_string_fields(
        require_exact_keys(decoded["signInKey"], SIGN_IN_KEY_EXPECTED_KEYS, key_location),
        SIGN_IN_KEY_EXPECTED_KEYS,
        key_location,
    )
    if sign_in_key["keyDerivation"] != SIGN_IN_KEY_DERIVATION:
        fail(f"{key_location}.keyDerivation must be {SIGN_IN_KEY_DERIVATION!r}")
    if sign_in_key["domain"] != SIGN_IN_KEY_DOMAIN:
        fail(f"{key_location}.domain must be {SIGN_IN_KEY_DOMAIN!r}")
    if sign_in_key["codec"] != SIGN_IN_CODEC:
        fail(f"{key_location}.codec must be {SIGN_IN_CODEC!r}")
    for key, length in (("prkHex", 32), ("seedHex", 32), ("publicKeyHex", 32), ("signatureHex", 64)):
        require_hex(sign_in_key[key], length, f"{key_location}.{key}")
    fixture["signInKey"] = sign_in_key

    secrets_location = f"{location}.applicationSecrets"
    raw_secrets = require_exact_keys(
        decoded["applicationSecrets"], SIGN_IN_SECRETS_EXPECTED_KEYS, secrets_location
    )
    application_secrets: dict[str, Any] = require_string_fields(
        raw_secrets, SIGN_IN_SECRETS_EXPECTED_KEYS - {"secrets"}, secrets_location
    )
    if application_secrets["construction"] != APPLICATION_SECRET_DOMAIN:
        fail(f"{secrets_location}.construction must be {APPLICATION_SECRET_DOMAIN!r}")
    require_hex(application_secrets["prkHex"], 32, f"{secrets_location}.prkHex")
    application_secrets["secrets"] = load_secret_entries(raw_secrets["secrets"], secrets_location)
    fixture["applicationSecrets"] = application_secrets

    wallet_location = f"{location}.kalvoraWallet"
    wallet = require_string_fields(
        require_exact_keys(decoded["kalvoraWallet"], SIGN_IN_WALLET_EXPECTED_KEYS, wallet_location),
        SIGN_IN_WALLET_EXPECTED_KEYS,
        wallet_location,
    )
    if wallet["path"] != KALVORA_PATH_TEXT:
        fail(f"{wallet_location}.path must be {KALVORA_PATH_TEXT!r}")
    if wallet["derivation"] != KALVORA_DERIVATION:
        fail(f"{wallet_location}.derivation must be {KALVORA_DERIVATION!r}")
    if wallet["codec"] != KALVORA_CODEC:
        fail(f"{wallet_location}.codec must be {KALVORA_CODEC!r}")
    require_hex(wallet["publicKeyHex"], 32, f"{wallet_location}.publicKeyHex")
    require_hex(wallet["signatureHex"], 64, f"{wallet_location}.signatureHex")
    fixture["kalvoraWallet"] = wallet
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


def fingerprint(value: str) -> str:
    """The core's display fingerprint: ASCII alphanumerics, uppercased, 16, by four."""
    compact = "".join(
        character for character in value if character.isascii() and character.isalnum()
    ).upper()[:16]
    return " ".join(compact[index : index + 4] for index in range(0, len(compact), 4))


def derive_master_seed(
    fixture: dict[str, Any], location: str
) -> tuple[str, str, str, bytes]:
    """Steps 1-4 of the Kalvora transcript: normalization, entropy, external salt, scrypt."""
    normalized_username, application_id, network_id, _, _, master_seed = derive_transcript(
        fixture, location, KALVORA_PASSWORD_HASH_DOMAIN, KALVORA_ENTROPY_DOMAIN
    )
    return normalized_username, application_id, network_id, master_seed


def derive_transcript(
    fixture: dict[str, Any],
    location: str,
    password_hash_domain: bytes,
    entropy_domain: str,
    scrypt_n: int = SCRYPT_N_V1,
) -> tuple[str, str, str, bytes, bytes, bytes]:
    """Steps 1-4 of a profile's transcript, returning its intermediates too."""
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

    password_hash = hashlib.sha512(password_hash_domain + password).digest()
    entropy_transcript = "\n".join(
        (
            entropy_domain,
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
        n=scrypt_n,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return (
        normalized_username,
        application_id,
        network_id,
        password_hash,
        wallet_entropy,
        master_seed,
    )


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def verify_exact_signature(
    private_key: Ed25519PrivateKey, message_utf8: str, signature_hex: str, location: str
) -> None:
    message = message_utf8.encode("utf-8")
    if not 1 <= len(message) <= 1_048_576:
        fail(f"{location}.messageUtf8 must encode to 1-1,048,576 UTF-8 bytes")
    if private_key.sign(message).hex() != signature_hex:
        fail(f"independent Ed25519 signature does not match {location}.signatureHex")
    try:
        private_key.public_key().verify(bytes.fromhex(signature_hex), message)
    except InvalidSignature:
        fail(f"committed Ed25519 signature in {location} does not verify")


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


def verify_sign_in_vector(
    fixture: dict[str, Any],
    wallet_fixture: dict[str, str],
    secret_fixture: dict[str, Any],
    location: str = "sign-in fixture",
    password_hash_domain: bytes = SIGN_IN_PASSWORD_HASH_DOMAIN,
    entropy_domain: str = SIGN_IN_ENTROPY_DOMAIN,
    scrypt_n: int = SCRYPT_N_V1,
) -> dict[str, Any]:
    """Reproduce a sign-in fixture and return its derived values for comparison."""
    for key in SIGN_IN_SHARED_CREDENTIAL_KEYS:
        if fixture[key] != wallet_fixture[key]:
            fail(f"{location}.{key} differs from the wallet fixture")

    (
        normalized_username,
        application_id,
        network_id,
        password_hash,
        entropy,
        master_seed,
    ) = derive_transcript(
        fixture, location, password_hash_domain, entropy_domain, scrypt_n
    )
    if password_hash.hex() != fixture["passwordHashHex"]:
        fail(f"independent password hash does not match {location}.passwordHashHex")
    if entropy.hex() != fixture["entropyHex"]:
        fail(f"independent entropy transcript does not match {location}.entropyHex")
    if master_seed.hex() != fixture["masterSeedHex"]:
        fail(f"independent scrypt output does not match {location}.masterSeedHex")

    # The sign-in key: RFC 5869 HKDF-SHA256 with the domain as salt and info.
    key_location = f"{location}.signInKey"
    sign_in = fixture["signInKey"]
    domain = SIGN_IN_KEY_DOMAIN.encode("utf-8")
    sign_in_prk = hkdf_extract_sha256(domain, master_seed)
    if sign_in_prk.hex() != sign_in["prkHex"]:
        fail(f"independent HKDF-Extract does not match {key_location}.prkHex")
    sign_in_seed = hkdf_expand_sha256(sign_in_prk, domain, 32)
    if sign_in_seed.hex() != sign_in["seedHex"]:
        fail(f"independent HKDF-Expand does not match {key_location}.seedHex")
    sign_in_private_key = Ed25519PrivateKey.from_private_bytes(sign_in_seed)
    sign_in_public_key = raw_public_key(sign_in_private_key)
    if sign_in_public_key.hex() != sign_in["publicKeyHex"]:
        fail(f"independent public-key derivation does not match {key_location}.publicKeyHex")
    identifier = f"S_{sign_in_public_key.hex()}"
    if SIGN_IN_IDENTIFIER_PATTERN.fullmatch(identifier) is None:
        fail("independent sign-in identifier does not have the S_<64 hex> form")
    if identifier != sign_in["publicKeyIdentifier"]:
        fail(f"independent identifier does not match {key_location}.publicKeyIdentifier")
    if identifier != sign_in["address"]:
        fail(f"independent address does not match {key_location}.address")
    if fingerprint(identifier) != sign_in["fingerprint"]:
        fail(f"independent fingerprint does not match {key_location}.fingerprint")
    verify_exact_signature(
        sign_in_private_key, sign_in["messageUtf8"], sign_in["signatureHex"], key_location
    )

    # Application secrets under the sign-in profile id, from the same scrypt output.
    secrets_location = f"{location}.applicationSecrets"
    application_secrets = fixture["applicationSecrets"]
    application_prk = hkdf_extract_sha256(APPLICATION_SECRET_DOMAIN.encode("utf-8"), master_seed)
    if application_prk.hex() != application_secrets["prkHex"]:
        fail(f"independent HKDF-Extract does not match {secrets_location}.prkHex")
    secrets_by_label: dict[str, bytes] = {}
    for index, entry in enumerate(application_secrets["secrets"]):
        entry_location = f"{secrets_location}.secrets[{index}]"
        label = entry["label"]
        if LABEL_PATTERN.fullmatch(label) is None:
            fail(f"{entry_location}.label is not a valid application secret label")
        if label in secrets_by_label:
            fail(f"{entry_location}.label repeats an earlier label")
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
        secret = hkdf_expand_sha256(application_prk, info, APPLICATION_SECRET_BYTES)
        if secret.hex() != entry["secretHex"]:
            fail(f"independent HKDF-Expand does not match {entry_location}.secretHex")
        if secret in (
            master_seed,
            sign_in_prk,
            sign_in_seed,
            sign_in_public_key,
            application_prk,
            *secrets_by_label.values(),
        ):
            fail(f"{entry_location}.secretHex is not separated from the other values")
        secrets_by_label[label] = secret

    # The Kalvora wallet: SLIP-0010 at the Kalvora path, from one secret as master seed.
    wallet_location = f"{location}.kalvoraWallet"
    wallet = fixture["kalvoraWallet"]
    wallet_master_seed = secrets_by_label.get(wallet["masterSeedLabel"])
    if wallet_master_seed is None:
        fail(f"{wallet_location}.masterSeedLabel names no secret in {secrets_location}")
    wallet_private_key = Ed25519PrivateKey.from_private_bytes(
        slip10_ed25519(wallet_master_seed, KALVORA_PATH)
    )
    wallet_public_key = raw_public_key(wallet_private_key)
    if wallet_public_key.hex() != wallet["publicKeyHex"]:
        fail(f"independent SLIP-0010 derivation does not match {wallet_location}.publicKeyHex")
    wallet_address = base58_encode(wallet_public_key)
    if wallet_address != wallet["address"]:
        fail(f"independent Base58 encoding does not match {wallet_location}.address")
    if f"A_{wallet_address}" != wallet["publicKeyIdentifier"]:
        fail(f"independent identifier does not match {wallet_location}.publicKeyIdentifier")
    if fingerprint(wallet_address) != wallet["fingerprint"]:
        fail(f"independent fingerprint does not match {wallet_location}.fingerprint")
    verify_exact_signature(
        wallet_private_key, wallet["messageUtf8"], wallet["signatureHex"], wallet_location
    )

    # Same credentials and salt, different keys: the sign-in key is not the
    # Kalvora password wallet, nor the wallet opened from the secret, and the
    # profile id in `info` separates the secrets from the Kalvora profile's.
    kalvora_password_wallet = bytes.fromhex(wallet_fixture["publicKeyHex"])
    if len({sign_in_public_key, wallet_public_key, kalvora_password_wallet}) != 3:
        fail(f"{location} keys are not separated from each other and the wallet fixture")
    _, _, _, kalvora_master_seed = derive_master_seed(wallet_fixture, "fixture")
    if master_seed == kalvora_master_seed:
        fail(f"{location}.masterSeedHex equals the Kalvora profile's scrypt output")
    kalvora_secrets = {entry["label"]: entry["secretHex"] for entry in secret_fixture["secrets"]}
    for label, secret in secrets_by_label.items():
        if kalvora_secrets.get(label) == secret.hex():
            fail(f"{secrets_location} {label!r} equals the Kalvora profile's secret")
    if not any(label in kalvora_secrets for label in secrets_by_label):
        fail(f"{secrets_location} shares no label with the Kalvora application-secret fixture")
    return {
        "masterSeed": master_seed,
        "passwordHash": password_hash,
        "entropy": entropy,
        "signInPublicKey": sign_in_public_key,
        "walletPublicKey": wallet_public_key,
        "secrets": secrets_by_label,
    }


def verify_sign_in_v2_vector(
    fixture: dict[str, Any],
    wallet_fixture: dict[str, str],
    secret_fixture: dict[str, Any],
    v1_fixture: dict[str, Any],
    v1_values: dict[str, Any],
) -> None:
    """Reproduce the v2 fixture at N = 2^18 and require it to differ from v1."""
    location = "sign-in v2 fixture"
    v2_values = verify_sign_in_vector(
        fixture,
        wallet_fixture,
        secret_fixture,
        location,
        SIGN_IN_V2_PASSWORD_HASH_DOMAIN,
        SIGN_IN_V2_ENTROPY_DOMAIN,
        SCRYPT_N_V2,
    )
    for key in SIGN_IN_SHARED_CREDENTIAL_KEYS:
        if fixture[key] != v1_fixture[key]:
            fail(f"{location}.{key} differs from the sign-in v1 fixture")
    if fixture["profile"] == v1_fixture["profile"] or fixture["algorithm"] == v1_fixture["algorithm"]:
        fail(f"{location} reuses the v1 profile id or algorithm label")
    for key in ("passwordHash", "entropy", "masterSeed", "signInPublicKey", "walletPublicKey"):
        if v2_values[key] == v1_values[key]:
            fail(f"{location} {key} equals the sign-in v1 fixture's")
    for label, secret in v2_values["secrets"].items():
        if v1_values["secrets"].get(label) == secret:
            fail(f"{location} secret {label!r} equals the sign-in v1 fixture's")
    if not any(label in v1_values["secrets"] for label in v2_values["secrets"]):
        fail(f"{location} shares no label with the sign-in v1 fixture")
    # The v2 cost is the point: the same entropy at v1's N must not give v2's seed.
    at_v1_cost = hashlib.scrypt(
        v2_values["entropy"],
        salt=bytes.fromhex(fixture["saltHex"]),
        n=SCRYPT_N_V1,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    if at_v1_cost == v2_values["masterSeed"]:
        fail(f"{location}.masterSeedHex does not depend on N = 2^18")


def main() -> int:
    try:
        check_slip10_reference()
        check_hkdf_reference()
        wallet_fixture = load_fixture()
        verify_vector(wallet_fixture)
        secret_fixture = load_application_secret_fixture()
        verify_application_secret_vector(secret_fixture, wallet_fixture)
        sign_in_fixture = load_sign_in_fixture()
        sign_in_values = verify_sign_in_vector(sign_in_fixture, wallet_fixture, secret_fixture)
        verify_sign_in_v2_vector(
            load_sign_in_fixture(
                SIGN_IN_V2_FIXTURE_PATH,
                "sign-in v2 fixture",
                SIGN_IN_V2_PROFILE,
                SIGN_IN_V2_ALGORITHM,
                SIGN_IN_V2_KDF,
            ),
            wallet_fixture,
            secret_fixture,
            sign_in_fixture,
            sign_in_values,
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
        "identity, address and signature; for its application secrets: "
        "strict fixture shape, HKDF-SHA256 (checked against RFC 5869), PRK, "
        "info, labels and secrets; and for the sign-in profile: strict fixture "
        "shape, its transcript intermediates and scrypt output, the HKDF-SHA256 "
        "sign-in key, S_ identifier, fingerprint and signature, its application "
        "secrets, the Kalvora wallet from one of them at m/44'/5258'/0'/0'/0', "
        "and separation from the Kalvora vectors; and for the sign-in profile "
        "v2: the same checks under its own domains with scrypt at N=2^18, its "
        "KDF field, and separation from every v1 value."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
