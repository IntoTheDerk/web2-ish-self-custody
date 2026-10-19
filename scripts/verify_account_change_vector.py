#!/usr/bin/env python3
"""Independently verify the account-change vector.

`vectors/account-change-v1.json` pins the account-change message (ten lines,
docs/PROTOCOL.md "Account-change message") for each action, signatures by three
keys, and four signatures that a strict verifier must refuse. This script
reproduces all of it from the standard library and `cryptography` alone, and
shares no code with the TypeScript implementation:

- the two sign-in keys are derived from credentials (the sign-in profile's
  transcript, scrypt and HKDF step), the first of them checked against the
  committed sign-in vector, and the recovery key from its seed label;
- each message is rebuilt from its fields, and each signature re-signed (Ed25519
  is deterministic) and verified;
- every verification first applies RFC 8032's strict checks (S < L, canonical A
  and R, A not one of the eight small-order points by explicit byte comparison)
  and only then calls `cryptography`; each negative case must fail exactly the
  check its `reason` names;
- `acceptedUnderZip215` is checked against this script's own ZIP-215
  (cofactored, non-canonical-tolerant) verification in pure Python, which is how
  the small-order case verifies under a lax rule.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "vectors" / "account-change-v1.json"
SIGN_IN_FIXTURE_PATH = ROOT / "vectors" / "sign-in-ed25519-external-salt-v1.json"
WARNING = "TEST-ONLY CREDENTIALS. NEVER USE THESE VALUES FOR A REAL WALLET."
ACCOUNT_CHANGE_DOMAIN = "web2-ish-self-custody account change v1"
SIGN_IN_PROFILE = "web2ish-sign-in-ed25519-external-salt-v1"
SIGN_IN_PASSWORD_HASH_DOMAIN = b"web2-ish-self-custody sign-in password hash v1\n"
SIGN_IN_ENTROPY_DOMAIN = "web2-ish-self-custody sign-in Ed25519 external salt entropy v1"
SIGN_IN_KEY_DOMAIN = b"web2-ish-self-custody sign-in key v1"

# Ed25519 (RFC 8032 section 5.1).
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

# The canonical encodings of the eight points of small order, compared byte
# for byte with a submitted public key (checked against the curve below).
SMALL_ORDER_ENCODINGS = frozenset(
    bytes.fromhex(value)
    for value in (
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    )
)

# The action table of docs/PROTOCOL.md Part 4: the principal forms of each action and
# which keys sign. "key" is a sign-in key, "recovery-key" the recovery key.
ACTION_RULES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "sign-in-key-rotation": ("key", "key", ("authorizer", "subject")),
    "email-change": ("key", "email", ("authorizer",)),
    "recovery-key-enrollment": ("key", "recovery-key", ("authorizer", "subject")),
    "recovery-key-removal": ("key", "none", ("authorizer",)),
    "recovery-begin": ("recovery-key", "none", ("authorizer",)),
    "recovery-reset": ("recovery-key", "key", ("authorizer", "subject")),
}
# Which fixture key each principal of each action names.
ACTION_KEYS: dict[str, tuple[str, str | None]] = {
    "sign-in-key-rotation": ("current", "next"),
    "email-change": ("current", None),
    "recovery-key-enrollment": ("current", "recovery"),
    "recovery-key-removal": ("current", None),
    "recovery-begin": ("recovery", None),
    "recovery-reset": ("recovery", "next"),
}
NEGATIVE_REASONS = (
    "small-order-public-key",
    "non-canonical-public-key",
    "non-canonical-r",
    "s-not-below-l",
)

EXPECTED_KEYS = frozenset(
    {"warning", "format", "signInCredentials", "context", "keys", "cases", "negativeCases"}
)
CREDENTIAL_KEYS = frozenset(
    {"profile", "username", "normalizedUsername", "applicationId", "networkId", "saltHex"}
)
CONTEXT_KEYS = frozenset(
    {"serviceProfileId", "applicationId", "networkId", "usernameNormalized", "nonceHex", "expiresAt"}
)
DERIVED_KEY_KEYS = frozenset(
    {"passwordUtf8", "masterSeedHex", "seedHex", "publicKeyHex", "principal"}
)
RECOVERY_KEY_KEYS = frozenset({"seedLabel", "seedHex", "publicKeyHex", "principal"})
CASE_KEYS = frozenset({"action", "authorizer", "subject", "messageUtf8", "signatures"})
EMAIL_CASE_KEYS = CASE_KEYS | {"emailInput"}
SIGNATURE_KEYS = frozenset({"role", "signer", "signatureHex"})
NEGATIVE_KEYS = frozenset(
    {"name", "reason", "acceptedUnderZip215", "messageUtf8", "publicKeyHex", "signatureHex"}
)

CONTEXT_LITERAL = re.compile(r"[a-z0-9][a-z0-9._:-]{0,79}", re.ASCII)
HEX_PATTERN = re.compile(r"[0-9a-f]+", re.ASCII)
ISO_MILLISECONDS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", re.ASCII)
KEY_PRINCIPAL = re.compile(r"key:S_[0-9a-f]{64}", re.ASCII)
RECOVERY_PRINCIPAL = re.compile(r"recovery-key:[0-9a-f]{64}", re.ASCII)
EMAIL_PATTERN = re.compile(
    r"[^\s@<>\"',;:\\\x00-\x1f\x7f-\x9f]{1,64}@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+"
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


def read_strict_json(path: Path, location: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read strict JSON {location}: {error}")


def require_exact_keys(value: Any, expected: frozenset[str], location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{location} must be an object")
    actual = frozenset(value)
    if actual != expected:
        fail(
            f"{location} has an invalid shape "
            f"(missing={sorted(expected - actual)!r}, unexpected={sorted(actual - expected)!r})"
        )
    return value


def require_string(value: Any, location: str) -> str:
    if not isinstance(value, str):
        fail(f"{location} must be a string")
    return value


def require_hex(value: Any, byte_length: int, location: str) -> bytes:
    text = require_string(value, location)
    if len(text) != byte_length * 2 or HEX_PATTERN.fullmatch(text) is None:
        fail(f"{location} must be exactly {byte_length} lowercase-hex bytes")
    return bytes.fromhex(text)


# --- Reference checks of the primitives this script implements itself ------


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_sha256_one_block(prk: bytes, info: bytes) -> bytes:
    """RFC 5869 HKDF-Expand for L = 32: T(1) = HMAC(PRK, info || 0x01)."""
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def check_references() -> None:
    # RFC 5869 appendix A.1, the first 32 bytes of the output.
    prk = hkdf_extract_sha256(bytes(range(13)), b"\x0b" * 22)
    if prk.hex() != "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5":
        fail("HKDF-Extract does not reproduce RFC 5869 test case 1")
    if hkdf_expand_sha256_one_block(prk, bytes(range(0xF0, 0xFA))).hex() != (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    ):
        fail("HKDF-Expand does not reproduce RFC 5869 test case 1")
    # RFC 8032 section 7.1, TEST 1 (empty message), through `cryptography`.
    key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    )
    if raw_public_key(key).hex() != (
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ):
        fail("Ed25519 key derivation does not reproduce RFC 8032 TEST 1")
    if key.sign(b"").hex() != (
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ):
        fail("Ed25519 signing does not reproduce RFC 8032 TEST 1")
    # This script's own curve arithmetic: the base point has order L, and every
    # listed small-order encoding is a distinct point whose 8-multiple is the
    # identity, while the base point is not of small order.
    base = decode_point_lax(BASE_ENCODING)
    if base is None or scalar_multiply(L, base) != IDENTITY:
        fail("pure-Python Ed25519 arithmetic does not give the base point order L")
    points = set()
    for encoding in SMALL_ORDER_ENCODINGS:
        point = decode_point_lax(encoding)
        if point is None or not canonical_encoding(encoding):
            fail(f"small-order encoding {encoding.hex()} does not decode canonically")
        if scalar_multiply(8, point) != IDENTITY:
            fail(f"small-order encoding {encoding.hex()} is not of small order")
        points.add(affine(point))
    if len(points) != 8 or scalar_multiply(8, base) == IDENTITY:
        fail("the small-order list is not eight distinct small-order points")


# --- Ed25519 in pure Python: decoding rules and a ZIP-215 verifier ----------

IDENTITY = (0, 1, 1, 0)
BASE_ENCODING = (4 * pow(5, P - 2, P) % P).to_bytes(32, "little")


def point_add(a: tuple[int, int, int, int], b: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Extended twisted Edwards addition (RFC 8032 section 5.1.4)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def scalar_multiply(scalar: int, point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        scalar >>= 1
    return affine_extended(result)


def affine(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    inverse = pow(z, P - 2, P)
    return (x * inverse % P, y * inverse % P)


def affine_extended(point: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    x, y = affine(point)
    return (x, y, 1, x * y % P)


def decode_point_lax(encoding: bytes) -> tuple[int, int, int, int] | None:
    """ZIP-215 decoding: y may be any 255-bit value (reduced mod p), x = 0 with
    the sign bit set is allowed. Returns None for a y with no curve point."""
    if len(encoding) != 32:
        return None
    value = int.from_bytes(encoding, "little")
    sign = value >> 255
    y = (value & ((1 << 255) - 1)) % P
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow(u * pow(v, 7, P), (P - 5) // 8, P)) % P
    if (v * x * x - u) % P != 0:
        x = x * SQRT_M1 % P
        if (v * x * x - u) % P != 0:
            return None
    if (x & 1) != sign:
        x = (P - x) % P
    return (x, y, 1, x * y % P)


def canonical_encoding(encoding: bytes) -> bool:
    """RFC 8032 section 5.1.3: y < p, and not x = 0 with the sign bit set."""
    value = int.from_bytes(encoding, "little")
    y = value & ((1 << 255) - 1)
    if y >= P:
        return False
    point = decode_point_lax(encoding)
    if point is None:
        return False
    return not (point[0] == 0 and value >> 255 == 1)


def zip215_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """ZIP-215: S < L, lax decoding of A and R, the cofactored equation
    [8][S]B = [8]R + [8][k]A with k = SHA-512(R || A || M) over the given bytes."""
    if len(signature) != 64:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    a = decode_point_lax(public_key)
    r = decode_point_lax(signature[:32])
    base = decode_point_lax(BASE_ENCODING)
    if a is None or r is None or base is None:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    left = scalar_multiply(8, scalar_multiply(s, base))
    right = scalar_multiply(8, point_add(r, scalar_multiply(k, a)))
    return affine(left) == affine(right)


def strict_failures(public_key: bytes, signature: bytes) -> set[str]:
    """Which of the RFC 8032 checks a (public key, signature) pair fails."""
    failures = set()
    if int.from_bytes(signature[32:], "little") >= L:
        failures.add("s-not-below-l")
    if not canonical_encoding(public_key):
        failures.add("non-canonical-public-key")
    elif public_key in SMALL_ORDER_ENCODINGS:
        failures.add("small-order-public-key")
    if not canonical_encoding(signature[:32]):
        failures.add("non-canonical-r")
    return failures


def strict_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """The explicit checks first, then `cryptography`'s Ed25519 verification."""
    if len(public_key) != 32 or len(signature) != 64 or strict_failures(public_key, signature):
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


# --- The sign-in profile, for the two sign-in keys ---------------------------


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def normalize_username(username: str) -> str:
    normalized = username.strip("\t\n\f\r ")
    normalized = "".join(
        chr(ord(character) + 32) if "A" <= character <= "Z" else character
        for character in normalized
    )
    if not 3 <= len(normalized) <= 120 or any(
        ord(character) < 0x21 or ord(character) > 0x7E for character in normalized
    ):
        fail("normalized username must be 3-120 printable ASCII characters")
    return normalized


def derive_sign_in_key(credentials: dict[str, str], password: str) -> tuple[bytes, bytes]:
    """The sign-in profile's transcript, scrypt and HKDF step: (masterSeed, seed)."""
    if len(password) < 10 or len(password.encode("utf-8")) > 1_024:
        fail("fixture password must be 10 characters to 1,024 UTF-8 bytes")
    password_hash = hashlib.sha512(SIGN_IN_PASSWORD_HASH_DOMAIN + password.encode("utf-8")).digest()
    transcript = "\n".join(
        (
            SIGN_IN_ENTROPY_DOMAIN,
            credentials["applicationId"],
            credentials["networkId"],
            credentials["normalizedUsername"],
            password_hash.hex(),
        )
    ).encode("utf-8")
    entropy = hashlib.sha512(transcript).digest()
    master_seed = hashlib.scrypt(
        entropy,
        salt=bytes.fromhex(credentials["saltHex"]),
        n=65_536,
        r=8,
        p=1,
        dklen=32,
        maxmem=128 * 1_024 * 1_024,
    )
    prk = hkdf_extract_sha256(SIGN_IN_KEY_DOMAIN, master_seed)
    return master_seed, hkdf_expand_sha256_one_block(prk, SIGN_IN_KEY_DOMAIN)


# --- The fixture -------------------------------------------------------------


def check_principal(value: str, form: str, location: str) -> None:
    if form == "key" and KEY_PRINCIPAL.fullmatch(value) is None:
        fail(f"{location} must be key:S_<64 hex>")
    if form == "recovery-key" and RECOVERY_PRINCIPAL.fullmatch(value) is None:
        fail(f"{location} must be recovery-key:<64 hex>")
    if form == "none" and value != "none":
        fail(f"{location} must be none")
    if form == "email":
        address = value[len("email:") :] if value.startswith("email:") else ""
        if EMAIL_PATTERN.fullmatch(address) is None or address != address.strip().lower():
            fail(f"{location} must be email:<normalized address>")


def build_message(context: dict[str, str], action: str, authorizer: str, subject: str) -> str:
    fields = (
        ACCOUNT_CHANGE_DOMAIN,
        context["serviceProfileId"],
        context["applicationId"],
        context["networkId"],
        action,
        context["usernameNormalized"],
        context["nonceHex"],
        context["expiresAt"],
        authorizer,
        subject,
    )
    for field in fields:
        if any(character in field for character in "\n\r\x0b\x0c\x85\u2028\u2029"):
            fail("an account-change field contains a line break")
    return "\n".join(fields)


def verify() -> str:
    check_references()
    fixture = require_exact_keys(read_strict_json(FIXTURE_PATH, "fixture"), EXPECTED_KEYS, "fixture")
    sign_in = read_strict_json(SIGN_IN_FIXTURE_PATH, "sign-in fixture")
    if fixture["warning"] != WARNING:
        fail("fixture.warning does not contain the required test-only warning")
    if fixture["format"] != ACCOUNT_CHANGE_DOMAIN:
        fail(f"fixture.format must be {ACCOUNT_CHANGE_DOMAIN!r}")

    credentials = {
        key: require_string(value, f"signInCredentials.{key}")
        for key, value in require_exact_keys(
            fixture["signInCredentials"], CREDENTIAL_KEYS, "signInCredentials"
        ).items()
    }
    if credentials["profile"] != SIGN_IN_PROFILE:
        fail(f"signInCredentials.profile must be {SIGN_IN_PROFILE!r}")
    for key in CREDENTIAL_KEYS:
        if credentials[key] != sign_in.get(key):
            fail(f"signInCredentials.{key} differs from the sign-in vector")
    if normalize_username(credentials["username"]) != credentials["normalizedUsername"]:
        fail("independent username normalization does not match normalizedUsername")
    require_hex(credentials["saltHex"], 32, "signInCredentials.saltHex")

    context = {
        key: require_string(value, f"context.{key}")
        for key, value in require_exact_keys(fixture["context"], CONTEXT_KEYS, "context").items()
    }
    for key in ("serviceProfileId", "applicationId", "networkId"):
        if CONTEXT_LITERAL.fullmatch(context[key]) is None:
            fail(f"context.{key} is not a valid identifier literal")
    if (context["applicationId"], context["networkId"], context["usernameNormalized"]) != (
        credentials["applicationId"],
        credentials["networkId"],
        credentials["normalizedUsername"],
    ):
        fail("context must name the same application, network and username as the credentials")
    require_hex(context["nonceHex"], 32, "context.nonceHex")
    if ISO_MILLISECONDS.fullmatch(context["expiresAt"]) is None:
        fail("context.expiresAt must be ISO-8601 UTC with milliseconds")

    keys = require_exact_keys(fixture["keys"], frozenset({"current", "next", "recovery"}), "keys")
    seeds: dict[str, bytes] = {}
    publics: dict[str, bytes] = {}
    principals: dict[str, str] = {}
    for name in ("current", "next"):
        entry = require_exact_keys(keys[name], DERIVED_KEY_KEYS, f"keys.{name}")
        master_seed, seed = derive_sign_in_key(credentials, require_string(entry["passwordUtf8"], f"keys.{name}.passwordUtf8"))
        if master_seed != require_hex(entry["masterSeedHex"], 32, f"keys.{name}.masterSeedHex"):
            fail(f"independent scrypt output does not match keys.{name}.masterSeedHex")
        if seed != require_hex(entry["seedHex"], 32, f"keys.{name}.seedHex"):
            fail(f"independent HKDF sign-in key step does not match keys.{name}.seedHex")
        seeds[name] = seed
    recovery_entry = require_exact_keys(keys["recovery"], RECOVERY_KEY_KEYS, "keys.recovery")
    recovery_seed = hashlib.sha256(
        require_string(recovery_entry["seedLabel"], "keys.recovery.seedLabel").encode("utf-8")
    ).digest()
    if recovery_seed != require_hex(recovery_entry["seedHex"], 32, "keys.recovery.seedHex"):
        fail("keys.recovery.seedHex is not SHA-256 of its seedLabel")
    seeds["recovery"] = recovery_seed
    for name in ("current", "next", "recovery"):
        entry = keys[name]
        public_key = raw_public_key(Ed25519PrivateKey.from_private_bytes(seeds[name]))
        if public_key != require_hex(entry["publicKeyHex"], 32, f"keys.{name}.publicKeyHex"):
            fail(f"independent Ed25519 key does not match keys.{name}.publicKeyHex")
        if not canonical_encoding(public_key) or public_key in SMALL_ORDER_ENCODINGS:
            fail(f"keys.{name} is not a strict Ed25519 public key")
        expected = (
            f"recovery-key:{public_key.hex()}" if name == "recovery" else f"key:S_{public_key.hex()}"
        )
        if entry["principal"] != expected:
            fail(f"keys.{name}.principal must be {expected!r}")
        publics[name] = public_key
        principals[name] = expected
    if publics["current"].hex() != sign_in["signInKey"]["publicKeyHex"]:
        fail("keys.current is not the committed sign-in vector's key")
    if len(set(publics.values())) != 3:
        fail("the three fixture keys are not distinct")

    cases = fixture["cases"]
    if not isinstance(cases, list):
        fail("fixture.cases must be an array")
    seen_actions: list[str] = []
    messages: set[str] = set()
    for index, raw in enumerate(cases):
        location = f"cases[{index}]"
        action = raw.get("action") if isinstance(raw, dict) else None
        if action not in ACTION_RULES:
            fail(f"{location}.action is not an action of this release")
        case = require_exact_keys(raw, EMAIL_CASE_KEYS if action == "email-change" else CASE_KEYS, location)
        authorizer_form, subject_form, signing_roles = ACTION_RULES[action]
        authorizer = require_string(case["authorizer"], f"{location}.authorizer")
        subject = require_string(case["subject"], f"{location}.subject")
        check_principal(authorizer, authorizer_form, f"{location}.authorizer")
        check_principal(subject, subject_form, f"{location}.subject")
        authorizer_key, subject_key = ACTION_KEYS[action]
        if authorizer != principals[authorizer_key]:
            fail(f"{location}.authorizer must name keys.{authorizer_key}")
        if subject_key is not None and subject != principals[subject_key]:
            fail(f"{location}.subject must name keys.{subject_key}")
        if action == "email-change":
            email_input = require_string(case["emailInput"], f"{location}.emailInput")
            if subject != "email:" + email_input.strip().lower():
                fail(f"{location}.subject is not email: + the normalized emailInput")
        message = build_message(context, action, authorizer, subject)
        if message != require_string(case["messageUtf8"], f"{location}.messageUtf8"):
            fail(f"independent message construction does not match {location}.messageUtf8")
        message_bytes = message.encode("utf-8")
        if len(message.split("\n")) != 10 or message.endswith("\n"):
            fail(f"{location}.messageUtf8 is not ten lines without a trailing newline")
        signatures = case["signatures"]
        if not isinstance(signatures, list):
            fail(f"{location}.signatures must be an array")
        roles = []
        for signature_index, raw_signature in enumerate(signatures):
            signature_location = f"{location}.signatures[{signature_index}]"
            entry = require_exact_keys(raw_signature, SIGNATURE_KEYS, signature_location)
            role = entry["role"]
            signer = entry["signer"]
            expected_signer = authorizer_key if role == "authorizer" else subject_key
            if signer != expected_signer:
                fail(f"{signature_location}.signer must be the {role}'s key")
            signature = require_hex(entry["signatureHex"], 64, f"{signature_location}.signatureHex")
            if Ed25519PrivateKey.from_private_bytes(seeds[signer]).sign(message_bytes) != signature:
                fail(f"independent Ed25519 signature does not match {signature_location}.signatureHex")
            if not strict_verify(publics[signer], message_bytes, signature):
                fail(f"{signature_location} does not verify strictly")
            if not zip215_verify(publics[signer], message_bytes, signature):
                fail(f"{signature_location} does not verify under ZIP-215 either")
            roles.append(role)
        if tuple(roles) != signing_roles:
            fail(f"{location} must carry exactly the signatures {signing_roles!r}")
        seen_actions.append(action)
        messages.add(message)
    if sorted(seen_actions) != sorted(ACTION_RULES):
        fail("fixture.cases must cover each action of this release exactly once")

    negatives = fixture["negativeCases"]
    if not isinstance(negatives, list):
        fail("fixture.negativeCases must be an array")
    reasons: list[str] = []
    for index, raw in enumerate(negatives):
        location = f"negativeCases[{index}]"
        case = require_exact_keys(raw, NEGATIVE_KEYS, location)
        require_string(case["name"], f"{location}.name")
        reason = case["reason"]
        if reason not in NEGATIVE_REASONS:
            fail(f"{location}.reason is not one of {NEGATIVE_REASONS!r}")
        message = require_string(case["messageUtf8"], f"{location}.messageUtf8")
        if message not in messages:
            fail(f"{location}.messageUtf8 is not one of the positive cases' messages")
        public_key = require_hex(case["publicKeyHex"], 32, f"{location}.publicKeyHex")
        signature = require_hex(case["signatureHex"], 64, f"{location}.signatureHex")
        failures = strict_failures(public_key, signature)
        if failures != {reason}:
            fail(f"{location} fails the checks {sorted(failures)!r}, not exactly {reason!r}")
        if strict_verify(public_key, message.encode("utf-8"), signature):
            fail(f"{location} verifies strictly; it must not")
        accepted = case["acceptedUnderZip215"]
        if not isinstance(accepted, bool):
            fail(f"{location}.acceptedUnderZip215 must be a boolean")
        if zip215_verify(public_key, message.encode("utf-8"), signature) != accepted:
            fail(f"{location}.acceptedUnderZip215 does not match ZIP-215 verification")
        reasons.append(reason)
    if sorted(reasons) != sorted(NEGATIVE_REASONS):
        fail("fixture.negativeCases must cover each strict check exactly once")
    return (
        f"{len(cases)} account-change messages and their signatures, and "
        f"{len(negatives)} strictly refused signatures"
    )


def main() -> int:
    try:
        summary = verify()
    except VerificationError as error:
        print(f"Account-change vector verification failed: {error}", file=sys.stderr)
        return 1
    except (MemoryError, ValueError) as error:
        print(f"Account-change vector verification failed closed: {error}", file=sys.stderr)
        return 1
    print(
        "Independent Python verification passed for the account-change vector: "
        f"{summary}; the sign-in keys re-derived from their credentials (scrypt and "
        "HKDF), the messages rebuilt field by field, every signature reproduced, the "
        "RFC 8032 strict checks applied before cryptography's verification, and "
        "ZIP-215 acceptance checked with pure-Python curve arithmetic."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
