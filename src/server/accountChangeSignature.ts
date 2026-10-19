import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { utf8 } from "../encoding.js";
import { IdentityError } from "./errors.js";

/**
 * Strict Ed25519 for account changes (package-internal).
 *
 * Login keeps `verifyChallengeSignature`, which uses noble's default
 * `zip215: true`. That rule accepts a small-order public key with R = identity
 * and S = 0 over every message, which is harmless for consensus code but not
 * for a signature that authorizes rebinding an account. Every account-change
 * signature is therefore checked against RFC 8032's stricter rules, the same
 * ones `scripts/verify_account_change_vector.py` applies before it calls
 * `cryptography`:
 *
 * - S < L (no malleated scalar);
 * - A and R are canonical encodings (y < p, and no x = 0 with the sign bit set);
 * - A is not one of the eight points of small order.
 *
 * Then `ed25519.verify(…, { zip215: false })`, which applies the same rules
 * again inside noble.
 */

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;
const signatureHexPattern = /^[0-9a-f]{128}$/u;
/** The order of the Ed25519 base point. */
const GROUP_ORDER = ed25519.Point.Fn.ORDER;

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let index = bytes.length - 1; index >= 0; index -= 1) {
    value = (value << 8n) | BigInt(bytes[index] as number);
  }
  return value;
}

/** RFC 8032 decoding with `zip215: false`: canonical, on the curve. */
function decodesCanonically(bytes: Uint8Array): boolean {
  try {
    ed25519.Point.fromBytes(bytes, false);
    return true;
  } catch {
    return false;
  }
}

/**
 * True when `publicKey` is a 32-byte canonical encoding of a curve point that
 * is not of small order. Every key a deterministic derivation produces passes;
 * only a crafted key fails.
 */
export function isStrictEd25519PublicKey(publicKey: Uint8Array): boolean {
  if (!(publicKey instanceof Uint8Array) || publicKey.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    return false;
  }
  try {
    return !ed25519.Point.fromBytes(publicKey, false).isSmallOrder();
  } catch {
    return false;
  }
}

/**
 * The key check of registration, sign-in-key rotation, recovery-key
 * enrollment and recovery completion. It runs before any account lookup, so
 * `invalid-public-key` says nothing about any account.
 */
export function assertStrictEd25519PublicKey(publicKey: Uint8Array, field = "publicKey"): void {
  if (!isStrictEd25519PublicKey(publicKey)) {
    throw new IdentityError(
      `${field} must be a canonical Ed25519 public key that is not of small order.`,
      "invalid-public-key",
    );
  }
}

/**
 * Verifies one account-change signature strictly. `signature` is exactly 128
 * lowercase hex characters (no trimming, no uppercase); `message` is the
 * account-change message, as text (signed as its UTF-8 bytes) or as bytes.
 * Never throws: every malformed input is simply `false`.
 */
export function verifyAccountChangeSignature(
  signature: string,
  message: string | Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (typeof signature !== "string" || !signatureHexPattern.test(signature)) {
    return false;
  }
  if (!isStrictEd25519PublicKey(publicKey)) {
    return false;
  }
  const signatureBytes = hexToBytes(signature);
  if (signatureBytes.byteLength !== ED25519_SIGNATURE_BYTES) {
    return false;
  }
  const r = signatureBytes.subarray(0, 32);
  const s = littleEndianToBigInt(signatureBytes.subarray(32));
  if (s >= GROUP_ORDER || !decodesCanonically(r)) {
    return false;
  }
  const messageBytes = typeof message === "string" ? utf8(message) : message;
  if (!(messageBytes instanceof Uint8Array)) {
    return false;
  }
  try {
    return ed25519.verify(signatureBytes, messageBytes, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
