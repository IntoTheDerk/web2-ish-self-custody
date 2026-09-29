import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { utf8 } from "../encoding.js";

/**
 * Server-side secret generation and hashing.
 *
 * Nothing here touches wallet material. Session tokens and verification codes
 * are bearer secrets the service mints, hands out once, and thereafter only
 * recognizes by digest: the plaintext is never persisted, so a database
 * disclosure yields nothing replayable.
 */

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Omits O/0 and I/1 so a code read aloud or off a screen is unambiguous. */
const VERIFICATION_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const SESSION_TOKEN_BYTES = 32;
const NONCE_BYTES = 32;
const VERIFICATION_CODE_LENGTH = 8;

const VERIFICATION_CODE_DOMAIN =
  "web2-ish-self-custody email verification code v1";

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function base64url(bytes: Uint8Array): string {
  let encoded = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    encoded += BASE64URL_ALPHABET.charAt(first >> 2);
    encoded += BASE64URL_ALPHABET.charAt(((first & 0x03) << 4) | ((second ?? 0) >> 4));
    if (second === undefined) {
      break;
    }
    encoded += BASE64URL_ALPHABET.charAt(((second & 0x0f) << 2) | ((third ?? 0) >> 6));
    if (third === undefined) {
      break;
    }
    encoded += BASE64URL_ALPHABET.charAt(third & 0x3f);
  }
  return encoded;
}

function sha256Hex(value: string): string {
  return bytesToHex(sha256(utf8(value)));
}

/** 256 bits of CSPRNG output, URL-safe and padding-free. Returned once. */
export function generateSessionToken(): string {
  return base64url(randomBytes(SESSION_TOKEN_BYTES));
}

/**
 * The only form of a session token the service stores. Lowercase hex matches
 * the `token_hash ~ '^[0-9a-f]{64}$'` CHECK on the sessions table.
 */
export function hashSessionToken(token: string): string {
  return sha256Hex(token);
}

/**
 * Rejection sampling, not modulo folding: with a 32-symbol alphabet the two
 * happen to agree, but the rejection bound keeps the code uniform if the
 * alphabet ever changes to a length that does not divide 256.
 */
export function generateVerificationCode(): string {
  const alphabetLength = VERIFICATION_ALPHABET.length;
  const ceiling = 256 - (256 % alphabetLength);
  let code = "";
  while (code.length < VERIFICATION_CODE_LENGTH) {
    for (const byte of randomBytes(VERIFICATION_CODE_LENGTH)) {
      if (byte >= ceiling) {
        continue;
      }
      code += VERIFICATION_ALPHABET.charAt(byte % alphabetLength);
      if (code.length === VERIFICATION_CODE_LENGTH) {
        break;
      }
    }
  }
  return code;
}

/**
 * Binds the code to the verification row it was minted for. Without the id in
 * the digest, a code issued for one verification would validate against any
 * other verification that happened to draw the same code.
 *
 * Callers must pass a code already reduced to the verification alphabet, which
 * keeps the newline-joined preimage unambiguous.
 */
export function hashVerificationCode(
  serviceProfileId: string,
  verificationId: string,
  code: string,
): string {
  return sha256Hex(
    [VERIFICATION_CODE_DOMAIN, serviceProfileId, verificationId, code].join("\n"),
  );
}

/**
 * Compares two hex digests without leaking, through timing, how many leading
 * characters matched. Differing lengths short-circuit: the length of a digest
 * is not secret, its contents are.
 */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < a.length; index += 1) {
    difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return difference === 0;
}

/** 32 CSPRNG bytes as lowercase hex, sized for the challenge nonce column. */
export function randomNonceHex(): string {
  return bytesToHex(randomBytes(NONCE_BYTES));
}
