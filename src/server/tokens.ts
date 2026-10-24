import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { utf8 } from "../encoding.js";

/**
 * Server-side secret generation and hashing.
 *
 * Nothing here touches wallet material. Session tokens, recovery tokens and
 * codes are bearer secrets the service mints, hands out once, and thereafter
 * only recognizes by digest: the plaintext is never persisted. The digests
 * are unkeyed SHA-256, so what a database disclosure yields depends on the
 * secret's size. A 256-bit token's digest yields nothing replayable. A
 * reset code replaces the enrolled key, so it is 80 bits, beyond an offline
 * search of its digest within its 15-minute life. An email verification
 * code is 40 bits: its digest can be searched offline, but it proves only
 * that an address received mail and replaces no key, and its attempt bound
 * is what holds online.
 */

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Omits O/0 and I/1 so a code read aloud or off a screen is unambiguous. */
const VERIFICATION_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const SESSION_TOKEN_BYTES = 32;
const NONCE_BYTES = 32;
const VERIFICATION_CODE_LENGTH = 8;
/** 16 symbols of 5 bits: 80 bits, typed in four groups of four. */
const ACCOUNT_RESET_CODE_LENGTH = 16;

const VERIFICATION_CODE_DOMAIN =
  "web2-ish-self-custody email verification code v1";
const ACCOUNT_RESET_CODE_DOMAIN = "web2-ish-self-custody account reset code v1";

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
function generateCode(length: number): string {
  const alphabetLength = VERIFICATION_ALPHABET.length;
  const ceiling = 256 - (256 % alphabetLength);
  let code = "";
  while (code.length < length) {
    for (const byte of randomBytes(length)) {
      if (byte >= ceiling) {
        continue;
      }
      code += VERIFICATION_ALPHABET.charAt(byte % alphabetLength);
      if (code.length === length) {
        break;
      }
    }
  }
  return code;
}

/** An email verification code: 8 symbols (40 bits). */
export function generateVerificationCode(): string {
  return generateCode(VERIFICATION_CODE_LENGTH);
}

/**
 * An account reset code: 16 symbols (80 bits) of the same alphabet. It
 * replaces the enrolled key with no password, so its digest must not be
 * searchable offline: 2^80 SHA-256 evaluations are far beyond any attacker
 * within the code's 15 minutes, where 2^40 take about a minute on one GPU. A
 * slow hash is not the answer, because a completion hashes the submitted code
 * before any account-specific check, so an unauthenticated caller could spend
 * the server's CPU with it.
 */
export function generateAccountResetCode(): string {
  return generateCode(ACCOUNT_RESET_CODE_LENGTH);
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
 * The stored form of an account-reset code: bound to its reset row, as a
 * verification code is to its verification, under its own domain so that a
 * digest of one kind never matches a row of the other.
 *
 * Callers must pass a code already reduced to the verification alphabet.
 */
export function hashAccountResetCode(
  serviceProfileId: string,
  resetId: string,
  code: string,
): string {
  return sha256Hex([ACCOUNT_RESET_CODE_DOMAIN, serviceProfileId, resetId, code].join("\n"));
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

const SECOND_FACTOR_TICKET_DOMAIN = "web2-ish-self-custody second-factor ticket v1";

/** A second-factor ticket: 32 random bytes, base64url, like a session token. */
export function generateSecondFactorTicket(): string {
  return base64url(randomBytes(SESSION_TOKEN_BYTES));
}

/**
 * Its stored digest. Domain separated, so neither table's digests can stand
 * in for the other's: a ticket's digest is never a session token's.
 */
export function hashSecondFactorTicket(serviceProfileId: string, ticket: string): string {
  return sha256Hex([SECOND_FACTOR_TICKET_DOMAIN, serviceProfileId, ticket].join("\n"));
}
