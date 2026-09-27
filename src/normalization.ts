import { DerivationError } from "./errors.js";

const asciiIdentifier = /^[\x21-\x7e]{3,120}$/u;
const asciiWhitespace = /^[\t\n\f\r ]+|[\t\n\f\r ]+$/gu;

/**
 * Every profile in this package requires at least this many password
 * characters, counted as Unicode code points of the UTF-8 password bytes.
 *
 * Passwords are not normalized (see {@link assertWalletPassword}), so this is
 * the code-point count of exactly the bytes that are hashed. It is a floor, not
 * a strength check: a ten-character password can still be trivially guessable,
 * and the application that lets a user choose one owns the strength policy.
 */
export const MINIMUM_PASSWORD_CHARACTERS = 10;
/** The upper bound is on the encoded bytes, which is what the KDF consumes. */
export const MAXIMUM_PASSWORD_BYTES = 1_024;

/**
 * The username is a derivation input, so normalization has to be exactly
 * reproducible on every platform and in every locale.
 *
 * Trimming and case folding are deliberately ASCII-only: `String.toLowerCase`
 * is locale- and Unicode-sensitive (Turkish dotted I, for one), and a username
 * that folds differently on two devices derives two different wallets. The
 * printable-ASCII restriction is what makes that safe to promise.
 */
export function normalizeUsername(username: string): string {
  const normalized = username
    .replace(asciiWhitespace, "")
    .replace(/[A-Z]/gu, (letter) => letter.toLowerCase());

  if (!asciiIdentifier.test(normalized)) {
    throw new DerivationError(
      "The username must be 3–120 printable ASCII characters after ASCII trim and lowercase normalization.",
      "invalid-username",
    );
  }
  return normalized;
}

function isContinuation(byte: number | undefined): boolean {
  return byte !== undefined && byte >= 0x80 && byte <= 0xbf;
}

/**
 * Counts the Unicode code points in `bytes`, or returns -1 if the bytes are not
 * well-formed UTF-8 (Unicode §3.9, Table 3-7: no overlong forms, no surrogates,
 * nothing above U+10FFFF, no truncated sequence).
 *
 * Deliberately byte-level rather than `TextDecoder`: decoding would copy the
 * password into a JavaScript string, which can never be zeroed, and the whole
 * derivation path is built to keep password material in buffers it clears.
 */
function countUtf8CodePoints(bytes: Uint8Array): number {
  let count = 0;
  let index = 0;
  while (index < bytes.length) {
    const lead = bytes[index] as number;
    let length: number;
    let secondMin = 0x80;
    let secondMax = 0xbf;
    if (lead <= 0x7f) {
      length = 1;
    } else if (lead >= 0xc2 && lead <= 0xdf) {
      length = 2;
    } else if (lead >= 0xe0 && lead <= 0xef) {
      length = 3;
      if (lead === 0xe0) secondMin = 0xa0; // overlong
      if (lead === 0xed) secondMax = 0x9f; // UTF-16 surrogates
    } else if (lead >= 0xf0 && lead <= 0xf4) {
      length = 4;
      if (lead === 0xf0) secondMin = 0x90; // overlong
      if (lead === 0xf4) secondMax = 0x8f; // above U+10FFFF
    } else {
      return -1;
    }

    if (length > 1) {
      const second = bytes[index + 1];
      if (second === undefined || second < secondMin || second > secondMax) {
        return -1;
      }
      for (let offset = 2; offset < length; offset += 1) {
        if (!isContinuation(bytes[index + offset])) {
          return -1;
        }
      }
    }
    index += length;
    count += 1;
  }
  return count;
}

/**
 * The password is raw bytes and is hashed exactly as given: no trimming, case
 * folding, or Unicode normalization. It must be well-formed UTF-8 — the
 * encoding of what the user typed — so that "characters" has one meaning, and
 * it must be {@link MINIMUM_PASSWORD_CHARACTERS} code points to
 * {@link MAXIMUM_PASSWORD_BYTES} bytes long.
 */
export function assertWalletPassword(password: Uint8Array): void {
  if (!(password instanceof Uint8Array) || password.byteLength > MAXIMUM_PASSWORD_BYTES) {
    throw new DerivationError(
      `The password must be a Uint8Array of at most ${MAXIMUM_PASSWORD_BYTES} UTF-8 bytes.`,
      "invalid-password",
    );
  }
  const characters = countUtf8CodePoints(password);
  if (characters < 0) {
    throw new DerivationError(
      "The password must be well-formed UTF-8.",
      "invalid-password",
    );
  }
  if (characters < MINIMUM_PASSWORD_CHARACTERS) {
    throw new DerivationError(
      `The password must be at least ${MINIMUM_PASSWORD_CHARACTERS} characters long.`,
      "invalid-password",
    );
  }
}
