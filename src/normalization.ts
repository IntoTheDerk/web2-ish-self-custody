import { DerivationError } from "./errors.js";

const asciiIdentifier = /^[\x21-\x7e]{3,120}$/u;
const asciiWhitespace = /^[\t\n\f\r ]+|[\t\n\f\r ]+$/gu;

/** Every profile in this package requires at least this many password bytes. */
export const MINIMUM_PASSWORD_BYTES = 24;
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

export function assertWalletPassword(password: Uint8Array): void {
  if (
    !(password instanceof Uint8Array) ||
    password.byteLength < MINIMUM_PASSWORD_BYTES ||
    password.byteLength > MAXIMUM_PASSWORD_BYTES
  ) {
    throw new DerivationError(
      `The password must contain ${MINIMUM_PASSWORD_BYTES}–${MAXIMUM_PASSWORD_BYTES} UTF-8 bytes.`,
      "invalid-password",
    );
  }
}
