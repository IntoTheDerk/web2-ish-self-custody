import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { utf8 } from "./encoding.js";
import { DerivationError } from "./errors.js";
import { assertWalletPassword, normalizeUsername } from "./normalization.js";

/**
 * The server-keyed salt: an oblivious pseudorandom function (RFC 9497, base
 * mode, ristretto255-SHA512) between the client and the identity service whose
 * output is mixed into the 32-byte external salt of an `external-32` profile
 * (docs/PROTOCOL.md#part-5--the-server-keyed-salt).
 *
 * Without it, anyone who knows a username, the public salt and a published
 * address or sign-in public key can test password guesses offline at one KDF
 * run each. With it, each guess needs the service's per-account OPRF key, so it
 * costs a rate-limited request to the service, and a leaked database or
 * address alone is no longer an oracle. The service never sees the password or
 * the OPRF output (it sees a blinded group element), and it cannot compute the
 * salt without the password, so it still cannot compute a key
 * (docs/SECURITY_MODEL.md#server-keyed-salt).
 *
 * The salt only changes the `salt` the profile is given. No profile, id or
 * transcript changes: the same credentials under the same profile derive a
 * different key when the salt is different, which is what makes this an opt-in
 * layer rather than a new profile.
 */

/** Prefixed to the username and password to form the OPRF input. Fixed wire surface. */
export const OPRF_INPUT_DOMAIN = "web2-ish-self-custody oprf input v1\n";
/** The HMAC data prefix of the salt step. Fixed wire surface. */
export const OPRF_SALT_DOMAIN = "web2-ish-self-custody oprf salt v1";
/** The length of a blinded or evaluated ristretto255 element. */
export const OPRF_ELEMENT_BYTES = 32;

const EXTERNAL_SALT_BYTES = 32;

type Rng = (bytes?: number) => Uint8Array;

export type OprfSaltRequest = Readonly<{
  /** The 32-byte blinded element to send to the service. It reveals nothing about the password. */
  blinded: Uint8Array;
  /**
   * Completes the exchange with the service's 32-byte answer and returns the
   * salt to pass to the profile as `salt`: HMAC-SHA256 keyed by the OPRF
   * output, over the domain and the service's public salt. Works once; the
   * input, the blind and the OPRF output are zeroed before it returns.
   */
  finish(evaluated: Uint8Array, publicSalt: Uint8Array): Uint8Array;
  /** Zeroes everything held, for a request that is abandoned. Safe to call after `finish`. */
  discard(): void;
}>;

function assertElement(value: unknown, what: string): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== OPRF_ELEMENT_BYTES) {
    throw new DerivationError(`The ${what} must be exactly 32 bytes.`, "invalid-salt");
  }
}

/**
 * The OPRF input: the domain, the normalized username and the raw password
 * bytes, joined by newlines. The username is also bound by the service's
 * per-account key, so this is only defence in depth.
 */
function oprfInput(normalizedUsername: string, password: Uint8Array): Uint8Array {
  return concatBytes(utf8(`${OPRF_INPUT_DOMAIN}${normalizedUsername}\n`), password);
}

/**
 * Blinds the password for the service. `rng` exists for known-answer vectors
 * only; production calls leave it out and get the platform's CSPRNG.
 */
export function startOprfSalt(
  username: string,
  password: Uint8Array,
  rng?: Rng,
): OprfSaltRequest {
  if (!(password instanceof Uint8Array)) {
    throw new DerivationError("Password input must be a Uint8Array.", "invalid-password");
  }
  assertWalletPassword(password);
  const normalizedUsername = normalizeUsername(username);
  const input = oprfInput(normalizedUsername, password);
  const { blind, blinded } = ristretto255_oprf.oprf.blind(input, rng);
  let open = true;

  const discard = (): void => {
    open = false;
    input.fill(0);
    blind.fill(0);
  };

  return Object.freeze({
    blinded,
    finish(evaluated: Uint8Array, publicSalt: Uint8Array): Uint8Array {
      if (!open) {
        throw new DerivationError("This OPRF request was already finished.", "invalid-salt");
      }
      assertElement(evaluated, "OPRF answer");
      if (
        !(publicSalt instanceof Uint8Array) ||
        publicSalt.byteLength !== EXTERNAL_SALT_BYTES
      ) {
        throw new DerivationError(
          "The public derivation salt must be exactly 32 bytes.",
          "invalid-salt",
        );
      }
      let output: Uint8Array | undefined;
      try {
        try {
          output = ristretto255_oprf.oprf.finalize(input, blind, evaluated);
        } catch {
          throw new DerivationError("The OPRF answer is not valid.", "invalid-salt");
        }
        return hmac(sha256, output, concatBytes(utf8(OPRF_SALT_DOMAIN), Uint8Array.of(0), publicSalt));
      } finally {
        output?.fill(0);
        discard();
      }
    },
    discard,
  });
}
