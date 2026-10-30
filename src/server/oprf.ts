import { ristretto255_oprf } from "@noble/curves/ed25519.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes } from "@noble/hashes/utils.js";
import { utf8 } from "../encoding.js";
import { DerivationError } from "../errors.js";
import { OPRF_ELEMENT_BYTES } from "../oprf.js";
import { normalizeUsername } from "../normalization.js";

/**
 * The service half of the server-keyed salt (src/oprf.ts).
 *
 * One 32-byte master key yields a per-account OPRF key, so the service keeps no
 * per-account table (the account does not need to exist, and an unknown
 * username answers exactly like a known one). The master key is a secret of the
 * host, kept outside the database it protects: whoever holds it and a database
 * dump can guess passwords offline, so it belongs in a secrets manager or KMS
 * with its own access, and a backup of it is part of the namespace's backup. A
 * lost master key makes every salt, and so every key and wallet derived under
 * it, unreachable.
 *
 * The master key is the one thing this module will not default, derive or
 * generate: it comes from the host.
 */

/** HMAC data prefix of the per-account key seed. Fixed wire surface. */
export const OPRF_USER_KEY_DOMAIN = "web2-ish-self-custody oprf user key v1";
/** The RFC 9497 `info` of the per-account key derivation. Fixed wire surface. */
export const OPRF_KEY_INFO = "web2-ish-self-custody oprf key info v1";
/** The least a master key may be. */
export const OPRF_MASTER_KEY_BYTES = 32;

export type OprfServerConfig = Readonly<{
  /** At least 32 random bytes the host keeps secret. */
  masterKey: Uint8Array;
  /** Namespaces the per-account keys, normally the identity service profile id. */
  serviceProfileId: string;
}>;

export type OprfServer = Readonly<{
  /**
   * Evaluates a client's blinded element under the account's key and returns
   * the 32-byte answer. Throws `DerivationError` `invalid-username` for a
   * username the SDK refuses and `invalid-salt` for a malformed element; both
   * depend only on the request, never on whether the account exists.
   */
  evaluate(username: string, blinded: Uint8Array): Uint8Array;
}>;

function assertMasterKey(masterKey: Uint8Array): void {
  if (!(masterKey instanceof Uint8Array) || masterKey.byteLength < OPRF_MASTER_KEY_BYTES) {
    throw new DerivationError(
      "The OPRF master key must be at least 32 bytes.",
      "invalid-salt",
    );
  }
  let allSame = true;
  for (let index = 1; index < masterKey.byteLength; index += 1) {
    if (masterKey[index] !== masterKey[0]) {
      allSame = false;
      break;
    }
  }
  if (allSame) {
    throw new DerivationError("The OPRF master key is not random.", "invalid-salt");
  }
}

export function createOprfServer(config: OprfServerConfig): OprfServer {
  assertMasterKey(config.masterKey);
  if (typeof config.serviceProfileId !== "string" || config.serviceProfileId.length === 0) {
    throw new DerivationError("A service profile id is required.", "invalid-profile");
  }
  // The server keeps its own copy, so the host zeroing its array later is harmless.
  const masterKey = Uint8Array.from(config.masterKey);
  const serviceProfileId = config.serviceProfileId;
  const keyInfo = utf8(OPRF_KEY_INFO);

  return Object.freeze({
    evaluate(username: string, blinded: Uint8Array): Uint8Array {
      const normalizedUsername = normalizeUsername(username);
      if (!(blinded instanceof Uint8Array) || blinded.byteLength !== OPRF_ELEMENT_BYTES) {
        throw new DerivationError("The blinded element must be exactly 32 bytes.", "invalid-salt");
      }
      const seed = hmac(
        sha256,
        masterKey,
        concatBytes(
          utf8(OPRF_USER_KEY_DOMAIN),
          Uint8Array.of(0),
          utf8(serviceProfileId),
          Uint8Array.of(0),
          utf8(normalizedUsername),
        ),
      );
      let secretKey: Uint8Array | undefined;
      try {
        secretKey = ristretto255_oprf.oprf.deriveKeyPair(seed, keyInfo).secretKey;
        try {
          return ristretto255_oprf.oprf.blindEvaluate(secretKey, blinded);
        } catch {
          throw new DerivationError("The blinded element is not valid.", "invalid-salt");
        }
      } finally {
        seed.fill(0);
        secretKey?.fill(0);
      }
    },
  });
}
