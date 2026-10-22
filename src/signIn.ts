import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { defineIdentityCodec, type IdentityCodec } from "./codec.js";
import { utf8 } from "./encoding.js";
import { DerivationError } from "./errors.js";
import {
  defineDerivationProfile,
  type DerivationProfile,
  type KeyDerivation,
} from "./profile.js";

/**
 * The sign-in profile: a password-derived Ed25519 key that signs in to an
 * identity service and is not a key on any chain.
 *
 * It exists so that an application can keep its users' sign-in key and their
 * wallet apart while still running one password stretch per entry. The service
 * enrolls the sign-in key (`S_` + hex, which no chain parser accepts), and the
 * application derives its wallet from an application secret of the same run
 * (docs/PROTOCOL.md#part-3--the-sign-in-profile). Nothing here knows about any chain, and
 * this module imports no chain SDK.
 */

/**
 * The HKDF-SHA256 salt and `info` of the sign-in key step. Fixed wire surface:
 * a change is a new key-derivation id and a new profile id, never an edit.
 */
export const SIGN_IN_KEY_DOMAIN = "web2-ish-self-custody sign-in key v1";

const SIGN_IN_SEED_BYTES = 32;
const ED25519_PUBLIC_KEY_BYTES = 32;
/** HKDF-Expand's block counter for T(1), the only block when L = HashLen. */
const HKDF_FIRST_BLOCK = Uint8Array.of(0x01);
const SIGN_IN_PUBLIC_KEY_PREFIX = "S_";
/** Exactly the encoder's output: no trimming, no uppercase, no other length. */
const signInPublicKeyIdentifier = /^S_[0-9a-f]{64}$/u;

/**
 * The sign-in key step: HKDF-SHA256 of the scrypt output with
 * `SIGN_IN_KEY_DOMAIN` as both the salt and the `info`, L = 32.
 *
 * ```
 * PRK    = HMAC-SHA256(key = utf8(SIGN_IN_KEY_DOMAIN), data = masterSeed)   HKDF-Extract
 * seed_s = HMAC-SHA256(key = PRK, data = utf8(SIGN_IN_KEY_DOMAIN) ‖ 0x01)   HKDF-Expand, T(1)
 * ```
 *
 * It is one-way, so the profile can be used with application secrets: the
 * secrets come from a PRK extracted under a different domain
 * (docs/PROTOCOL.md#application-secrets), and the sign-in key reveals neither
 * that PRK nor `masterSeed`. Both HMACs are computed with `hmac` directly, as
 * the application-secret expansion is, because noble's `expand` copies its
 * output out of an internal buffer that it never clears. The PRK is zeroed
 * before this returns, and the result is HMAC's own output, which the core
 * zeroes.
 */
export const signInHkdfEd25519: KeyDerivation = Object.freeze({
  id: "hkdf-sha256-sign-in-key-v1",
  deriveKey(masterSeed: Uint8Array): Uint8Array {
    if (!(masterSeed instanceof Uint8Array) || masterSeed.byteLength !== SIGN_IN_SEED_BYTES) {
      throw new DerivationError(
        "The sign-in key step takes the exact 32-byte scrypt output.",
        "invalid-seed",
      );
    }
    const domain = utf8(SIGN_IN_KEY_DOMAIN);
    const prk = hmac(sha256, domain, masterSeed);
    try {
      return hmac(sha256, prk, concatBytes(domain, HKDF_FIRST_BLOCK));
    } finally {
      prk.fill(0);
    }
  },
});

function assertPublicKeyBytes(publicKeyBytes: Uint8Array): Uint8Array {
  if (
    !(publicKeyBytes instanceof Uint8Array) ||
    publicKeyBytes.byteLength !== ED25519_PUBLIC_KEY_BYTES
  ) {
    throw new DerivationError(
      "Sign-in public keys must be 32 bytes.",
      "invalid-public-key",
    );
  }
  return publicKeyBytes;
}

function encodeSignInPublicKey(publicKeyBytes: Uint8Array): string {
  return `${SIGN_IN_PUBLIC_KEY_PREFIX}${bytesToHex(assertPublicKeyBytes(publicKeyBytes))}`;
}

/**
 * The sign-in key's identifier, `S_` followed by the public key as 64
 * lowercase hex digits. It is both the address and the public-key identifier.
 *
 * The `_` is outside the base58 alphabet and the tag is not Kalvora's `A_`, so
 * no Kalvora parser accepts it, and the Kalvora codec's strict decoder refuses
 * it. Decoding accepts exactly what encoding produces: no surrounding
 * whitespace, no uppercase, no other length; anything else is
 * `invalid-public-key`.
 */
export const signInEd25519Codec: IdentityCodec = defineIdentityCodec({
  id: "web2ish-sign-in-ed25519-hex-v1",

  encodeAddress: encodeSignInPublicKey,

  encodePublicKey: encodeSignInPublicKey,

  decodePublicKey(identifier) {
    if (typeof identifier !== "string" || !signInPublicKeyIdentifier.test(identifier)) {
      throw new DerivationError(
        "Sign-in public keys must be S_ followed by 64 lowercase hex characters.",
        "invalid-public-key",
      );
    }
    return hexToBytes(identifier.slice(SIGN_IN_PUBLIC_KEY_PREFIX.length));
  },
});

/**
 * Service-salted sign-in profile. The caller supplies the 32-byte salt its
 * identity service publishes. The scrypt output (`masterSeed`) feeds two
 * independent branches: `signInHkdfEd25519` gives the sign-in key the service
 * enrolls, and `withDerivedWallet`'s application secrets give whatever else the
 * application needs from the same password entry, such as a key-encryption-key
 * root or the master seed of a wallet the service never sees.
 *
 * The KDF is the package floor and the Kalvora profile's. Every string below
 * is fixed wire surface, including the trailing newline on the password-hash
 * domain, which is concatenated with the raw password bytes rather than
 * line-joined. Any change, including to the KDF, is a new profile id, never an
 * edit; and because an application secret binds the profile id, a new profile
 * id also changes every secret derived under it.
 */
export const signInEd25519ExternalSalt: DerivationProfile = defineDerivationProfile({
  id: "web2ish-sign-in-ed25519-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-hkdf-sha256-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "web2-ish-self-custody sign-in password hash v1\n",
    entropy: "web2-ish-self-custody sign-in Ed25519 external salt entropy v1",
  },
  keyDerivation: signInHkdfEd25519,
  codec: signInEd25519Codec,
});

/**
 * Service-salted sign-in profile v2: the v1 construction at four times the
 * scrypt cost, `N = 2^18` (256 MiB of working memory per derivation) instead
 * of `2^16`, under its own id, algorithm label and transcript domains.
 *
 * It exists because a sign-in public key, and a wallet address derived from an
 * application secret of the same run once it is published, are password
 * oracles: anyone with the username and the public salt can test guesses
 * offline at one scrypt per guess (docs/SECURITY_MODEL.md#offline-guessing-cost).
 * v2 makes each guess cost four times the scrypt work and memory of v1. scrypt
 * was kept rather than Argon2id because, in a pure-JavaScript browser worker,
 * the pinned @noble/hashes Argon2id runs about 15 times slower than a native attacker's
 * while its scrypt runs within about 1.2 times, so in the same time budget
 * scrypt costs the attacker far more per guess (docs/SECURITY_MODEL.md).
 *
 * Everything else is v1's: the transcript layout, the `external-32` salt,
 * `signInHkdfEd25519` (whose domain separates the sign-in key from the
 * application secrets of one run; the run itself differs from v1's by its
 * transcript domains and KDF), and `signInEd25519Codec`. Application secrets
 * work exactly as under v1, with this profile's id in their `info`, so every
 * secret, and every wallet an application derives from one, differs from v1's
 * for the same credentials. Moving a user from v1 to v2 is therefore a key and
 * wallet change, not an upgrade in place; v1 stays exported so an application
 * can derive the old keys once while it moves a user.
 *
 * Every string below is fixed wire surface; any change, including to the KDF,
 * is a new profile id, never an edit.
 */
export const signInEd25519ExternalSaltV2: DerivationProfile = defineDerivationProfile({
  id: "web2ish-sign-in-ed25519-external-salt-v2",
  curve: "ed25519",
  algorithm: "scrypt-sha512-hkdf-sha256-ed25519-external-32-v2",
  saltPolicy: "external-32",
  kdf: { N: 262_144, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "web2-ish-self-custody sign-in password hash v2\n",
    entropy: "web2-ish-self-custody sign-in Ed25519 external salt entropy v2",
  },
  keyDerivation: signInHkdfEd25519,
  codec: signInEd25519Codec,
});
