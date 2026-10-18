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
