import bs58 from "bs58";
import {
  KEY_TYPE,
  deriveHDPrivateKey,
  generateKalvoraAddress,
  generateKalvoraPublicKeyIdentifier,
} from "kalvora.js/wallet";
import { defineIdentityCodec, type IdentityCodec } from "../codec.js";
import { DerivationError } from "../errors.js";
import {
  defineDerivationProfile,
  type DerivationProfile,
  type KeyDerivation,
} from "../profile.js";
import { deriveIdentityFromSeed, type SeedIdentity } from "../seed.js";

const base58Address = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/u;
const ED25519_PUBLIC_KEY_BYTES = 32;

/**
 * Kalvora support is provided by kalvora.js: key derivation and address
 * encoding call `kalvora.js/wallet`, so a password wallet here is exactly the
 * wallet kalvora.js derives from the same seed. That entry point has no
 * network or protobuf code. kalvora.js is an optional peer dependency, needed
 * only by this module.
 */

/** Kalvora's registered SLIP-44 coin type. */
export const KALVORA_SLIP44_COIN_TYPE = 5258;

/**
 * The path every Kalvora password wallet is derived at: kalvora.js's first
 * wallet, account 0, change 0, address 0, all hardened.
 *
 * Pinned here rather than read from kalvora.js, because it is part of this
 * profile's definition: a kalvora.js release that moved its default path must
 * not move existing password wallets with it.
 */
export const KALVORA_DERIVATION_PATH = "m/44'/5258'/0'/0'/0'";

/**
 * Kalvora's Ed25519 convention, encoded by kalvora.js: the address is the
 * base58 of the raw public key, and the wire identifier is that address behind
 * an `A_` tag. Decoding stays local and strict, accepting only that exact
 * form.
 */
export const kalvoraEd25519Codec: IdentityCodec = defineIdentityCodec({
  id: "kalvora-ed25519-base58-v1",

  encodeAddress(publicKeyBytes) {
    return generateKalvoraAddress(Uint8Array.from(publicKeyBytes), KEY_TYPE.ED25519);
  },

  encodePublicKey(publicKeyBytes) {
    return generateKalvoraPublicKeyIdentifier(Uint8Array.from(publicKeyBytes), KEY_TYPE.ED25519);
  },

  decodePublicKey(identifier) {
    const trimmed = identifier.trim();
    if (!trimmed.startsWith("A_")) {
      throw new DerivationError(
        "Kalvora Ed25519 public keys must use the A_<base58> identifier form.",
        "invalid-public-key",
      );
    }

    const encoded = trimmed.slice(trimmed.lastIndexOf("_") + 1);
    if (!base58Address.test(encoded)) {
      throw new DerivationError(
        "Kalvora Ed25519 public key is not valid base58.",
        "invalid-public-key",
      );
    }

    let decoded: Uint8Array;
    try {
      decoded = bs58.decode(encoded);
    } catch {
      throw new DerivationError(
        "Kalvora Ed25519 public key is not valid base58.",
        "invalid-public-key",
      );
    }
    if (decoded.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new DerivationError(
        "Kalvora Ed25519 public keys must be 32 bytes.",
        "invalid-public-key",
      );
    }
    return decoded;
  },
});

/**
 * SLIP-0010 Ed25519 at `KALVORA_DERIVATION_PATH`, computed by kalvora.js. The
 * scrypt output is the SLIP-0010 master seed.
 */
export const kalvoraSlip10Ed25519: KeyDerivation = Object.freeze({
  id: `slip10-ed25519:${KALVORA_DERIVATION_PATH}`,
  deriveKey(masterSeed: Uint8Array): Uint8Array {
    return deriveHDPrivateKey(masterSeed, KALVORA_DERIVATION_PATH, KEY_TYPE.ED25519);
  },
});

/**
 * Service-salted: the caller supplies a 32-byte salt the service owns. The
 * scrypt output is a SLIP-0010 master seed, and the wallet key is its node at
 * `KALVORA_DERIVATION_PATH`, so coin type 5258 is part of every key and the
 * wallet is the one kalvora.js derives from that seed.
 *
 * Every string below is fixed wire surface — including the trailing newline on
 * the password-hash domain, which is concatenated with the raw password bytes
 * rather than line-joined. Editing any of them, or the path, redefines every
 * wallet derived under this profile, so a change belongs in a new profile id,
 * never here.
 */
export const kalvoraEd25519ExternalSalt: DerivationProfile = defineDerivationProfile({
  id: "web2ish-kalvora-ed25519-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-slip10-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "web2-ish-self-custody password hash v1\n",
    entropy: "web2-ish-self-custody Kalvora Ed25519 external salt entropy v1",
  },
  keyDerivation: kalvoraSlip10Ed25519,
  codec: kalvoraEd25519Codec,
});

/** The bundled Kalvora profiles, keyed by id, for resolving a stored profile id. */
export const kalvoraProfiles: Readonly<Record<string, DerivationProfile>> = Object.freeze({
  [kalvoraEd25519ExternalSalt.id]: kalvoraEd25519ExternalSalt,
});

/**
 * Kalvora identity for an application-owned random 32-byte Ed25519 key, for
 * wallets that are not password-derived. The seed is used as the private key
 * directly, with no SLIP-0010 step. Storage, encryption, and recovery stay
 * with the caller.
 */
export function deriveKalvoraEd25519IdentityFromSeed(seed: Uint8Array): SeedIdentity {
  return deriveIdentityFromSeed(seed, kalvoraEd25519Codec);
}
