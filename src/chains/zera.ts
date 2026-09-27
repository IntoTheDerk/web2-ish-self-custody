import bs58 from "bs58";
import { defineIdentityCodec, type IdentityCodec } from "../codec.js";
import { DerivationError } from "../errors.js";
import { defineDerivationProfile, type DerivationProfile } from "../profile.js";
import { deriveIdentityFromSeed, type SeedIdentity } from "../seed.js";

const base58Address = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/u;
const ED25519_PUBLIC_KEY_BYTES = 32;

/**
 * ZERA's Ed25519 convention: the address is the base58 of the raw public key,
 * and the wire identifier is that address behind an `A_` tag.
 */
export const zeraEd25519Codec: IdentityCodec = defineIdentityCodec({
  id: "zera-ed25519-base58-v1",

  encodeAddress(publicKeyBytes) {
    return bs58.encode(publicKeyBytes);
  },

  encodePublicKey(publicKeyBytes) {
    return `A_${bs58.encode(publicKeyBytes)}`;
  },

  decodePublicKey(identifier) {
    const trimmed = identifier.trim();
    if (!trimmed.startsWith("A_")) {
      throw new DerivationError(
        "ZERA Ed25519 public keys must use the A_<base58> identifier form.",
        "invalid-public-key",
      );
    }

    const encoded = trimmed.slice(trimmed.lastIndexOf("_") + 1);
    if (!base58Address.test(encoded)) {
      throw new DerivationError(
        "ZERA Ed25519 public key is not valid base58.",
        "invalid-public-key",
      );
    }

    let decoded: Uint8Array;
    try {
      decoded = bs58.decode(encoded);
    } catch {
      throw new DerivationError(
        "ZERA Ed25519 public key is not valid base58.",
        "invalid-public-key",
      );
    }
    if (decoded.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new DerivationError(
        "ZERA Ed25519 public keys must be 32 bytes.",
        "invalid-public-key",
      );
    }
    return decoded;
  },
});

/**
 * Service-salted: the caller supplies a 32-byte salt the service owns.
 *
 * Every string below is fixed wire surface, reproduced exactly as originally
 * specified — including the trailing newline on the password-hash domain,
 * which is concatenated with the raw password bytes rather than line-joined.
 * Editing any of them redefines every wallet derived under this profile, so a
 * change belongs in a new profile id, never here.
 */
export const zeraEd25519ExternalSalt: DerivationProfile = defineDerivationProfile({
  id: "web2ish-zera-ed25519-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "web2-ish-self-custody password hash v1\n",
    entropy: "web2-ish-self-custody ZERA Ed25519 external salt entropy v1",
  },
  codec: zeraEd25519Codec,
});

/** The bundled ZERA profiles, keyed by id, for resolving a stored profile id. */
export const zeraProfiles: Readonly<Record<string, DerivationProfile>> = Object.freeze({
  [zeraEd25519ExternalSalt.id]: zeraEd25519ExternalSalt,
});

/**
 * ZERA identity for an application-owned random seed, for wallets that are not
 * password-derived. Storage, encryption, and recovery stay with the caller.
 */
export function deriveZeraEd25519IdentityFromSeed(seed: Uint8Array): SeedIdentity {
  return deriveIdentityFromSeed(seed, zeraEd25519Codec);
}
