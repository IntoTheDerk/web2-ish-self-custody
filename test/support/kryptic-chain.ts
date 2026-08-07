import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import { defineIdentityCodec, type IdentityCodec } from "../../src/codec.js";
import { DerivationError } from "../../src/errors.js";
import { defineDerivationProfile, type DerivationProfile } from "../../src/profile.js";

const hex64 = /^[0-9a-f]{64}$/u;

/**
 * A throwaway second chain that shares nothing with ZERA: lowercase hex behind
 * a `k_` tag instead of base58 behind `A_`.
 *
 * It exists so the suite can prove the core is genuinely chain-agnostic rather
 * than ZERA behind an interface. Every assertion made against it runs through
 * the same derivation, challenge, and identity-service code the real chain
 * uses; nothing here is imported by `src/`.
 */
export const krypticHexCodec: IdentityCodec = defineIdentityCodec({
  id: "kryptic-hex-v1",

  encodeAddress(publicKeyBytes) {
    return bytesToHex(publicKeyBytes);
  },

  encodePublicKey(publicKeyBytes) {
    return `k_${bytesToHex(publicKeyBytes)}`;
  },

  decodePublicKey(identifier) {
    const trimmed = identifier.trim();
    if (!trimmed.startsWith("k_")) {
      throw new DerivationError(
        "Kryptic public keys must use the k_<hex> identifier form.",
        "invalid-public-key",
      );
    }
    const encoded = trimmed.slice(2);
    if (!hex64.test(encoded)) {
      throw new DerivationError(
        "Kryptic public keys must be 32 lowercase hex-encoded bytes.",
        "invalid-public-key",
      );
    }
    return hexToBytes(encoded);
  },
});

/** Service-salted, with its own transcript domains. */
export const krypticExternalSalt: DerivationProfile = defineDerivationProfile({
  id: "kryptic-ed25519-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "kryptic test chain password hash v1\n",
    entropy: "kryptic test chain external salt entropy v1",
  },
  codec: krypticHexCodec,
});

/** Stateless, to prove both salt policies are chain-independent. */
export const krypticStateless: DerivationProfile = defineDerivationProfile({
  id: "kryptic-ed25519-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-ed25519-v1",
  saltPolicy: "derived-from-username",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "kryptic test chain password hash v1\n",
    entropy: "kryptic test chain entropy v1",
    salt: "kryptic test chain public username salt v1",
  },
  codec: krypticHexCodec,
});

/**
 * ZERA's exact transcript — same domains, same KDF — behind the hex codec.
 *
 * The profile id is not part of the signed transcript, so this must derive the
 * very same key bytes as the committed ZERA external-salt vector and differ
 * only in how those bytes are spelled. That is the cleanest available proof
 * that the codec is a presentation seam and not a derivation input.
 */
export const krypticZeraTranscript: DerivationProfile = defineDerivationProfile({
  id: "kryptic-zera-transcript-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { ...zeraEd25519ExternalSalt.kdf },
  domains: { ...zeraEd25519ExternalSalt.domains },
  codec: krypticHexCodec,
});

/**
 * Well-formed by `defineIdentityCodec`'s shape rules, but its decode does not
 * invert its encode: it drops the last byte. Callers that trust it would enroll
 * wallets they can never resolve back, which is exactly what
 * `assertCodecRoundTrip` exists to catch.
 */
export const truncatingCodec: IdentityCodec = defineIdentityCodec({
  id: "broken-truncating-v1",

  encodeAddress(publicKeyBytes) {
    return bytesToHex(publicKeyBytes);
  },

  encodePublicKey(publicKeyBytes) {
    return `t_${bytesToHex(publicKeyBytes)}`;
  },

  decodePublicKey(identifier) {
    return hexToBytes(identifier.slice(2)).slice(0, -1);
  },
});

export const truncatingProfile: DerivationProfile = defineDerivationProfile({
  id: "broken-truncating-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "broken test chain password hash v1\n",
    entropy: "broken test chain external salt entropy v1",
  },
  codec: truncatingCodec,
});
