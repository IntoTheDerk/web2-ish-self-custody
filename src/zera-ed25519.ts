import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";

export const ZERA_ED25519_DIRECT_SEED_PROFILE =
  "zera-ed25519-direct-seed-v1" as const;

export type ZeraEd25519DirectSeedIdentity = Readonly<{
  curve: "ed25519";
  seedProfile: typeof ZERA_ED25519_DIRECT_SEED_PROFILE;
  address: string;
  publicKey: string;
}>;

/**
 * Derives only the public ZERA identity for an existing 32-byte Ed25519 seed.
 *
 * The caller keeps ownership of `seed`. The SDK works from an internal copy and
 * clears that copy before returning. This API deliberately provides no storage,
 * persistence, encryption, recovery, or signing behavior.
 */
export function deriveZeraEd25519IdentityFromSeed(
  seed: Uint8Array,
): ZeraEd25519DirectSeedIdentity {
  if (
    !ArrayBuffer.isView(seed) ||
    Object.prototype.toString.call(seed) !== "[object Uint8Array]" ||
    seed.byteLength !== 32
  ) {
    throw new TypeError("A ZERA Ed25519 seed must contain exactly 32 bytes.");
  }

  const ownedSeed = Uint8Array.from(seed);
  try {
    const publicKeyBytes = ed25519.getPublicKey(ownedSeed);
    const address = bs58.encode(publicKeyBytes);
    return Object.freeze({
      curve: "ed25519",
      seedProfile: ZERA_ED25519_DIRECT_SEED_PROFILE,
      address,
      publicKey: `A_${address}`,
    });
  } finally {
    ownedSeed.fill(0);
  }
}
