import { ed25519 } from "@noble/curves/ed25519.js";
import type { IdentityCodec } from "./codec.js";

export const ED25519_SEED_BYTES = 32;

export type SeedIdentity = Readonly<{
  curve: "ed25519";
  codecId: string;
  address: string;
  publicKey: string;
}>;

const typedArrayTagGetter = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype) as object,
  Symbol.toStringTag,
)?.get;

/**
 * Derives only the public identity for an existing 32-byte Ed25519 seed.
 *
 * This exists for applications that already generate a random wallet seed and
 * want the same address convention without adopting password derivation — the
 * recovery and guessing properties of the two are materially different. The
 * caller keeps ownership of `seed`; this works from an internal copy and clears
 * it before returning, and provides no storage, encryption, or signing.
 *
 * The type check is deliberately stricter than `instanceof`: a Buffer or a
 * subclass would pass `instanceof Uint8Array` while carrying different
 * semantics, so the exact tag is required.
 */
export function deriveIdentityFromSeed(
  seed: Uint8Array,
  codec: IdentityCodec,
): SeedIdentity {
  if (
    !ArrayBuffer.isView(seed) ||
    typedArrayTagGetter?.call(seed) !== "Uint8Array" ||
    seed.byteLength !== ED25519_SEED_BYTES
  ) {
    throw new TypeError("An Ed25519 seed must contain exactly 32 bytes.");
  }

  const ownedSeed = Uint8Array.from(seed);
  try {
    const publicKeyBytes = ed25519.getPublicKey(ownedSeed);
    return Object.freeze({
      curve: "ed25519" as const,
      codecId: codec.id,
      address: codec.encodeAddress(publicKeyBytes),
      publicKey: codec.encodePublicKey(publicKeyBytes),
    });
  } finally {
    ownedSeed.fill(0);
  }
}
