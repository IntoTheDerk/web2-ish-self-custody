import { DerivationError } from "./errors.js";

/**
 * How a chain or application encodes a public key as a human-facing address
 * and as a wire identifier.
 *
 * This is the seam that keeps the core generic. Nothing in the derivation or
 * identity-service code knows what base58, bech32, or hex look like; it asks
 * the codec. A new chain is a new codec, not a patch to the core.
 */
export type IdentityCodec = Readonly<{
  /**
   * Stable identifier, recorded alongside enrolled wallets so a deployment can
   * tell which encoding produced a stored address.
   */
  id: string;

  /** Canonical public address for a raw public key. */
  encodeAddress: (publicKeyBytes: Uint8Array) => string;

  /**
   * Canonical public-key identifier. May differ from the address when a chain
   * prefixes or tags its keys.
   */
  encodePublicKey: (publicKeyBytes: Uint8Array) => string;

  /**
   * Inverse of `encodePublicKey`. Must throw for anything malformed rather
   * than returning a partial or coerced result — callers rely on this to
   * reject junk before it reaches signature verification.
   */
  decodePublicKey: (identifier: string) => Uint8Array;
}>;

const codecId = /^[a-z0-9][a-z0-9._-]{2,63}$/u;

export function defineIdentityCodec(codec: IdentityCodec): IdentityCodec {
  if (!codecId.test(codec.id)) {
    throw new DerivationError(
      "Identity codec id must be 3-64 characters from [a-z0-9._-].",
      "invalid-codec",
    );
  }
  for (const method of ["encodeAddress", "encodePublicKey", "decodePublicKey"] as const) {
    if (typeof codec[method] !== "function") {
      throw new DerivationError(
        `Identity codec is missing ${method}.`,
        "invalid-codec",
      );
    }
  }
  return Object.freeze({ ...codec });
}

/**
 * Round-trips a key through the codec and rejects any disagreement.
 *
 * A codec whose decode does not invert its encode would let a caller enroll a
 * key under an identifier nobody can resolve back, so this is checked at the
 * boundary rather than assumed.
 */
export function assertCodecRoundTrip(
  codec: IdentityCodec,
  publicKeyBytes: Uint8Array,
): void {
  const identifier = codec.encodePublicKey(publicKeyBytes);
  const decoded = codec.decodePublicKey(identifier);
  if (
    decoded.byteLength !== publicKeyBytes.byteLength ||
    decoded.some((byte, index) => byte !== publicKeyBytes[index])
  ) {
    throw new DerivationError(
      "Identity codec does not round-trip its own public key encoding.",
      "invalid-codec",
    );
  }
}
