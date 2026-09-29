import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import type { IdentityCodec } from "../codec.js";
import { utf8 } from "../encoding.js";
import { DerivationError } from "../errors.js";
import { IdentityError } from "./errors.js";
import type { ChallengePurpose } from "./types.js";

export const CHALLENGE_DOMAIN = "web2-ish-self-custody auth challenge v1";

const hex64 = /^[0-9a-f]{64}$/u;
const hex128 = /^[0-9a-f]{128}$/u;
const ED25519_PUBLIC_KEY_BYTES = 32;

function assertNoLineBreak(value: string, field: string): string {
  if (/[\r\n]/u.test(value)) {
    throw new IdentityError(
      `${field} must not contain line breaks.`,
      "invalid-request",
    );
  }
  return value;
}

export type ChallengeMessageInput = Readonly<{
  serviceProfileId: string;
  applicationId: string;
  networkId: string;
  purpose: ChallengePurpose;
  usernameNormalized: string;
  nonceHex: string;
  expiresAt: Date;
}>;

/**
 * The exact bytes a client signs.
 *
 * Every component is newline-free by construction (username normalization
 * rejects anything outside printable ASCII), so the line-delimited encoding is
 * unambiguous and two different field tuples cannot produce the same message.
 * The leading domain string keeps these signatures from being replayable
 * against any other protocol that signs with the same key.
 */
export function buildChallengeMessage(input: ChallengeMessageInput): string {
  if (!hex64.test(input.nonceHex)) {
    throw new IdentityError("Challenge nonce must be 32 hex-encoded bytes.", "invalid-request");
  }
  return [
    CHALLENGE_DOMAIN,
    assertNoLineBreak(input.serviceProfileId, "serviceProfileId"),
    assertNoLineBreak(input.applicationId, "applicationId"),
    assertNoLineBreak(input.networkId, "networkId"),
    input.purpose,
    assertNoLineBreak(input.usernameNormalized, "username"),
    input.nonceHex,
    input.expiresAt.toISOString(),
  ].join("\n");
}

export type WalletIdentityInput = Readonly<{
  publicKey: string;
  address: string;
}>;

export type CanonicalWalletIdentity = Readonly<{
  curve: "ed25519";
  codecId: string;
  address: string;
  addressNormalized: string;
  publicKey: string;
  publicKeyBytes: Uint8Array;
}>;

/**
 * Re-derives the address and identifier from the submitted public key using the
 * deployment's codec, and rejects any disagreement — so a caller cannot enroll
 * a key under an address it does not control, and cannot smuggle in a
 * non-canonical encoding of one it does.
 *
 * The codec is a parameter rather than a hardcoded convention; that is what
 * lets a non-Kalvora deployment use this service unchanged.
 */
export function canonicalWalletIdentity(
  codec: IdentityCodec,
  input: WalletIdentityInput,
): CanonicalWalletIdentity {
  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = codec.decodePublicKey(input.publicKey);
  } catch (error) {
    throw new IdentityError(
      error instanceof DerivationError
        ? error.message
        : "Public key is not valid for this deployment's identity codec.",
      "invalid-public-key",
    );
  }

  if (publicKeyBytes.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    throw new IdentityError("Ed25519 public keys must be 32 bytes.", "invalid-public-key");
  }

  const address = codec.encodeAddress(publicKeyBytes);
  const publicKey = codec.encodePublicKey(publicKeyBytes);
  if (input.address.trim() !== address) {
    throw new IdentityError(
      "Wallet address does not match its public key.",
      "invalid-address",
    );
  }

  return Object.freeze({
    curve: "ed25519" as const,
    codecId: codec.id,
    address,
    addressNormalized: address.toLowerCase(),
    publicKey,
    publicKeyBytes,
  });
}

/**
 * Verifies a challenge signature using the exact convention the derivation core
 * produces: Ed25519 over the raw UTF-8 challenge bytes, as emitted by
 * `signExactMessageUnsafe`.
 */
export function verifyChallengeSignature(
  identity: CanonicalWalletIdentity,
  message: string,
  signature: string,
): boolean {
  const normalized = signature.trim().toLowerCase();
  if (!hex128.test(normalized)) {
    return false;
  }

  try {
    return ed25519.verify(hexToBytes(normalized), utf8(message), identity.publicKeyBytes);
  } catch {
    return false;
  }
}
