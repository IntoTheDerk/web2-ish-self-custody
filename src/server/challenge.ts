import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import bs58 from "bs58";
import { utf8 } from "../encoding.js";
import { IdentityError } from "./errors.js";
import type { ChallengePurpose } from "./types.js";

export const CHALLENGE_DOMAIN = "web2-ish-self-custody auth challenge v1";

const hex64 = /^[0-9a-f]{64}$/u;
const hex128 = /^[0-9a-f]{128}$/u;
const base58Address = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/u;

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
  address: string;
  addressNormalized: string;
  publicKey: string;
  publicKeyBytes: Uint8Array;
}>;

/**
 * Recomputes the address from the public key and rejects any mismatch, so a
 * caller cannot register a key under an address it does not control.
 */
export function canonicalWalletIdentity(
  input: WalletIdentityInput,
): CanonicalWalletIdentity {
  const publicKey = input.publicKey.trim();
  if (!publicKey.startsWith("A_")) {
    throw new IdentityError(
      "Ed25519 public keys must use the A_<base58> identifier form.",
      "invalid-public-key",
    );
  }

  let publicKeyBytes: Uint8Array;
  try {
    publicKeyBytes = bs58.decode(publicKey.slice(publicKey.lastIndexOf("_") + 1));
  } catch {
    throw new IdentityError("Ed25519 public key is not valid base58.", "invalid-public-key");
  }
  if (publicKeyBytes.length !== 32) {
    throw new IdentityError("Ed25519 public keys must be 32 bytes.", "invalid-public-key");
  }

  const address = bs58.encode(publicKeyBytes);
  if (!base58Address.test(address) || input.address.trim() !== address) {
    throw new IdentityError(
      "Wallet address does not match its Ed25519 public key.",
      "invalid-address",
    );
  }

  return Object.freeze({
    curve: "ed25519" as const,
    address,
    addressNormalized: address.toLowerCase(),
    publicKey: `A_${address}`,
    publicKeyBytes,
  });
}

/**
 * Verifies a challenge signature using the exact convention the derivation SDK
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
