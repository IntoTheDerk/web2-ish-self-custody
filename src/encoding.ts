import { bytesToHex } from "@noble/hashes/utils.js";
import { DerivationError } from "./errors.js";
import type { DerivationContext } from "./types.js";

const encoder = new TextEncoder();
const contextValue = /^[a-z0-9][a-z0-9._:-]{0,79}$/u;

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function hex(value: Uint8Array): string {
  return bytesToHex(value);
}

export function canonicalizeContext(context: DerivationContext): Required<DerivationContext> {
  const applicationId = context.applicationId.trim().toLowerCase();
  const networkId = context.networkId.trim().toLowerCase();
  if (!contextValue.test(applicationId) || !contextValue.test(networkId)) {
    throw new DerivationError("Invalid application or network derivation context.", "invalid-context");
  }
  return { applicationId, networkId };
}

export function fingerprint(value: string): string {
  return value
    .replace(/[^a-z0-9]/giu, "")
    .toUpperCase()
    .slice(0, 16)
    .replace(/(.{4})/gu, "$1 ")
    .trim();
}
