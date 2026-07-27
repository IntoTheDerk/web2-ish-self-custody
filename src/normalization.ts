import { DerivationError } from "./errors.js";

const asciiIdentifier = /^[\x21-\x7e]{3,120}$/u;

export function normalizeDemocracyOsUsername(username: string): string {
  const normalized = username.trim().toLowerCase();
  if (normalized.length === 0 || normalized.length > 320 || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw new DerivationError("Invalid DemocracyOS username.", "invalid-username");
  }
  return normalized;
}

export function normalizeWeb2ishUsername(username: string): string {
  const normalized = username.replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/gu, "").replace(/[A-Z]/gu, (letter) =>
    letter.toLowerCase(),
  );
  if (!asciiIdentifier.test(normalized)) {
    throw new DerivationError(
      "The v1 username must be 3–120 printable ASCII characters after ASCII trim and lowercase normalization.",
      "invalid-username",
    );
  }
  return normalized;
}

export function assertWalletPassword(password: Uint8Array, minimumBytes: number): void {
  if (!(password instanceof Uint8Array) || password.byteLength < minimumBytes || password.byteLength > 1_024) {
    throw new DerivationError(
      `The password must contain ${minimumBytes}–1,024 UTF-8 bytes for this profile.`,
      "invalid-password",
    );
  }
}
