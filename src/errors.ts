export type DerivationErrorCode =
  | "aborted"
  | "async-wallet-scope"
  | "invalid-codec"
  | "invalid-context"
  | "invalid-message"
  | "invalid-password"
  | "invalid-profile"
  | "invalid-public-key"
  | "invalid-recovery-code"
  | "invalid-salt"
  | "invalid-secret-label"
  | "invalid-seed"
  | "invalid-username"
  | "invalid-vault"
  | "secret-unavailable"
  | "vault-authentication-failed"
  | "vault-identity-mismatch"
  | "wallet-scope-closed";

export class DerivationError extends Error {
  constructor(
    message: string,
    readonly code: DerivationErrorCode,
  ) {
    super(message);
    this.name = "DerivationError";
  }
}
