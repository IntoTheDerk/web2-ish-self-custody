export type DerivationErrorCode =
  | "aborted"
  | "async-wallet-scope"
  | "invalid-context"
  | "invalid-digest"
  | "invalid-message"
  | "invalid-password"
  | "invalid-profile"
  | "invalid-salt"
  | "invalid-username"
  | "invalid-wallet-seed"
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
