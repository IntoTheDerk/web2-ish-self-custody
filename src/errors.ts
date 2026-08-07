export type DerivationErrorCode =
  | "aborted"
  | "async-wallet-scope"
  | "invalid-codec"
  | "invalid-context"
  | "invalid-message"
  | "invalid-password"
  | "invalid-profile"
  | "invalid-public-key"
  | "invalid-salt"
  | "invalid-username"
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
