import { hexToBytes } from "@noble/hashes/utils.js";
import { withDerivedWallet } from "./derive.js";
import { DerivationError } from "./errors.js";
import { normalizeUsername } from "./normalization.js";
import type { DerivationProfile } from "./profile.js";
import { signInEd25519Codec } from "./signIn.js";
import type { DerivedWallet } from "./types.js";
import { createWalletVault, type WalletVault } from "./vault.js";

export type AccountWalletMode = "per-account-deterministic" | "random-vault";

/** Public, persistent enrollment metadata. Save before deriving the first key. */
export type AccountWalletSetup = Readonly<{
  accountId: string;
  mode: AccountWalletMode;
  profileId: string;
  codecId: string;
  applicationId: string;
  networkId: string;
  normalizedUsername: string;
  /** Independent random 32-byte salt, used only in deterministic mode. */
  publicSaltHex: string;
}>;

function checkSetup(setup: AccountWalletSetup, profile: DerivationProfile): void {
  if (setup.profileId !== profile.id || setup.codecId !== profile.codec.id ||
      profile.saltPolicy !== "external-32" ||
      !/^[0-9a-f]{64}$/u.test(setup.publicSaltHex) ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(setup.accountId) ||
      normalizeUsername(setup.normalizedUsername) !== setup.normalizedUsername) {
    throw new DerivationError("Account wallet setup does not match the selected profile.", "invalid-profile");
  }
}

/**
 * Reconstructs an account's signing identity. A different password means a different key.
 *
 * `options.applicationSecrets` is passed to `withDerivedWallet` unchanged, so the
 * callback receives the same application secrets, under the same rules, as a
 * direct call with the account's salt. Under the sign-in profile that is how
 * the application gets its wallet's master seed from the same password entry.
 */
export function withAccountWallet<T>(
  setup: AccountWalletSetup,
  profile: DerivationProfile,
  password: Uint8Array,
  use: (wallet: DerivedWallet, secrets: ReadonlyMap<string, Uint8Array>) => T,
  options?: Readonly<{ applicationSecrets?: readonly string[] }>,
): Promise<T> {
  checkSetup(setup, profile);
  if (setup.mode !== "per-account-deterministic") {
    throw new DerivationError("This account must be opened from its encrypted vault.", "invalid-profile");
  }
  return withDerivedWallet({
    profile, password, username: setup.normalizedUsername,
    context: { applicationId: setup.applicationId, networkId: setup.networkId },
    salt: hexToBytes(setup.publicSaltHex),
  }, use, options);
}

/**
 * Generates the seed internally; neither a seed nor a password goes to the service.
 *
 * Refuses the sign-in profile (`invalid-profile`): a random key comes from no
 * password derivation, so there would be no application secret to give the
 * application a wallet beside the sign-in key. Serve it in a deterministic mode.
 */
export async function createRandomAccountWallet(
  setup: AccountWalletSetup,
  profile: DerivationProfile,
  password: Uint8Array,
): Promise<{ vault: WalletVault; recoveryCode: string }> {
  checkSetup(setup, profile);
  if (setup.mode !== "random-vault") {
    throw new DerivationError("This account uses deterministic derivation.", "invalid-profile");
  }
  if (profile.codec.id === signInEd25519Codec.id) {
    throw new DerivationError(
      "The sign-in profile derives its key from the password; random-vault mode needs a chain wallet profile.",
      "invalid-profile",
    );
  }
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32));
  try {
    return await createWalletVault({
      profile, password, seed, username: setup.normalizedUsername,
      context: { applicationId: setup.applicationId, networkId: setup.networkId },
    });
  } finally {
    seed.fill(0);
  }
}
