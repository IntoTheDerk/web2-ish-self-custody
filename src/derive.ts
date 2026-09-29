import { ed25519 } from "@noble/curves/ed25519.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import { canonicalizeContext, fingerprint, utf8 } from "./encoding.js";
import { DerivationError } from "./errors.js";
import { assertWalletPassword, normalizeUsername } from "./normalization.js";
import type { DerivationProfile } from "./profile.js";
import type { DerivationCredentials, DerivedIdentity, DerivedWallet } from "./types.js";

const EXTERNAL_SALT_BYTES = 32;
const MAXIMUM_MESSAGE_BYTES = 1_048_576;
const ED25519_KEY_BYTES = 32;

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new DerivationError("Wallet derivation was cancelled.", "aborted");
  }
}

/**
 * Resolves the scrypt salt for a profile.
 *
 * The salt policy is checked before any KDF work so a caller who supplies the
 * wrong shape finds out immediately rather than after a second of scrypt.
 */
function resolveSalt(
  profile: DerivationProfile,
  suppliedSalt: Uint8Array | undefined,
  applicationId: string,
  networkId: string,
  normalizedUsername: string,
): Uint8Array {
  if (profile.saltPolicy === "external-32") {
    if (!(suppliedSalt instanceof Uint8Array) || suppliedSalt.byteLength !== EXTERNAL_SALT_BYTES) {
      throw new DerivationError(
        "This profile requires an exact 32-byte public derivation salt.",
        "invalid-salt",
      );
    }
    return Uint8Array.from(suppliedSalt);
  }

  if (suppliedSalt !== undefined) {
    throw new DerivationError(
      "This profile derives its own salt and does not accept an external salt.",
      "invalid-salt",
    );
  }

  const saltDomain = profile.domains.salt;
  if (saltDomain === undefined) {
    throw new DerivationError(
      "Profile is missing the salt domain its policy requires.",
      "invalid-profile",
    );
  }
  return sha256(utf8([saltDomain, applicationId, networkId, normalizedUsername].join("\n")));
}

async function runScrypt(
  entropy: Uint8Array,
  salt: Uint8Array,
  credentials: DerivationCredentials,
): Promise<Uint8Array> {
  const { kdf } = credentials.profile;
  throwIfAborted(credentials.signal);
  let progressCallbackError: unknown;
  const output = await scryptAsync(entropy, salt, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    dkLen: kdf.dkLen,
    onProgress(progress) {
      try {
        credentials.onProgress?.(progress);
      } catch (error) {
        progressCallbackError ??= error;
      }
    },
  });
  try {
    throwIfAborted(credentials.signal);
    if (progressCallbackError !== undefined) throw progressCallbackError;
    return output;
  } catch (error) {
    output.fill(0);
    throw error;
  }
}

/** Runs the profile's key-derivation step and holds it to exactly 32 bytes. */
function deriveChainKey(profile: DerivationProfile, masterSeed: Uint8Array): Uint8Array {
  // The step gets its own copy, so nothing it does can reach the seed the
  // caller of this function still zeroes.
  const input = Uint8Array.from(masterSeed);
  let key: unknown;
  try {
    key = profile.keyDerivation?.deriveKey(input);
  } catch {
    throw new DerivationError(
      `Key derivation "${profile.keyDerivation?.id}" failed.`,
      "invalid-profile",
    );
  } finally {
    input.fill(0);
  }
  if (!(key instanceof Uint8Array) || key.byteLength !== ED25519_KEY_BYTES) {
    if (key instanceof Uint8Array) key.fill(0);
    throw new DerivationError(
      `Key derivation "${profile.keyDerivation?.id}" must return exactly 32 bytes.`,
      "invalid-profile",
    );
  }
  return key;
}

/**
 * Package-internal seed access.
 *
 * Deliberately NOT re-exported from the barrel. `withDerivedWallet` is the
 * public way to use a wallet precisely because it bounds the seed's lifetime;
 * the only legitimate reason to hold raw seed bytes is to seal them into a
 * vault, and `vault.ts` is the one caller. Anything else should use the scoped
 * API. Callers of this MUST zero the seed they receive.
 */
export async function deriveWalletSeedUnsafe(
  credentials: DerivationCredentials,
): Promise<{ seed: Uint8Array; identity: DerivedIdentity }> {
  return derive(credentials);
}

async function derive(
  credentials: DerivationCredentials,
): Promise<{ seed: Uint8Array; identity: DerivedIdentity }> {
  const { profile } = credentials;

  assertWalletPassword(credentials.password);
  const normalizedUsername = normalizeUsername(credentials.username);
  const context = canonicalizeContext(credentials.context);
  const password = Uint8Array.from(credentials.password);

  let salt: Uint8Array | undefined;
  let passwordEntropyHash: Uint8Array | undefined;
  let walletEntropy: Uint8Array | undefined;
  let masterSeed: Uint8Array | undefined;
  let seed: Uint8Array | undefined;

  try {
    salt = resolveSalt(
      profile,
      credentials.salt,
      context.applicationId,
      context.networkId,
      normalizedUsername,
    );

    passwordEntropyHash = sha512(concatBytes(utf8(profile.domains.passwordHash), password));
    walletEntropy = sha512(
      utf8(
        [
          profile.domains.entropy,
          context.applicationId,
          context.networkId,
          normalizedUsername,
          bytesToHex(passwordEntropyHash),
        ].join("\n"),
      ),
    );

    masterSeed = await runScrypt(walletEntropy, salt, credentials);
    throwIfAborted(credentials.signal);
    if (profile.keyDerivation === undefined) {
      seed = masterSeed;
      masterSeed = undefined;
    } else {
      seed = deriveChainKey(profile, masterSeed);
    }

    const publicKeyBytes = ed25519.getPublicKey(seed);
    const address = profile.codec.encodeAddress(publicKeyBytes);

    return {
      seed,
      identity: Object.freeze({
        profileId: profile.id,
        codecId: profile.codec.id,
        curve: "ed25519",
        normalizedUsername,
        address,
        publicKey: profile.codec.encodePublicKey(publicKeyBytes),
        publicKeyBytes: Uint8Array.from(publicKeyBytes),
        fingerprint: fingerprint(address),
      }),
    };
  } catch (error) {
    seed?.fill(0);
    throw error;
  } finally {
    password.fill(0);
    salt?.fill(0);
    passwordEntropyHash?.fill(0);
    walletEntropy?.fill(0);
    masterSeed?.fill(0);
  }
}

/**
 * Derives a wallet, hands it to `useWallet`, and zeroes the seed on the way
 * out. The callback must be synchronous: an async callback could retain the
 * wallet past this function's return and defeat the bounded secret lifetime
 * that is the whole point of the scoped API.
 */
export async function withDerivedWallet<T>(
  credentials: DerivationCredentials,
  useWallet: (wallet: DerivedWallet) => T,
): Promise<T> {
  if (!(credentials.password instanceof Uint8Array)) {
    throw new DerivationError("Password input must be a Uint8Array.", "invalid-password");
  }
  const profile: unknown = credentials.profile;
  if (typeof profile !== "object" || profile === null || typeof credentials.profile.id !== "string") {
    throw new DerivationError(
      "credentials.profile must be a derivation profile object.",
      "invalid-profile",
    );
  }

  const derived = await derive(credentials);

  let active = true;
  const wallet: DerivedWallet = Object.freeze({
    identity: derived.identity,
    signExactMessageUnsafe(message: Uint8Array) {
      if (!active) {
        throw new DerivationError(
          "The derived wallet is no longer available outside its callback scope.",
          "wallet-scope-closed",
        );
      }
      if (
        !(message instanceof Uint8Array) ||
        message.byteLength === 0 ||
        message.byteLength > MAXIMUM_MESSAGE_BYTES
      ) {
        throw new DerivationError(
          `Message must contain 1–${MAXIMUM_MESSAGE_BYTES} bytes.`,
          "invalid-message",
        );
      }
      return ed25519.sign(message, derived.seed);
    },
  });

  try {
    const result = useWallet(wallet);
    if (
      typeof result === "object" &&
      result !== null &&
      "then" in result &&
      typeof result.then === "function"
    ) {
      throw new DerivationError(
        "Wallet callbacks must be synchronous so secret lifetime stays bounded.",
        "async-wallet-scope",
      );
    }
    return result;
  } finally {
    active = false;
    derived.seed.fill(0);
  }
}

export async function derivePublicIdentity(
  credentials: DerivationCredentials,
): Promise<DerivedIdentity> {
  return withDerivedWallet(credentials, (wallet) =>
    Object.freeze({
      ...wallet.identity,
      publicKeyBytes: Uint8Array.from(wallet.identity.publicKeyBytes),
    }),
  );
}
