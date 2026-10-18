import { ed25519 } from "@noble/curves/ed25519.js";
import { extract } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
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

/**
 * The HKDF-Extract salt of every application secret and the first line of its
 * `info`. It versions the construction: any change to it, to the `info` layout,
 * or to the output length is a new domain string, never an edit (see
 * docs/PROTOCOL.md#application-secrets).
 */
const APPLICATION_SECRET_DOMAIN = "web2-ish-self-custody application secret v1";
/** HKDF-Expand's block counter for T(1), the only block when L = HashLen. */
const HKDF_FIRST_BLOCK = Uint8Array.of(0x01);
/** No line break in the alphabet, so the newline-joined `info` is unambiguous. */
const applicationSecretLabel = /^[a-z0-9][a-z0-9._:-]{2,79}$/u;
const NO_APPLICATION_SECRETS: readonly string[] = Object.freeze([]);

type Derived = {
  seed: Uint8Array;
  identity: DerivedIdentity;
  /** In request order. Empty unless labels were passed to `derive`. */
  secrets: readonly (readonly [label: string, secret: Uint8Array])[];
};

/** Equal-length comparison that inspects every byte. */
function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

/**
 * Whether a callback's result is one of the secret arrays, a view of one, or
 * one's buffer. Each secret owns its buffer (it is `hmac`'s fresh output), so
 * sharing a buffer means sharing the bytes that are about to be zeroed.
 */
function sharesSecretMemory(value: unknown, secrets: Derived["secrets"]): boolean {
  const buffer: unknown = ArrayBuffer.isView(value) ? value.buffer : value;
  return secrets.some(([, secret]) => secret.buffer === buffer);
}

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
  // Never requests application secrets, so `derive` computes no PRK on this
  // path and nothing derived from the master seed reaches the vault.
  const { seed, identity } = await derive(credentials, NO_APPLICATION_SECRETS);
  return { seed, identity };
}

/**
 * Validates the requested labels before any KDF work and returns a frozen copy,
 * so a caller that mutates its array mid-derivation cannot change what is
 * derived.
 */
function resolveApplicationSecretLabels(options: unknown): readonly string[] {
  if (options === undefined) return NO_APPLICATION_SECRETS;
  if (typeof options !== "object" || options === null) {
    throw new DerivationError(
      "withDerivedWallet options must be an object.",
      "invalid-secret-label",
    );
  }
  const requested: unknown = (options as { applicationSecrets?: unknown }).applicationSecrets;
  if (requested === undefined) return NO_APPLICATION_SECRETS;
  if (!Array.isArray(requested)) {
    throw new DerivationError(
      "applicationSecrets must be an array of labels.",
      "invalid-secret-label",
    );
  }

  const labels: string[] = [];
  const seen = new Set<string>();
  for (const label of requested as readonly unknown[]) {
    if (typeof label !== "string" || !applicationSecretLabel.test(label)) {
      throw new DerivationError(
        "Each application secret label must be 3-80 characters from [a-z0-9._:-], starting with a letter or digit.",
        "invalid-secret-label",
      );
    }
    if (seen.has(label)) {
      throw new DerivationError(
        `Application secret label "${label}" is requested more than once.`,
        "invalid-secret-label",
      );
    }
    seen.add(label);
    labels.push(label);
  }
  return Object.freeze(labels);
}

/**
 * HKDF-SHA256 from the scrypt output: one Extract keyed by the domain string,
 * then one 32-byte Expand per label. The PRK is zeroed before this returns.
 *
 * Expand is computed as its single block, T(1) = HMAC-SHA256(PRK, info ‖ 0x01),
 * which is HKDF-Expand exactly for L = 32 = HashLen. noble's `expand` copies
 * its output out of an internal buffer that it never clears, so it would leave
 * a second copy of every secret that nothing zeroes; `hmac` cleans its own
 * state and returns the only copy. Any other length is a new domain string
 * (docs/PROTOCOL.md#versioning), not a second block here.
 */
function deriveApplicationSecrets(
  masterSeed: Uint8Array,
  profileId: string,
  applicationId: string,
  networkId: string,
  normalizedUsername: string,
  labels: readonly string[],
): Derived["secrets"] {
  const prk = extract(sha256, masterSeed, utf8(APPLICATION_SECRET_DOMAIN));
  const secrets: (readonly [string, Uint8Array])[] = [];
  try {
    for (const label of labels) {
      const info = utf8(
        [
          APPLICATION_SECRET_DOMAIN,
          profileId,
          applicationId,
          networkId,
          normalizedUsername,
          label,
        ].join("\n"),
      );
      secrets.push([label, hmac(sha256, prk, concatBytes(info, HKDF_FIRST_BLOCK))]);
    }
    return secrets;
  } catch (error) {
    for (const [, secret] of secrets) secret.fill(0);
    throw error;
  } finally {
    prk.fill(0);
  }
}

/**
 * `secretLabels` is the internal flag of docs/PROTOCOL.md#application-secrets:
 * the PRK is computed only when it is non-empty, and only `withDerivedWallet`
 * passes a non-empty one.
 */
async function derive(
  credentials: DerivationCredentials,
  secretLabels: readonly string[],
): Promise<Derived> {
  const { profile } = credentials;

  assertWalletPassword(credentials.password);
  const normalizedUsername = normalizeUsername(credentials.username);
  const context = canonicalizeContext(credentials.context);
  if (secretLabels.length > 0 && profile.keyDerivation === undefined) {
    // Without the step the wallet key IS the scrypt output, so a secret
    // derived from it would not be independent of the wallet key.
    throw new DerivationError(
      "Application secrets need a profile with a key-derivation step; in this profile the wallet key is the scrypt output itself.",
      "secret-unavailable",
    );
  }
  const password = Uint8Array.from(credentials.password);

  let salt: Uint8Array | undefined;
  let passwordEntropyHash: Uint8Array | undefined;
  let walletEntropy: Uint8Array | undefined;
  let masterSeed: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  let secrets: Derived["secrets"] = [];

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
      // Checked again: a profile object that was not frozen by
      // `defineDerivationProfile` can lose its step during scrypt, and an
      // empty map must never stand in for requested secrets.
      if (secretLabels.length > 0) {
        throw new DerivationError(
          "Application secrets need a profile with a key-derivation step; in this profile the wallet key is the scrypt output itself.",
          "secret-unavailable",
        );
      }
      seed = masterSeed;
      masterSeed = undefined;
    } else {
      seed = deriveChainKey(profile, masterSeed);
      if (secretLabels.length > 0) {
        // A step that hands back the scrypt output unchanged makes the wallet
        // key the scrypt output after all. The core cannot prove a step is
        // one-way (docs/PROTOCOL.md#application-secrets), but it refuses the
        // one invertible step it can recognise. `seed` is zeroed by `catch`.
        if (equalBytes(seed, masterSeed)) {
          throw new DerivationError(
            "Application secrets need a key-derivation step that does not return the scrypt output itself.",
            "secret-unavailable",
          );
        }
        // `masterSeed` is still live here and is zeroed in `finally` below.
        secrets = deriveApplicationSecrets(
          masterSeed,
          profile.id,
          context.applicationId,
          context.networkId,
          normalizedUsername,
          secretLabels,
        );
      }
    }

    const publicKeyBytes = ed25519.getPublicKey(seed);
    const address = profile.codec.encodeAddress(publicKeyBytes);

    return {
      seed,
      secrets,
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
    for (const [, secret] of secrets) secret.fill(0);
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
 *
 * `options.applicationSecrets` requests 32-byte application secrets, derived
 * from the same scrypt run with HKDF-SHA256 under application-chosen labels
 * (docs/PROTOCOL.md#application-secrets). They arrive as the callback's second
 * parameter, keyed by label; the map is empty when none are requested. Their
 * arrays are zeroed when the callback returns, like the seed, so a caller that
 * needs one later copies it inside the callback and zeroes the copy itself.
 * Returning the map, a secret's array, a view of one or its buffer would hand
 * back bytes that are already zero, so it throws `wallet-scope-closed` instead.
 * Labels must match `^[a-z0-9][a-z0-9._:-]{2,79}$` and be unique
 * (`invalid-secret-label`), checked before any KDF work. A profile without a
 * key-derivation step refuses secrets (`secret-unavailable`) before any KDF
 * work too, and one whose step returns the scrypt output unchanged refuses them
 * with the same code once that output is known. Secrets are independent of
 * the wallet key only when the profile's step is one-way, which the core cannot
 * check (see `KeyDerivation`).
 */
export async function withDerivedWallet<T>(
  credentials: DerivationCredentials,
  useWallet: (wallet: DerivedWallet, secrets: ReadonlyMap<string, Uint8Array>) => T,
  options?: Readonly<{ applicationSecrets?: readonly string[] }>,
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

  const secretLabels = resolveApplicationSecretLabels(options);

  const derived = await derive(credentials, secretLabels);
  // The map is the caller's view; zeroing walks this function's own list, so a
  // callback that edits the map cannot keep an array from being cleared.
  const secrets: ReadonlyMap<string, Uint8Array> = new Map(derived.secrets);

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
    const result = useWallet(wallet, secrets);
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
    if (
      derived.secrets.length > 0 &&
      (result === secrets || sharesSecretMemory(result, derived.secrets))
    ) {
      throw new DerivationError(
        "Application secrets are zeroed when the callback returns; copy one inside the callback instead of returning it.",
        "wallet-scope-closed",
      );
    }
    return result;
  } finally {
    active = false;
    derived.seed.fill(0);
    for (const [, secret] of derived.secrets) secret.fill(0);
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
