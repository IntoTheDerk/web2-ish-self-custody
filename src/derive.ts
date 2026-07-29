import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes } from "@noble/hashes/utils.js";
import bs58 from "bs58";
import { canonicalizeContext, fingerprint, utf8 } from "./encoding.js";
import { DerivationError } from "./errors.js";
import {
  assertWalletPassword,
  normalizeDemocracyOsUsername,
  normalizeWeb2ishUsername,
} from "./normalization.js";
import { getProfile } from "./profiles.js";
import type {
  DemocracyOsCredentials,
  DerivationCredentials,
  DerivedPublicIdentity,
  DerivedWallet,
  Ed25519Identity,
  Secp256k1Identity,
  ZeraEd25519Credentials,
  ZeraEd25519ExternalSaltCredentials,
} from "./types.js";

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw new DerivationError("Wallet derivation was cancelled.", "aborted");
  }
}

function exactExternalSalt(salt: Uint8Array | undefined): Uint8Array {
  if (!(salt instanceof Uint8Array) || salt.byteLength !== 32) {
    throw new DerivationError(
      "This profile requires an exact 32-byte public derivation salt.",
      "invalid-salt",
    );
  }
  return Uint8Array.from(salt);
}

async function runScrypt(
  entropy: Uint8Array,
  salt: Uint8Array,
  credentials: DerivationCredentials,
): Promise<Uint8Array> {
  const profile = getProfile(credentials.profile);
  throwIfAborted(credentials.signal);
  let progressCallbackError: unknown;
  const output = await scryptAsync(entropy, salt, {
    N: profile.N,
    r: profile.r,
    p: profile.p,
    dkLen: profile.dkLen,
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

async function deriveDemocracyOs(
  credentials: DemocracyOsCredentials,
): Promise<{ seed: Uint8Array; identity: Secp256k1Identity }> {
  if (credentials.context !== undefined) {
    throw new DerivationError(
      "The DemocracyOS compatibility profile does not accept derivation context.",
      "invalid-context",
    );
  }
  assertWalletPassword(credentials.password, 12);
  const normalizedUsername = normalizeDemocracyOsUsername(credentials.username);
  const password = Uint8Array.from(credentials.password);
  const salt = exactExternalSalt(credentials.salt);
  let passwordEntropyHash: Uint8Array | undefined;
  let walletEntropy: Uint8Array | undefined;
  let seed: Uint8Array | undefined;

  try {
    passwordEntropyHash = sha512(
      concatBytes(
        utf8("DemocracyOS password wallet password hash v2\n"),
        password,
      ),
    );
    walletEntropy = sha512(
      utf8(
        `DemocracyOS password wallet entropy v2\n${normalizedUsername}\n${bytesToHex(passwordEntropyHash)}`,
      ),
    );
    seed = await runScrypt(walletEntropy, salt, credentials);
    throwIfAborted(credentials.signal);
    if (!secp256k1.utils.isValidSecretKey(seed)) {
      throw new DerivationError(
        "The deterministic secp256k1 output was not a valid scalar.",
        "invalid-wallet-seed",
      );
    }

    const publicKeyBytes = secp256k1.getPublicKey(seed, true);
    const publicKey = bytesToHex(publicKeyBytes);
    const address = `zera:${bytesToHex(sha256(publicKeyBytes).slice(0, 20))}`;
    return {
      seed,
      identity: Object.freeze({
        profileId: "democracyos-scrypt-sha512-secp256k1-v2",
        curve: "secp256k1",
        normalizedUsername,
        address,
        publicKey,
        publicKeyBytes: Uint8Array.from(publicKeyBytes),
        fingerprint: fingerprint(address),
      }),
    };
  } catch (error) {
    seed?.fill(0);
    throw error;
  } finally {
    password.fill(0);
    salt.fill(0);
    passwordEntropyHash?.fill(0);
    walletEntropy?.fill(0);
  }
}

async function deriveWeb2ishEd25519(
  credentials: ZeraEd25519Credentials,
): Promise<{ seed: Uint8Array; identity: Ed25519Identity }> {
  if (credentials.salt !== undefined) {
    throw new DerivationError(
      "The stateless ZERA profile derives its public salt and does not accept an external salt.",
      "invalid-salt",
    );
  }
  assertWalletPassword(credentials.password, 24);
  const normalizedUsername = normalizeWeb2ishUsername(credentials.username);
  const context = canonicalizeContext(credentials.context);
  const password = Uint8Array.from(credentials.password);
  let passwordEntropyHash: Uint8Array | undefined;
  let walletEntropy: Uint8Array | undefined;
  let salt: Uint8Array | undefined;
  let seed: Uint8Array | undefined;

  try {
    passwordEntropyHash = sha512(
      concatBytes(
        utf8("web2-ish-self-custody password hash v1\n"),
        password,
      ),
    );
    walletEntropy = sha512(
      utf8(
        [
          "web2-ish-self-custody ZERA Ed25519 entropy v1",
          context.applicationId,
          context.networkId,
          normalizedUsername,
          bytesToHex(passwordEntropyHash),
        ].join("\n"),
      ),
    );
    salt = sha256(
      utf8(
        [
          "web2-ish-self-custody public username salt v1",
          context.applicationId,
          context.networkId,
          normalizedUsername,
        ].join("\n"),
      ),
    );
    seed = await runScrypt(walletEntropy, salt, credentials);
    throwIfAborted(credentials.signal);
    const publicKeyBytes = ed25519.getPublicKey(seed);
    const address = bs58.encode(publicKeyBytes);
    const publicKey = `A_${address}`;

    return {
      seed,
      identity: Object.freeze({
        profileId: "web2ish-zera-ed25519-v1",
        curve: "ed25519",
        normalizedUsername,
        address,
        publicKey,
        publicKeyBytes: Uint8Array.from(publicKeyBytes),
        fingerprint: fingerprint(address),
      }),
    };
  } catch (error) {
    seed?.fill(0);
    throw error;
  } finally {
    password.fill(0);
    passwordEntropyHash?.fill(0);
    walletEntropy?.fill(0);
    salt?.fill(0);
  }
}

async function deriveWeb2ishExternalSaltEd25519(
  credentials: ZeraEd25519ExternalSaltCredentials,
): Promise<{ seed: Uint8Array; identity: Ed25519Identity }> {
  assertWalletPassword(credentials.password, 24);
  const normalizedUsername = normalizeWeb2ishUsername(credentials.username);
  const context = canonicalizeContext(credentials.context);
  const password = Uint8Array.from(credentials.password);
  const salt = exactExternalSalt(credentials.salt);
  let passwordEntropyHash: Uint8Array | undefined;
  let walletEntropy: Uint8Array | undefined;
  let seed: Uint8Array | undefined;

  try {
    passwordEntropyHash = sha512(
      concatBytes(
        utf8("web2-ish-self-custody password hash v1\n"),
        password,
      ),
    );
    walletEntropy = sha512(
      utf8(
        [
          "web2-ish-self-custody ZERA Ed25519 external salt entropy v1",
          context.applicationId,
          context.networkId,
          normalizedUsername,
          bytesToHex(passwordEntropyHash),
        ].join("\n"),
      ),
    );
    seed = await runScrypt(walletEntropy, salt, credentials);
    throwIfAborted(credentials.signal);
    const publicKeyBytes = ed25519.getPublicKey(seed);
    const address = bs58.encode(publicKeyBytes);
    const publicKey = `A_${address}`;

    return {
      seed,
      identity: Object.freeze({
        profileId: "web2ish-zera-ed25519-external-salt-v1",
        curve: "ed25519",
        normalizedUsername,
        address,
        publicKey,
        publicKeyBytes: Uint8Array.from(publicKeyBytes),
        fingerprint: fingerprint(address),
      }),
    };
  } catch (error) {
    seed?.fill(0);
    throw error;
  } finally {
    password.fill(0);
    salt.fill(0);
    passwordEntropyHash?.fill(0);
    walletEntropy?.fill(0);
  }
}

export async function withDerivedWallet<T>(
  credentials: DerivationCredentials,
  useWallet: (wallet: DerivedWallet) => T,
): Promise<T> {
  if (!(credentials.password instanceof Uint8Array)) {
    throw new DerivationError("Password input must be a Uint8Array.", "invalid-password");
  }

  const derived =
    credentials.profile === "democracyos-scrypt-sha512-secp256k1-v2"
      ? await deriveDemocracyOs(credentials)
      : credentials.profile === "web2ish-zera-ed25519-v1"
        ? await deriveWeb2ishEd25519(credentials)
        : credentials.profile === "web2ish-zera-ed25519-external-salt-v1"
          ? await deriveWeb2ishExternalSaltEd25519(credentials)
        : (() => {
            throw new DerivationError("Unknown deterministic wallet profile.", "invalid-profile");
          })();

  let active = true;
  const assertActive = () => {
    if (!active) {
      throw new DerivationError(
        "The derived wallet is no longer available outside its callback scope.",
        "wallet-scope-closed",
      );
    }
  };

  const wallet: DerivedWallet =
    derived.identity.curve === "ed25519"
      ? Object.freeze({
          identity: derived.identity,
          signExactMessageUnsafe(message: Uint8Array) {
            assertActive();
            if (!(message instanceof Uint8Array) || message.byteLength === 0 || message.byteLength > 1_048_576) {
              throw new DerivationError("Message must contain 1–1,048,576 bytes.", "invalid-message");
            }
            return ed25519.sign(message, derived.seed);
          },
        })
      : Object.freeze({
          identity: derived.identity,
          signDemocracyOsChallengeDigest(digest: Uint8Array) {
            assertActive();
            if (!(digest instanceof Uint8Array) || digest.byteLength !== 32) {
              throw new DerivationError("secp256k1 signing requires an exact 32-byte digest.", "invalid-digest");
            }
            // DemocracyOS web v2 calls @noble/secp256k1 signAsync with its
            // default SHA-256 prehash behavior. Preserve that behavior exactly.
            return secp256k1.sign(digest, derived.seed, { format: "compact" });
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
): Promise<DerivedPublicIdentity> {
  return withDerivedWallet(credentials, (wallet) => {
    const identity = wallet.identity;
    return Object.freeze({
      ...identity,
      publicKeyBytes: Uint8Array.from(identity.publicKeyBytes),
    }) as DerivedPublicIdentity;
  });
}
