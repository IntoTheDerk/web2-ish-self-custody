import { ed25519 } from "@noble/curves/ed25519.js";
import bs58 from "bs58";
import {
  KEY_TYPE,
  deriveHDPrivateKey,
  generateKalvoraAddress,
  generateKalvoraPublicKeyIdentifier,
} from "kalvora.js/wallet";
import { defineIdentityCodec, type IdentityCodec } from "../codec.js";
import { fingerprint } from "../encoding.js";
import { DerivationError } from "../errors.js";
import {
  defineDerivationProfile,
  type DerivationProfile,
  type KeyDerivation,
} from "../profile.js";
import { deriveIdentityFromSeed, type SeedIdentity } from "../seed.js";

const base58Address = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/u;
const ED25519_PUBLIC_KEY_BYTES = 32;
const MASTER_SEED_BYTES = 32;
const ED25519_KEY_BYTES = 32;
/** The signer's bounds, the same as `withDerivedWallet`'s. */
const MAXIMUM_MESSAGE_BYTES = 1_048_576;

/**
 * `%TypedArray%.prototype`'s own getters. Called on an array, they read its
 * internal slots, so neither a subclass nor an own property can change what
 * they report.
 */
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const typedArrayTagGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  Symbol.toStringTag,
)?.get;
const typedArrayByteLengthGetter = Object.getOwnPropertyDescriptor(
  typedArrayPrototype,
  "byteLength",
)?.get;

/**
 * A plain Uint8Array, of this realm or another: the exact typed-array tag, and
 * a prototype that is some realm's `Uint8Array.prototype`. That prototype's own
 * prototype is the realm's `%TypedArray%.prototype`, the one object on the
 * chain with an own `Symbol.toStringTag` accessor. A subclass, Buffer included,
 * puts one more prototype in between, so it fails.
 */
function isPlainUint8Array(value: unknown): value is Uint8Array {
  if (!ArrayBuffer.isView(value) || typedArrayTagGetter?.call(value) !== "Uint8Array") {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype === Uint8Array.prototype) return true;
  if (typeof prototype !== "object" || prototype === null) return false;
  const parent: unknown = Object.getPrototypeOf(prototype);
  return (
    typeof parent === "object" &&
    parent !== null &&
    typeof Object.getOwnPropertyDescriptor(parent, Symbol.toStringTag)?.get === "function"
  );
}

/**
 * Kalvora support is provided by kalvora.js: key derivation and address
 * encoding call `kalvora.js/wallet`, so a password wallet here is exactly the
 * wallet kalvora.js derives from the same seed. That entry point has no
 * network or protobuf code. kalvora.js is an optional peer dependency, needed
 * only by this module.
 */

/** Kalvora's registered SLIP-44 coin type. */
export const KALVORA_SLIP44_COIN_TYPE = 5258;

/**
 * The path every Kalvora password wallet is derived at: kalvora.js's first
 * wallet, account 0, change 0, address 0, all hardened.
 *
 * Pinned here rather than read from kalvora.js, because it is part of this
 * profile's definition: a kalvora.js release that moved its default path must
 * not move existing password wallets with it.
 */
export const KALVORA_DERIVATION_PATH = "m/44'/5258'/0'/0'/0'";

/**
 * Kalvora's Ed25519 convention, encoded by kalvora.js: the address is the
 * base58 of the raw public key, and the wire identifier is that address behind
 * an `A_` tag. Decoding stays local and strict, accepting only that exact
 * form.
 */
export const kalvoraEd25519Codec: IdentityCodec = defineIdentityCodec({
  id: "kalvora-ed25519-base58-v1",

  encodeAddress(publicKeyBytes) {
    return generateKalvoraAddress(Uint8Array.from(publicKeyBytes), KEY_TYPE.ED25519);
  },

  encodePublicKey(publicKeyBytes) {
    return generateKalvoraPublicKeyIdentifier(Uint8Array.from(publicKeyBytes), KEY_TYPE.ED25519);
  },

  decodePublicKey(identifier) {
    const trimmed = identifier.trim();
    if (!trimmed.startsWith("A_")) {
      throw new DerivationError(
        "Kalvora Ed25519 public keys must use the A_<base58> identifier form.",
        "invalid-public-key",
      );
    }

    const encoded = trimmed.slice(trimmed.lastIndexOf("_") + 1);
    if (!base58Address.test(encoded)) {
      throw new DerivationError(
        "Kalvora Ed25519 public key is not valid base58.",
        "invalid-public-key",
      );
    }

    let decoded: Uint8Array;
    try {
      decoded = bs58.decode(encoded);
    } catch {
      throw new DerivationError(
        "Kalvora Ed25519 public key is not valid base58.",
        "invalid-public-key",
      );
    }
    if (decoded.length !== ED25519_PUBLIC_KEY_BYTES) {
      throw new DerivationError(
        "Kalvora Ed25519 public keys must be 32 bytes.",
        "invalid-public-key",
      );
    }
    return decoded;
  },
});

/**
 * SLIP-0010 Ed25519 at `KALVORA_DERIVATION_PATH`, computed by kalvora.js. The
 * scrypt output is the SLIP-0010 master seed.
 */
export const kalvoraSlip10Ed25519: KeyDerivation = Object.freeze({
  id: `slip10-ed25519:${KALVORA_DERIVATION_PATH}`,
  deriveKey(masterSeed: Uint8Array): Uint8Array {
    return deriveHDPrivateKey(masterSeed, KALVORA_DERIVATION_PATH, KEY_TYPE.ED25519);
  },
});

/**
 * Service-salted: the caller supplies a 32-byte salt the service owns. The
 * scrypt output is a SLIP-0010 master seed, and the wallet key is its node at
 * `KALVORA_DERIVATION_PATH`, so coin type 5258 is part of every key and the
 * wallet is the one kalvora.js derives from that seed.
 *
 * Every string below is fixed wire surface — including the trailing newline on
 * the password-hash domain, which is concatenated with the raw password bytes
 * rather than line-joined. Editing any of them, or the path, redefines every
 * wallet derived under this profile, so a change belongs in a new profile id,
 * never here.
 */
export const kalvoraEd25519ExternalSalt: DerivationProfile = defineDerivationProfile({
  id: "web2ish-kalvora-ed25519-external-salt-v1",
  curve: "ed25519",
  algorithm: "scrypt-sha512-slip10-ed25519-external-32-v1",
  saltPolicy: "external-32",
  kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
  domains: {
    passwordHash: "web2-ish-self-custody password hash v1\n",
    entropy: "web2-ish-self-custody Kalvora Ed25519 external salt entropy v1",
  },
  keyDerivation: kalvoraSlip10Ed25519,
  codec: kalvoraEd25519Codec,
});

/** The bundled Kalvora profiles, keyed by id, for resolving a stored profile id. */
export const kalvoraProfiles: Readonly<Record<string, DerivationProfile>> = Object.freeze({
  [kalvoraEd25519ExternalSalt.id]: kalvoraEd25519ExternalSalt,
});

/**
 * Kalvora identity for an application-owned random 32-byte Ed25519 key, for
 * wallets that are not password-derived. The seed is used as the private key
 * directly, with no SLIP-0010 step. Storage, encryption, and recovery stay
 * with the caller.
 */
export function deriveKalvoraEd25519IdentityFromSeed(seed: Uint8Array): SeedIdentity {
  return deriveIdentityFromSeed(seed, kalvoraEd25519Codec);
}

/**
 * A Kalvora wallet opened from a 32-byte SLIP-0010 master seed by
 * {@link withKalvoraWalletFromMasterSeed}. `identity.derivation` is
 * `kalvoraSlip10Ed25519.id`, the step that produced the key; there is no
 * profile id, because no password derivation ran here.
 */
export type KalvoraMasterSeedWallet = Readonly<{
  identity: Readonly<{
    derivation: string;
    codecId: string;
    curve: "ed25519";
    address: string;
    publicKey: string;
    publicKeyBytes: Uint8Array;
    fingerprint: string;
  }>;
  /**
   * Signs the exact bytes given (1 to 1,048,576 of them), with no framing or
   * prehashing, as `withDerivedWallet`'s signer does. Throws
   * `wallet-scope-closed` once the callback has returned.
   */
  signExactMessageUnsafe: (message: Uint8Array) => Uint8Array;
}>;

/**
 * Opens the Kalvora wallet of a 32-byte SLIP-0010 master seed, hands it to
 * `useWallet`, and zeroes the key on the way out.
 *
 * The wallet key is `kalvoraSlip10Ed25519.deriveKey(masterSeed)`, the node at
 * `KALVORA_DERIVATION_PATH` that kalvora.js derives, encoded with
 * `kalvoraEd25519Codec`: the same key step and codec as the Kalvora password
 * profile, over a master seed the caller supplies instead of a scrypt output.
 * The intended seed is an application secret of a password derivation, such as
 * one under the sign-in profile (docs/PROTOCOL.md#kalvora-wallet-from-a-master-seed),
 * or that secret restored from the application's own encrypted backup.
 *
 * Synchronous on purpose, so it can run inside a `withDerivedWallet` callback,
 * and so the key's lifetime stays bounded:
 *
 * - `masterSeed` must be a plain `Uint8Array` of exactly 32 bytes, or this
 *   throws `invalid-seed` before deriving anything. Plain means the exact
 *   typed-array tag, as `deriveIdentityFromSeed` requires, and a prototype that
 *   is a realm's `Uint8Array.prototype`: a genuine Uint8Array from another
 *   realm is accepted, and a Buffer or any other subclass is refused. The length
 *   and the bytes are read from the array's internal slots, never through a
 *   `byteLength` property or an iterator that a subclass or an own property
 *   could replace. The caller keeps ownership of it and zeroes it; this works on
 *   an internal copy and clears that copy.
 * - A seed of 32 zero bytes is refused with `invalid-seed` too. It is what an
 *   application secret holds once its `withDerivedWallet` scope has ended and
 *   the SDK has zeroed it, and its wallet's key is public knowledge. An honest
 *   HMAC output is all-zero with probability 2^-256.
 * - The node key is zeroed when the callback returns or throws, and the signer
 *   then throws `wallet-scope-closed`.
 * - A callback that returns a thenable fails with `async-wallet-scope`, and the
 *   key is zeroed all the same.
 */
export function withKalvoraWalletFromMasterSeed<T>(
  masterSeed: Uint8Array,
  useWallet: (wallet: KalvoraMasterSeedWallet) => T,
): T {
  if (
    !isPlainUint8Array(masterSeed) ||
    typedArrayByteLengthGetter?.call(masterSeed) !== MASTER_SEED_BYTES
  ) {
    throw new DerivationError(
      "A Kalvora wallet master seed must be a plain Uint8Array of exactly 32 bytes.",
      "invalid-seed",
    );
  }

  // `set` with a typed-array source copies from its internal slots.
  const ownedSeed = new Uint8Array(MASTER_SEED_BYTES);
  ownedSeed.set(masterSeed);
  let key: Uint8Array | undefined;
  try {
    // Every byte is read, with no early exit, so the check's timing does not
    // depend on where the first non-zero byte is.
    let anyBit = 0;
    for (let index = 0; index < MASTER_SEED_BYTES; index += 1) anyBit |= ownedSeed[index]!;
    if (anyBit === 0) {
      throw new DerivationError(
        "A Kalvora wallet master seed of 32 zero bytes is a zeroed secret, not a seed.",
        "invalid-seed",
      );
    }
    key = kalvoraSlip10Ed25519.deriveKey(ownedSeed);
  } finally {
    ownedSeed.fill(0);
  }

  let active = true;
  try {
    if (!(key instanceof Uint8Array) || key.byteLength !== ED25519_KEY_BYTES) {
      throw new DerivationError(
        `Key derivation "${kalvoraSlip10Ed25519.id}" must return exactly 32 bytes.`,
        "invalid-profile",
      );
    }
    const walletKey = key;
    const publicKeyBytes = ed25519.getPublicKey(walletKey);
    const address = kalvoraEd25519Codec.encodeAddress(publicKeyBytes);
    const wallet: KalvoraMasterSeedWallet = Object.freeze({
      identity: Object.freeze({
        derivation: kalvoraSlip10Ed25519.id,
        codecId: kalvoraEd25519Codec.id,
        curve: "ed25519" as const,
        address,
        publicKey: kalvoraEd25519Codec.encodePublicKey(publicKeyBytes),
        publicKeyBytes: Uint8Array.from(publicKeyBytes),
        fingerprint: fingerprint(address),
      }),
      signExactMessageUnsafe(message: Uint8Array) {
        if (!active) {
          throw new DerivationError(
            "The Kalvora wallet is no longer available outside its callback scope.",
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
        return ed25519.sign(message, walletKey);
      },
    });

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
    if (key instanceof Uint8Array) key.fill(0);
  }
}
