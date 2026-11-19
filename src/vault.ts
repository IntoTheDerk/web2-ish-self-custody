import { ed25519 } from "@noble/curves/ed25519.js";
import { scryptAsync } from "@noble/hashes/scrypt.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { IdentityCodec } from "./codec.js";
import { deriveWalletSeedUnsafe } from "./derive.js";
import { fingerprint } from "./encoding.js";
import { DerivationError } from "./errors.js";
import { assertWalletPassword, normalizeUsername } from "./normalization.js";
import type { DerivationProfile } from "./profile.js";
import type {
  DerivationContext,
  DerivationCredentials,
  DerivedIdentity,
  DerivedWallet,
} from "./types.js";

/**
 * A wallet vault: the seed at rest, under two independent wrappers.
 *
 * Deterministic derivation alone cannot survive a password change -- the wallet
 * IS a function of the password, so a new password is a new wallet. A vault
 * breaks that coupling. One random data key encrypts the seed; that data key is
 * wrapped separately by a password-derived key and by a recovery code. Changing
 * the password re-wraps the data key and leaves the seed, and therefore the
 * address, untouched.
 *
 * What this does NOT change: nobody can open a vault without one of the two
 * secrets. A host that stores vaults holds ciphertext it cannot read, and a
 * user who loses both the password and the recovery code has lost the wallet.
 *
 * Storing a password-wrapped blob is not the concession it looks like. Under
 * deterministic derivation an attacker who learns a public address can already
 * grind candidate passwords offline and compare the derived address, so the
 * password was always exposed to offline attack by anyone holding public
 * material. See SECURITY.md.
 */

export const WALLET_VAULT_FORMAT = "web2-ish-self-custody-wallet-vault-v1";
const AAD_DOMAIN = "web2-ish-self-custody wallet vault aad v1";
const RECOVERY_INFO = "web2-ish-self-custody wallet vault recovery key v1";
const PASSWORD_INFO = "web2-ish-self-custody wallet vault password key v1";

/**
 * The v2 envelope: the same seed and password wrapper, and a set of recovery
 * codes instead of one. Each code wraps the same data key in its own slot, and
 * v2 keeps that data key across changes, so a new password leaves every code
 * working and codes can be replaced without the password. v1 is unchanged.
 */
export const WALLET_VAULT_FORMAT_V2 = "web2-ish-self-custody-wallet-vault-v2";
export const MAX_RECOVERY_CODES = 10;
export const DEFAULT_RECOVERY_CODE_COUNT = 5;
const AAD_DOMAIN_V2 = "web2-ish-self-custody wallet vault aad v2";
const RECOVERY_SLOT_AAD = "recovery slot";
const RECOVERY_INFO_V2 = "web2-ish-self-custody wallet vault recovery key v2";

const SEED_BYTES = 32;
const DATA_KEY_BYTES = 32;
const SALT_BYTES = 32;
const IV_BYTES = 12;
const RECOVERY_CODE_BYTES = 32;

/**
 * 32 symbols, chosen so a handwritten code cannot be misread: I, O, 0 and 1 are
 * all absent. Exactly five bits per character, so 32 bytes encode without
 * padding.
 */
const RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const RECOVERY_GROUP = 4;

export type SealedBox = Readonly<{ ivHex: string; ciphertextHex: string }>;

export type WalletVault = Readonly<{
  format: typeof WALLET_VAULT_FORMAT;
  version: 1;
  profileId: string;
  codecId: string;
  applicationId: string;
  networkId: string;
  normalizedUsername: string;
  address: string;
  publicKey: string;
  /** The seed, under the random data key. */
  seed: SealedBox;
  /** The data key, under a key stretched from the password. */
  password: Readonly<{
    kdf: Readonly<{ N: number; r: number; p: number; dkLen: number }>;
    saltHex: string;
  }> &
    SealedBox;
  /** The data key, under a key derived from the recovery code. */
  recovery: Readonly<{ saltHex: string }> & SealedBox;
}>;

/**
 * One recovery code's wrapper of the data key. `hint` is the code's first
 * group, public so a person can tell their codes apart and retire one.
 */
export type RecoverySlot = Readonly<{ hint: string; saltHex: string }> & SealedBox;

export type WalletVaultV2 = Readonly<
  Omit<WalletVault, "format" | "version" | "recovery"> & {
    format: typeof WALLET_VAULT_FORMAT_V2;
    version: 2;
    /** The data key, once per recovery code: 1 to MAX_RECOVERY_CODES slots. */
    recovery: readonly RecoverySlot[];
  }
>;

export type AnyWalletVault = WalletVault | WalletVaultV2;

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * A 256-bit recovery code, grouped for transcription.
 *
 * Always generated here and never chosen by a user: the recovery wrapper does
 * no password stretching, which is only safe because this input is full
 * entropy.
 */
export function generateRecoveryCode(): string {
  const bytes = randomBytes(RECOVERY_CODE_BYTES);
  try {
    let bits = 0;
    let accumulator = 0;
    let encoded = "";
    for (const byte of bytes) {
      accumulator = (accumulator << 8) | byte;
      bits += 8;
      while (bits >= 5) {
        bits -= 5;
        encoded += RECOVERY_ALPHABET[(accumulator >>> bits) & 31];
      }
    }
    if (bits > 0) {
      encoded += RECOVERY_ALPHABET[(accumulator << (5 - bits)) & 31];
    }
    return (encoded.match(new RegExp(`.{1,${RECOVERY_GROUP}}`, "gu")) ?? []).join("-");
  } finally {
    bytes.fill(0);
  }
}

/** Accepts any grouping or case; rejects characters the alphabet excludes. */
export function normalizeRecoveryCode(code: string): string {
  const normalized = code.replace(/[\s-]+/gu, "").toUpperCase();
  if (normalized.length === 0) {
    throw new DerivationError("A recovery code is required.", "invalid-recovery-code");
  }
  for (const character of normalized) {
    if (!RECOVERY_ALPHABET.includes(character)) {
      throw new DerivationError(
        "The recovery code contains characters that are not part of the code alphabet.",
        "invalid-recovery-code",
      );
    }
  }
  return normalized;
}

/** The public first group of a code: what a v2 slot is labelled with. */
export function recoveryCodeHint(code: string): string {
  const normalized = normalizeRecoveryCode(code);
  if (normalized.length < RECOVERY_GROUP) {
    throw new DerivationError("The recovery code is too short.", "invalid-recovery-code");
  }
  return normalized.slice(0, RECOVERY_GROUP);
}

function assertRecoveryCodeCount(count: number): number {
  if (!Number.isInteger(count) || count < 1 || count > MAX_RECOVERY_CODES) {
    throw new DerivationError(
      `A vault holds between 1 and ${MAX_RECOVERY_CODES} recovery codes.`,
      "invalid-recovery-code",
    );
  }
  return count;
}

/** A set of codes for one v2 vault. Hints are distinct, so each code names one slot. */
export function generateRecoveryCodes(count: number = DEFAULT_RECOVERY_CODE_COUNT): string[] {
  assertRecoveryCodeCount(count);
  const codes = new Map<string, string>();
  while (codes.size < count) {
    const code = generateRecoveryCode();
    const hint = recoveryCodeHint(code);
    if (!codes.has(hint)) codes.set(hint, code);
  }
  return [...codes.values()];
}

/** The hints of a vault's recovery codes. A v1 vault has one unlabelled code, so none. */
export function recoveryCodeHints(vault: AnyWalletVault): string[] {
  return vault.version === 2 ? vault.recovery.map((slot) => slot.hint) : [];
}

function recoveryCodeBytes(code: string): Uint8Array {
  const normalized = normalizeRecoveryCode(code);
  const bytes: number[] = [];
  let bits = 0;
  let accumulator = 0;
  for (const character of normalized) {
    accumulator = (accumulator << 5) | RECOVERY_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >>> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

/**
 * The bytes every wrapper authenticates.
 *
 * Binding the identity into the AAD means a vault cannot be re-labelled: swap
 * the address, the profile, or the codec and every open fails, rather than
 * silently yielding a wallet that is not the one the envelope claims.
 */
function additionalData(header: AnyVaultHeader): Uint8Array {
  return new TextEncoder().encode(
    [
      header.version === 2 ? AAD_DOMAIN_V2 : AAD_DOMAIN,
      header.format,
      String(header.version),
      header.profileId,
      header.codecId,
      header.applicationId,
      header.networkId,
      header.normalizedUsername,
      header.address,
      header.publicKey,
    ].join("\n"),
  );
}

/** A slot's own AAD: the header plus its hint, so a slot cannot be relabelled or moved. */
function slotAdditionalData(header: VaultHeaderV2, hint: string): Uint8Array {
  const base = additionalData(header);
  const suffix = new TextEncoder().encode(`\n${RECOVERY_SLOT_AAD}\n${hint}`);
  const aad = new Uint8Array(base.byteLength + suffix.byteLength);
  aad.set(base);
  aad.set(suffix, base.byteLength);
  return aad;
}

async function aesKey(raw: Uint8Array, usage: KeyUsage): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, [usage]);
}

async function seal(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<SealedBox> {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad as BufferSource },
      await aesKey(key, "encrypt"),
      plaintext as BufferSource,
    ),
  );
  return Object.freeze({ ivHex: bytesToHex(iv), ciphertextHex: bytesToHex(ciphertext) });
}

async function open(
  key: Uint8Array,
  box: SealedBox,
  aad: Uint8Array,
  failure: string,
): Promise<Uint8Array> {
  try {
    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: hexToBytes(box.ivHex) as BufferSource,
          additionalData: aad as BufferSource,
        },
        await aesKey(key, "decrypt"),
        hexToBytes(box.ciphertextHex) as BufferSource,
      ),
    );
  } catch {
    // One message for a wrong secret and for a tampered envelope: telling them
    // apart would confirm which half of a stolen vault an attacker had guessed.
    throw new DerivationError(failure, "vault-authentication-failed");
  }
}

async function recoveryKey(
  code: string,
  salt: Uint8Array,
  info: string = RECOVERY_INFO,
): Promise<Uint8Array> {
  const ikm = recoveryCodeBytes(code);
  try {
    const material = await globalThis.crypto.subtle.importKey(
      "raw",
      ikm as BufferSource,
      "HKDF",
      false,
      ["deriveBits"],
    );
    return new Uint8Array(
      await globalThis.crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: salt as BufferSource,
          info: new TextEncoder().encode(info) as BufferSource,
        },
        material,
        DATA_KEY_BYTES * 8,
      ),
    );
  } finally {
    ikm.fill(0);
  }
}

/** Stretched at the profile's own scrypt cost, because a password is not full entropy. */
async function passwordKey(
  password: Uint8Array,
  salt: Uint8Array,
  kdf: WalletVault["password"]["kdf"],
): Promise<Uint8Array> {
  const material = await scryptAsync(password, salt, {
    N: kdf.N,
    r: kdf.r,
    p: kdf.p,
    dkLen: kdf.dkLen,
  });
  const info = new TextEncoder().encode(PASSWORD_INFO);
  try {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      material as BufferSource,
      "HKDF",
      false,
      ["deriveBits"],
    );
    return new Uint8Array(
      await globalThis.crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: salt as BufferSource,
          info: info as BufferSource,
        },
        key,
        DATA_KEY_BYTES * 8,
      ),
    );
  } finally {
    material.fill(0);
  }
}

type VaultHeader = Omit<WalletVault, "seed" | "password" | "recovery">;
type VaultHeaderV2 = Omit<WalletVaultV2, "seed" | "password" | "recovery">;
type AnyVaultHeader = VaultHeader | VaultHeaderV2;

/**
 * Seals a seed into a vault from an already-decided header.
 *
 * Both creation and password re-wrap go through here, so the two can never
 * disagree about what is authenticated or how the wrappers are built.
 */
async function sealVault(params: {
  header: VaultHeader;
  kdf: WalletVault["password"]["kdf"];
  seed: Uint8Array;
  password: Uint8Array;
  recoveryCode: string;
}): Promise<WalletVault> {
  const aad = additionalData(params.header);
  const dataKey = randomBytes(DATA_KEY_BYTES);
  const passwordSalt = randomBytes(SALT_BYTES);
  const recoverySalt = randomBytes(SALT_BYTES);
  let passwordWrapKey: Uint8Array | undefined;
  let recoveryWrapKey: Uint8Array | undefined;

  try {
    passwordWrapKey = await passwordKey(params.password, passwordSalt, params.kdf);
    recoveryWrapKey = await recoveryKey(params.recoveryCode, recoverySalt);

    return Object.freeze({
      ...params.header,
      seed: await seal(dataKey, params.seed, aad),
      password: Object.freeze({
        kdf: Object.freeze({ ...params.kdf }),
        saltHex: bytesToHex(passwordSalt),
        ...(await seal(passwordWrapKey, dataKey, aad)),
      }),
      recovery: Object.freeze({
        saltHex: bytesToHex(recoverySalt),
        ...(await seal(recoveryWrapKey, dataKey, aad)),
      }),
    });
  } finally {
    dataKey.fill(0);
    passwordWrapKey?.fill(0);
    recoveryWrapKey?.fill(0);
  }
}

async function sealPassword(
  dataKey: Uint8Array,
  password: Uint8Array,
  kdf: WalletVault["password"]["kdf"],
  aad: Uint8Array,
): Promise<WalletVault["password"]> {
  const salt = randomBytes(SALT_BYTES);
  const key = await passwordKey(password, salt, kdf);
  try {
    return Object.freeze({
      kdf: Object.freeze({ ...kdf }),
      saltHex: bytesToHex(salt),
      ...(await seal(key, dataKey, aad)),
    });
  } finally {
    key.fill(0);
  }
}

/** One slot per code, each under its own salt, all wrapping the same data key. */
async function sealRecoverySlots(
  dataKey: Uint8Array,
  header: VaultHeaderV2,
  recoveryCodes: readonly string[],
): Promise<readonly RecoverySlot[]> {
  const slots: RecoverySlot[] = [];
  for (const code of recoveryCodes) {
    const hint = recoveryCodeHint(code);
    const salt = randomBytes(SALT_BYTES);
    const key = await recoveryKey(code, salt, RECOVERY_INFO_V2);
    try {
      slots.push(
        Object.freeze({
          hint,
          saltHex: bytesToHex(salt),
          ...(await seal(key, dataKey, slotAdditionalData(header, hint))),
        }),
      );
    } finally {
      key.fill(0);
    }
  }
  return Object.freeze(slots);
}

async function sealVaultV2(params: {
  header: VaultHeaderV2;
  kdf: WalletVault["password"]["kdf"];
  seed: Uint8Array;
  password: Uint8Array;
  recoveryCodeCount: number;
}): Promise<{ vault: WalletVaultV2; recoveryCodes: string[] }> {
  const recoveryCodes = generateRecoveryCodes(params.recoveryCodeCount);
  const aad = additionalData(params.header);
  const dataKey = randomBytes(DATA_KEY_BYTES);
  try {
    const vault: WalletVaultV2 = Object.freeze({
      ...params.header,
      seed: await seal(dataKey, params.seed, aad),
      password: await sealPassword(dataKey, params.password, params.kdf, aad),
      recovery: await sealRecoverySlots(dataKey, params.header, recoveryCodes),
    });
    return { vault, recoveryCodes };
  } finally {
    dataKey.fill(0);
  }
}

function scopedWallet(seed: Uint8Array, identity: DerivedIdentity): {
  wallet: DerivedWallet;
  close: () => void;
} {
  let active = true;
  const wallet: DerivedWallet = Object.freeze({
    identity,
    signExactMessageUnsafe(message: Uint8Array) {
      if (!active) {
        throw new DerivationError(
          "The vault wallet is no longer available outside its callback scope.",
          "wallet-scope-closed",
        );
      }
      if (!(message instanceof Uint8Array) || message.byteLength === 0) {
        throw new DerivationError("Message must contain at least one byte.", "invalid-message");
      }
      return ed25519.sign(message, seed);
    },
  });
  return {
    wallet,
    close: () => {
      active = false;
    },
  };
}

export type CreateWalletVaultOptions = Readonly<{
  profile: DerivationProfile;
  context: DerivationContext;
  username: string;
  /** The password that will open the vault. Zeroed by the caller, not here. */
  password: Uint8Array;
  /** The wallet seed to protect. Copied; the caller keeps ownership. */
  seed: Uint8Array;
  /** Supply one only to re-seal an existing kit; otherwise a fresh code is minted. */
  recoveryCode?: string;
}>;

/** The validation and identity fields both formats share; the caller owns and zeroes `seed`. */
function newVaultIdentity(options: Omit<CreateWalletVaultOptions, "recoveryCode">): {
  seed: Uint8Array;
  identity: Omit<VaultHeader, "format" | "version">;
} {
  if (!(options.seed instanceof Uint8Array) || options.seed.byteLength !== SEED_BYTES) {
    throw new DerivationError("A wallet seed must contain exactly 32 bytes.", "invalid-seed");
  }
  assertWalletPassword(options.password);
  const normalizedUsername = normalizeUsername(options.username);
  const applicationId = options.context.applicationId.trim().toLowerCase();
  const networkId = options.context.networkId.trim().toLowerCase();

  const seed = Uint8Array.from(options.seed);
  try {
    const publicKeyBytes = ed25519.getPublicKey(seed);
    return {
      seed,
      identity: {
        profileId: options.profile.id,
        codecId: options.profile.codec.id,
        applicationId,
        networkId,
        normalizedUsername,
        address: options.profile.codec.encodeAddress(publicKeyBytes),
        publicKey: options.profile.codec.encodePublicKey(publicKeyBytes),
      },
    };
  } catch (error) {
    seed.fill(0);
    throw error;
  }
}

export async function createWalletVault(
  options: CreateWalletVaultOptions,
): Promise<{ vault: WalletVault; recoveryCode: string }> {
  const { seed, identity } = newVaultIdentity(options);
  try {
    const recoveryCode = options.recoveryCode ?? generateRecoveryCode();
    const vault = await sealVault({
      header: { format: WALLET_VAULT_FORMAT, version: 1, ...identity },
      kdf: options.profile.kdf,
      seed,
      password: options.password,
      recoveryCode,
    });
    return { vault, recoveryCode };
  } finally {
    seed.fill(0);
  }
}

/**
 * Seals a seed into a v2 vault with a set of recovery codes.
 *
 * Every code opens the wallet and none is spent by use: they are spare keys to
 * keep in separate places, not one-time codes. Show them once.
 */
export async function createWalletVaultWithRecoveryCodes(
  options: Omit<CreateWalletVaultOptions, "recoveryCode"> &
    Readonly<{ recoveryCodeCount?: number }>,
): Promise<{ vault: WalletVaultV2; recoveryCodes: string[] }> {
  const count = assertRecoveryCodeCount(options.recoveryCodeCount ?? DEFAULT_RECOVERY_CODE_COUNT);
  const { seed, identity } = newVaultIdentity(options);
  try {
    return await sealVaultV2({
      header: { format: WALLET_VAULT_FORMAT_V2, version: 2, ...identity },
      kdf: options.profile.kdf,
      seed,
      password: options.password,
      recoveryCodeCount: count,
    });
  } finally {
    seed.fill(0);
  }
}

/**
 * Enrols an existing deterministic wallet into a vault.
 *
 * The seed is derived, sealed, and zeroed without ever leaving this function,
 * so the address a user already has is preserved while becoming
 * password-independent from here on.
 */
export async function createWalletVaultFromCredentials(
  credentials: DerivationCredentials,
  vaultPassword: Uint8Array,
  recoveryCode?: string,
): Promise<{ vault: WalletVault; recoveryCode: string }> {
  const derived = await deriveWalletSeedUnsafe(credentials);
  try {
    return await createWalletVault({
      profile: credentials.profile,
      context: credentials.context,
      username: credentials.username,
      password: vaultPassword,
      seed: derived.seed,
      ...(recoveryCode === undefined ? {} : { recoveryCode }),
    });
  } finally {
    derived.seed.fill(0);
  }
}

type VaultUnlock = { password: Uint8Array } | { recoveryCode: string };

async function openDataKey(vault: AnyWalletVault, unlock: VaultUnlock): Promise<Uint8Array> {
  const aad = additionalData(vault);
  if ("password" in unlock) {
    const key = await passwordKey(unlock.password, hexToBytes(vault.password.saltHex), vault.password.kdf);
    try {
      return await open(key, vault.password, aad, "The vault password is incorrect.");
    } finally {
      key.fill(0);
    }
  }
  if (vault.version === 2) {
    const { seed: _seed, password: _password, recovery, ...header } = vault;
    const hint = recoveryCodeHint(unlock.recoveryCode);
    const slot = recovery.find((candidate) => candidate.hint === hint);
    if (slot === undefined) {
      // Hints are public in the envelope, so answering "no such slot" early
      // tells a holder of the vault nothing; the error still matches a wrong code.
      throw new DerivationError("The recovery code is incorrect.", "vault-authentication-failed");
    }
    const slotKey = await recoveryKey(unlock.recoveryCode, hexToBytes(slot.saltHex), RECOVERY_INFO_V2);
    try {
      return await open(
        slotKey,
        slot,
        slotAdditionalData(header, hint),
        "The recovery code is incorrect.",
      );
    } finally {
      slotKey.fill(0);
    }
  }
  const key = await recoveryKey(unlock.recoveryCode, hexToBytes(vault.recovery.saltHex));
  try {
    return await open(key, vault.recovery, aad, "The recovery code is incorrect.");
  } finally {
    key.fill(0);
  }
}

async function withVaultSeed<T>(
  vault: AnyWalletVault,
  unlock: VaultUnlock,
  codec: IdentityCodec,
  useWallet: (wallet: DerivedWallet) => T,
): Promise<T> {
  const parsed = parseWalletVault(vault);
  let dataKey: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  try {
    dataKey = await openDataKey(parsed, unlock);
    seed = await open(dataKey, parsed.seed, additionalData(parsed), "The vault is unreadable.");
    if (seed.byteLength !== SEED_BYTES) {
      throw new DerivationError("The vault does not contain a 32-byte seed.", "invalid-seed");
    }

    // The AAD already binds the address, but recomputing it proves the sealed
    // seed is the one this envelope names rather than trusting the label.
    const publicKeyBytes = ed25519.getPublicKey(seed);
    if (codec.encodeAddress(publicKeyBytes) !== parsed.address) {
      throw new DerivationError(
        "The vault seed does not produce the address the vault claims.",
        "vault-identity-mismatch",
      );
    }

    const identity: DerivedIdentity = Object.freeze({
      profileId: parsed.profileId,
      codecId: parsed.codecId,
      curve: "ed25519" as const,
      normalizedUsername: parsed.normalizedUsername,
      address: parsed.address,
      publicKey: parsed.publicKey,
      publicKeyBytes: Uint8Array.from(publicKeyBytes),
      fingerprint: fingerprint(parsed.address),
    });

    const scope = scopedWallet(seed, identity);
    try {
      const result = useWallet(scope.wallet);
      if (
        typeof result === "object" &&
        result !== null &&
        "then" in result &&
        typeof (result as { then?: unknown }).then === "function"
      ) {
        throw new DerivationError(
          "Vault callbacks must be synchronous so secret lifetime stays bounded.",
          "async-wallet-scope",
        );
      }
      return result;
    } finally {
      scope.close();
    }
  } finally {
    dataKey?.fill(0);
    seed?.fill(0);
  }
}

export function openWalletVaultWithPassword<T>(
  vault: AnyWalletVault,
  password: Uint8Array,
  codec: IdentityCodec,
  useWallet: (wallet: DerivedWallet) => T,
): Promise<T> {
  return withVaultSeed(vault, { password }, codec, useWallet);
}

export function openWalletVaultWithRecoveryCode<T>(
  vault: AnyWalletVault,
  recoveryCode: string,
  codec: IdentityCodec,
  useWallet: (wallet: DerivedWallet) => T,
): Promise<T> {
  return withVaultSeed(vault, { recoveryCode }, codec, useWallet);
}

/**
 * Re-wraps the data key under a new password, leaving the seed and therefore
 * the address unchanged. This is the whole point of the vault: a password
 * change stops being a wallet change.
 *
 * The recovery wrapper is rebuilt too, so the previously issued code keeps
 * working -- reissuing a code the user has already written down would defeat
 * the kit.
 */
export async function rewrapWalletVaultPassword(
  vault: WalletVault,
  unlock: { password: Uint8Array } | { recoveryCode: string },
  newPassword: Uint8Array,
  recoveryCode: string,
): Promise<WalletVault> {
  const parsed = parseWalletVaultV1(vault);
  assertWalletPassword(newPassword);
  let dataKey: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  try {
    dataKey = await openDataKey(parsed, unlock);
    seed = await open(dataKey, parsed.seed, additionalData(parsed), "The vault is unreadable.");

    // The header carries forward untouched, which is exactly why the address
    // survives a password change.
    const { seed: _seed, password: _password, recovery: _recovery, ...header } = parsed;
    return await sealVault({
      header,
      kdf: parsed.password.kdf,
      seed,
      password: newPassword,
      recoveryCode,
    });
  } finally {
    dataKey?.fill(0);
    seed?.fill(0);
  }
}

/**
 * Moves a vault onto a fresh set of recovery codes, sealed from scratch as v2.
 *
 * This is the path from v1 to v2, and the path for someone who forgot the
 * password but holds a code: `unlock` opens the vault, `password` is what the
 * result opens with. The seed and address are unchanged; the data key is new,
 * so no earlier code opens the returned vault.
 */
export async function upgradeWalletVaultRecoveryCodes(
  vault: AnyWalletVault,
  unlock: VaultUnlock,
  password: Uint8Array,
  recoveryCodeCount: number = DEFAULT_RECOVERY_CODE_COUNT,
): Promise<{ vault: WalletVaultV2; recoveryCodes: string[] }> {
  const parsed = parseWalletVault(vault);
  assertWalletPassword(password);
  const count = assertRecoveryCodeCount(recoveryCodeCount);
  let dataKey: Uint8Array | undefined;
  let seed: Uint8Array | undefined;
  try {
    dataKey = await openDataKey(parsed, unlock);
    seed = await open(dataKey, parsed.seed, additionalData(parsed), "The vault is unreadable.");
    const {
      seed: _seed,
      password: _password,
      recovery: _recovery,
      format: _format,
      version: _version,
      ...identity
    } = parsed;
    return await sealVaultV2({
      header: { format: WALLET_VAULT_FORMAT_V2, version: 2, ...identity },
      kdf: parsed.password.kdf,
      seed,
      password,
      recoveryCodeCount: count,
    });
  } finally {
    dataKey?.fill(0);
    seed?.fill(0);
  }
}

/**
 * Replaces every recovery code of a v2 vault with a fresh set.
 *
 * The data key, the sealed seed and the password wrapper are kept, so the
 * password is neither needed nor changed: any current code is enough.
 */
export async function replaceWalletVaultRecoveryCodes(
  vault: WalletVaultV2,
  unlock: VaultUnlock,
  recoveryCodeCount: number = DEFAULT_RECOVERY_CODE_COUNT,
): Promise<{ vault: WalletVaultV2; recoveryCodes: string[] }> {
  const parsed = parseWalletVaultV2(vault);
  const recoveryCodes = generateRecoveryCodes(recoveryCodeCount);
  let dataKey: Uint8Array | undefined;
  try {
    dataKey = await openDataKey(parsed, unlock);
    const { seed: _seed, password: _password, recovery: _recovery, ...header } = parsed;
    const recovery = await sealRecoverySlots(dataKey, header, recoveryCodes);
    return { vault: Object.freeze({ ...parsed, recovery }), recoveryCodes };
  } finally {
    dataKey?.fill(0);
  }
}

/**
 * Retires one recovery code by its hint. No secret is involved: the slot is
 * dropped from this envelope. A copy of the vault kept from before still opens
 * with the retired code, so a platform must also stop serving the old copy.
 */
export function removeWalletVaultRecoveryCode(vault: WalletVaultV2, hint: string): WalletVaultV2 {
  const parsed = parseWalletVaultV2(vault);
  const recovery = parsed.recovery.filter((slot) => slot.hint !== hint);
  if (recovery.length === parsed.recovery.length) {
    throw new DerivationError("This vault has no recovery code with that hint.", "invalid-recovery-code");
  }
  if (recovery.length === 0) {
    throw new DerivationError(
      "A vault must keep at least one recovery code. Replace the set instead.",
      "invalid-recovery-code",
    );
  }
  return Object.freeze({ ...parsed, recovery: Object.freeze(recovery) });
}

/**
 * Re-wraps a v2 vault's data key under a new password. The data key, the
 * sealed seed and every recovery slot are kept, so all codes keep working.
 */
export async function rewrapWalletVaultPasswordV2(
  vault: WalletVaultV2,
  unlock: VaultUnlock,
  newPassword: Uint8Array,
): Promise<WalletVaultV2> {
  const parsed = parseWalletVaultV2(vault);
  assertWalletPassword(newPassword);
  let dataKey: Uint8Array | undefined;
  try {
    dataKey = await openDataKey(parsed, unlock);
    const password = await sealPassword(
      dataKey,
      newPassword,
      parsed.password.kdf,
      additionalData(parsed),
    );
    return Object.freeze({ ...parsed, password });
  } finally {
    dataKey?.fill(0);
  }
}

const hex = (length: number) => new RegExp(`^[0-9a-f]{${length * 2}}$`, "u");

function requireHex(value: unknown, bytes: number, field: string): string {
  if (typeof value !== "string" || !hex(bytes).test(value)) {
    throw new DerivationError(`Vault field "${field}" is malformed.`, "invalid-vault");
  }
  return value;
}

function requireBox(value: unknown, field: string): SealedBox {
  if (typeof value !== "object" || value === null) {
    throw new DerivationError(`Vault field "${field}" is malformed.`, "invalid-vault");
  }
  const box = value as Record<string, unknown>;
  const ciphertext = box["ciphertextHex"];
  if (typeof ciphertext !== "string" || !/^[0-9a-f]+$/u.test(ciphertext) || ciphertext.length < 32) {
    throw new DerivationError(`Vault field "${field}" is malformed.`, "invalid-vault");
  }
  return Object.freeze({
    ivHex: requireHex(box["ivHex"], IV_BYTES, `${field}.ivHex`),
    ciphertextHex: ciphertext,
  });
}

function requireText(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256) {
    throw new DerivationError(`Vault field "${field}" is malformed.`, "invalid-vault");
  }
  return value;
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new DerivationError(`Vault field "${field}" is malformed.`, "invalid-vault");
  }
  return value as Record<string, unknown>;
}

function requireVaultObject(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    throw new DerivationError("A wallet vault must be an object.", "invalid-vault");
  }
  return value as Record<string, unknown>;
}

/** The members both formats share, read after the format-specific checks. */
function parseSharedMembers(
  vault: Record<string, unknown>,
  passwordRecord: Record<string, unknown>,
): Omit<WalletVault, "format" | "version" | "recovery"> {
  const kdf = passwordRecord["kdf"] as Record<string, unknown> | undefined;
  if (
    typeof kdf !== "object" ||
    kdf === null ||
    typeof kdf["N"] !== "number" ||
    typeof kdf["r"] !== "number" ||
    typeof kdf["p"] !== "number" ||
    kdf["dkLen"] !== 32
  ) {
    throw new DerivationError('Vault field "password.kdf" is malformed.', "invalid-vault");
  }

  return {
    profileId: requireText(vault["profileId"], "profileId"),
    codecId: requireText(vault["codecId"], "codecId"),
    applicationId: requireText(vault["applicationId"], "applicationId"),
    networkId: requireText(vault["networkId"], "networkId"),
    normalizedUsername: requireText(vault["normalizedUsername"], "normalizedUsername"),
    address: requireText(vault["address"], "address"),
    publicKey: requireText(vault["publicKey"], "publicKey"),
    seed: requireBox(vault["seed"], "seed"),
    password: Object.freeze({
      kdf: Object.freeze({
        N: kdf["N"] as number,
        r: kdf["r"] as number,
        p: kdf["p"] as number,
        dkLen: 32,
      }),
      saltHex: requireHex(passwordRecord["saltHex"], SALT_BYTES, "password.saltHex"),
      ...requireBox(passwordRecord, "password"),
    }),
  };
}

/** Strict parse of the v1 envelope: one recovery wrapper. */
export function parseWalletVaultV1(value: unknown): WalletVault {
  const vault = requireVaultObject(value);
  if (vault["format"] !== WALLET_VAULT_FORMAT || vault["version"] !== 1) {
    throw new DerivationError("Unsupported wallet vault format.", "invalid-vault");
  }
  const passwordRecord = requireRecord(vault["password"], "password");
  const recoveryRecord = requireRecord(vault["recovery"], "recovery");
  return Object.freeze({
    format: WALLET_VAULT_FORMAT,
    version: 1,
    ...parseSharedMembers(vault, passwordRecord),
    recovery: Object.freeze({
      saltHex: requireHex(recoveryRecord["saltHex"], SALT_BYTES, "recovery.saltHex"),
      ...requireBox(recoveryRecord, "recovery"),
    }),
  });
}

const RECOVERY_HINT = new RegExp(`^[${RECOVERY_ALPHABET}]{${RECOVERY_GROUP}}$`, "u");

/** Strict parse of the v2 envelope: 1 to MAX_RECOVERY_CODES slots with distinct hints. */
export function parseWalletVaultV2(value: unknown): WalletVaultV2 {
  const vault = requireVaultObject(value);
  if (vault["format"] !== WALLET_VAULT_FORMAT_V2 || vault["version"] !== 2) {
    throw new DerivationError("Unsupported wallet vault format.", "invalid-vault");
  }
  const passwordRecord = requireRecord(vault["password"], "password");
  const slots = vault["recovery"];
  if (!Array.isArray(slots) || slots.length < 1 || slots.length > MAX_RECOVERY_CODES) {
    throw new DerivationError('Vault field "recovery" is malformed.', "invalid-vault");
  }
  const hints = new Set<string>();
  const recovery = slots.map((value: unknown, index): RecoverySlot => {
    const field = `recovery[${index}]`;
    const slot = requireRecord(value, field);
    const hint = slot["hint"];
    if (typeof hint !== "string" || !RECOVERY_HINT.test(hint) || hints.has(hint)) {
      throw new DerivationError(`Vault field "${field}.hint" is malformed.`, "invalid-vault");
    }
    hints.add(hint);
    return Object.freeze({
      hint,
      saltHex: requireHex(slot["saltHex"], SALT_BYTES, `${field}.saltHex`),
      ...requireBox(slot, field),
    });
  });
  return Object.freeze({
    format: WALLET_VAULT_FORMAT_V2,
    version: 2,
    ...parseSharedMembers(vault, passwordRecord),
    recovery: Object.freeze(recovery),
  });
}

/** Strict parse, so a vault from storage is validated before any key work. */
export function parseWalletVault(value: unknown): AnyWalletVault {
  return requireVaultObject(value)["version"] === 2
    ? parseWalletVaultV2(value)
    : parseWalletVaultV1(value);
}
