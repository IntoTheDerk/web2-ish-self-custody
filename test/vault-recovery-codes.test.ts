import { ed25519 } from "@noble/curves/ed25519.js";
import { beforeAll, describe, expect, it } from "vitest";
import {
  DEFAULT_RECOVERY_CODE_COUNT,
  MAX_RECOVERY_CODES,
  WALLET_VAULT_FORMAT_V2,
  createRandomAccountWalletWithRecoveryCodes,
  createWalletVault,
  createWalletVaultWithRecoveryCodes,
  generateRecoveryCode,
  generateRecoveryCodes,
  openWalletVaultWithPassword,
  openWalletVaultWithRecoveryCode,
  parseWalletVault,
  parseWalletVaultV1,
  parseWalletVaultV2,
  recoveryCodeHint,
  recoveryCodeHints,
  removeWalletVaultRecoveryCode,
  replaceWalletVaultRecoveryCodes,
  rewrapWalletVaultPassword,
  rewrapWalletVaultPasswordV2,
  upgradeWalletVaultRecoveryCodes,
  type AccountWalletSetup,
  type AnyWalletVault,
  type WalletVault,
  type WalletVaultV2,
} from "../src/index.js";
import { kalvoraEd25519Codec, kalvoraEd25519ExternalSalt as profile } from "../src/chains/kalvora.js";

const encoder = new TextEncoder();
const username = "codes-user@example.com";
const password = encoder.encode("vault unlock passphrase, long enough");
const nextPassword = encoder.encode("a different vault passphrase entirely");
const context = { applicationId: "democracy-os", networkId: "kalvora-mainnet" } as const;
const seed = new Uint8Array(32).fill(7);
const address = kalvoraEd25519Codec.encodeAddress(ed25519.getPublicKey(seed));
const failed = { code: "vault-authentication-failed", message: "The recovery code is incorrect." };

const addressWithCode = (vault: AnyWalletVault, code: string) =>
  openWalletVaultWithRecoveryCode(vault, code, kalvoraEd25519Codec, (wallet) => wallet.identity.address);
const addressWithPassword = (vault: AnyWalletVault, secret: Uint8Array) =>
  openWalletVaultWithPassword(vault, secret, kalvoraEd25519Codec, (wallet) => wallet.identity.address);
/** A different code that still names the same slot: the second group changes, the hint does not. */
const sameHintWrongCode = (code: string) => `${code.slice(0, 5)}${code[5] === "A" ? "B" : "A"}${code.slice(6)}`;
const json = (value: unknown) => JSON.parse(JSON.stringify(value)) as Record<string, any>;

/** scrypt is expensive at the profile's cost, so the suite shares one vault of each format. */
let vault: WalletVaultV2;
let codes: string[];
let v1: { vault: WalletVault; recoveryCode: string };

beforeAll(async () => {
  ({ vault, recoveryCodes: codes } = await createWalletVaultWithRecoveryCodes({ profile, context, username, password, seed }));
  v1 = await createWalletVault({ profile, context, username, password, seed });
}, 120_000);

describe("recovery code sets", () => {
  it("generates the default count with distinct hints, within bounds", () => {
    const set = generateRecoveryCodes();
    expect(set).toHaveLength(DEFAULT_RECOVERY_CODE_COUNT);
    expect(new Set(set.map(recoveryCodeHint)).size).toBe(set.length);
    expect(generateRecoveryCodes(MAX_RECOVERY_CODES)).toHaveLength(MAX_RECOVERY_CODES);
    for (const count of [0, MAX_RECOVERY_CODES + 1, 1.5, Number.NaN]) {
      expect(() => generateRecoveryCodes(count)).toThrowError(expect.objectContaining({ code: "invalid-recovery-code" }));
    }
  });

  it("derives the hint from the first group in any case or grouping", () => {
    const code = codes[0]!;
    expect(recoveryCodeHint(code)).toBe(code.slice(0, 4));
    expect(recoveryCodeHint(code.toLowerCase().replace(/-/gu, " "))).toBe(code.slice(0, 4));
    expect(() => recoveryCodeHint("AB")).toThrowError(expect.objectContaining({ code: "invalid-recovery-code" }));
    expect(recoveryCodeHints(vault)).toEqual(codes.map(recoveryCodeHint));
    expect(recoveryCodeHints(v1.vault)).toEqual([]);
  });
});

describe("a v2 vault", () => {
  it("keeps the address, stores no plaintext and survives a JSON round trip", () => {
    expect(vault.format).toBe(WALLET_VAULT_FORMAT_V2);
    expect(vault.version).toBe(2);
    expect(vault.address).toBe(address);
    expect(vault.recovery).toHaveLength(DEFAULT_RECOVERY_CODE_COUNT);
    const serialized = JSON.stringify(vault);
    for (const code of codes) expect(serialized).not.toContain(code.replace(/-/gu, "").slice(4));
    expect(parseWalletVault(json(vault))).toEqual(vault);
    expect(parseWalletVaultV2(json(vault))).toEqual(vault);
  });

  it("opens with the password and with every code, as the same wallet", async () => {
    expect(await addressWithPassword(vault, password)).toBe(address);
    for (const code of codes) expect(await addressWithCode(vault, code.toLowerCase())).toBe(address);
  }, 120_000);

  it("fails identically for a wrong code, an unknown hint, another vault's code and a v1 code", async () => {
    const other = await createWalletVaultWithRecoveryCodes({ profile, context, username, password, seed, recoveryCodeCount: 1 });
    for (const code of [sameHintWrongCode(codes[0]!), generateRecoveryCode(), other.recoveryCodes[0]!, v1.recoveryCode]) {
      await expect(addressWithCode(vault, code)).rejects.toMatchObject(failed);
    }
    await expect(addressWithCode(other.vault, codes[0]!)).rejects.toMatchObject(failed);
  }, 120_000);

  it("rejects a tampered slot, a relabelled slot and a slot moved from another vault", async () => {
    const [first, second, ...rest] = vault.recovery;
    const flipped = first!.ciphertextHex.replace(/.$/u, first!.ciphertextHex.endsWith("0") ? "1" : "0");
    const tampered = { ...vault, recovery: [{ ...first!, ciphertextHex: flipped }, second!, ...rest] };
    await expect(addressWithCode(tampered, codes[0]!)).rejects.toMatchObject(failed);

    // The hint is authenticated, so a slot cannot answer to another code's name.
    const swapped = { ...vault, recovery: [{ ...first!, hint: second!.hint }, { ...second!, hint: first!.hint }, ...rest] };
    await expect(addressWithCode(swapped, codes[0]!)).rejects.toMatchObject(failed);
    await expect(addressWithCode(swapped, codes[1]!)).rejects.toMatchObject(failed);

    // The header is authenticated too: a slot lifted into another account's vault does not open it.
    const stranger = await createWalletVaultWithRecoveryCodes({ profile, context, username: "someone-else@example.com", password, seed, recoveryCodeCount: 1 });
    const moved = { ...stranger.vault, recovery: [first!] };
    await expect(addressWithCode(moved, codes[0]!)).rejects.toMatchObject(failed);
  }, 120_000);
});

describe("retiring and replacing codes", () => {
  it("removes one code by hint and keeps the rest", async () => {
    const hint = recoveryCodeHint(codes[2]!);
    const remaining = removeWalletVaultRecoveryCode(vault, hint);
    expect(recoveryCodeHints(remaining)).toEqual(recoveryCodeHints(vault).filter((value) => value !== hint));
    await expect(addressWithCode(remaining, codes[2]!)).rejects.toMatchObject(failed);
    expect(await addressWithCode(remaining, codes[0]!)).toBe(address);
    expect(await addressWithCode(remaining, codes[4]!)).toBe(address);
    // The original envelope is untouched: removal returns a new vault.
    expect(vault.recovery).toHaveLength(DEFAULT_RECOVERY_CODE_COUNT);
  });

  it("rejects an unknown hint and never removes the last code", () => {
    expect(() => removeWalletVaultRecoveryCode(vault, "ZZZZ")).toThrowError(expect.objectContaining({ code: "invalid-recovery-code" }));
    let single = vault;
    for (const hint of recoveryCodeHints(vault).slice(1)) single = removeWalletVaultRecoveryCode(single, hint);
    expect(single.recovery).toHaveLength(1);
    expect(() => removeWalletVaultRecoveryCode(single, single.recovery[0]!.hint)).toThrowError(expect.objectContaining({ code: "invalid-recovery-code" }));
  });

  it("replaces the whole set with only a code, keeping the password", async () => {
    const replaced = await replaceWalletVaultRecoveryCodes(vault, { recoveryCode: codes[1]! }, 3);
    expect(replaced.recoveryCodes).toHaveLength(3);
    expect(replaced.vault.recovery).toHaveLength(3);
    expect(replaced.vault.seed).toEqual(vault.seed);
    expect(replaced.vault.password).toEqual(vault.password);
    for (const code of codes) await expect(addressWithCode(replaced.vault, code)).rejects.toMatchObject(failed);
    for (const code of replaced.recoveryCodes) expect(await addressWithCode(replaced.vault, code)).toBe(address);
    expect(await addressWithPassword(replaced.vault, password)).toBe(address);
    await expect(replaceWalletVaultRecoveryCodes(vault, { recoveryCode: sameHintWrongCode(codes[1]!) })).rejects.toMatchObject(failed);
  }, 120_000);

  it("replaces the set with the password too", async () => {
    const replaced = await replaceWalletVaultRecoveryCodes(vault, { password });
    expect(replaced.recoveryCodes).toHaveLength(DEFAULT_RECOVERY_CODE_COUNT);
    expect(await addressWithCode(replaced.vault, replaced.recoveryCodes[4]!)).toBe(address);
  }, 120_000);
});

describe("changing a v2 password keeps every code", () => {
  it("re-wraps from a code, retires only the old password and leaves the slots alone", async () => {
    const changed = await rewrapWalletVaultPasswordV2(vault, { recoveryCode: codes[3]! }, nextPassword);
    expect(changed.recovery).toEqual(vault.recovery);
    expect(changed.seed).toEqual(vault.seed);
    expect(await addressWithPassword(changed, nextPassword)).toBe(address);
    await expect(addressWithPassword(changed, password)).rejects.toMatchObject({ code: "vault-authentication-failed" });
    for (const code of codes) expect(await addressWithCode(changed, code)).toBe(address);
  }, 120_000);

  it("re-wraps from the current password and holds the new one to the password floor", async () => {
    const changed = await rewrapWalletVaultPasswordV2(vault, { password }, nextPassword);
    expect(await addressWithPassword(changed, nextPassword)).toBe(address);
    await expect(rewrapWalletVaultPasswordV2(vault, { recoveryCode: codes[0]! }, encoder.encode("short"))).rejects.toMatchObject({ code: "invalid-password" });
  }, 120_000);
});

describe("moving a vault onto a fresh code set", () => {
  it("upgrades v1 with the password: same address, new codes, old code retired", async () => {
    const upgraded = await upgradeWalletVaultRecoveryCodes(v1.vault, { password }, password);
    expect(upgraded.vault.version).toBe(2);
    expect(upgraded.vault.address).toBe(address);
    expect(upgraded.recoveryCodes).toHaveLength(DEFAULT_RECOVERY_CODE_COUNT);
    await expect(addressWithCode(upgraded.vault, v1.recoveryCode)).rejects.toMatchObject(failed);
    for (const code of upgraded.recoveryCodes) expect(await addressWithCode(upgraded.vault, code)).toBe(address);
    expect(await addressWithPassword(upgraded.vault, password)).toBe(address);
    // v1 itself is untouched and still opens with its own code.
    expect(await addressWithCode(v1.vault, v1.recoveryCode)).toBe(address);
  }, 120_000);

  it("upgrades v1 with its recovery code and a new password", async () => {
    const upgraded = await upgradeWalletVaultRecoveryCodes(v1.vault, { recoveryCode: v1.recoveryCode }, nextPassword, 2);
    expect(upgraded.recoveryCodes).toHaveLength(2);
    expect(await addressWithPassword(upgraded.vault, nextPassword)).toBe(address);
    await expect(addressWithPassword(upgraded.vault, password)).rejects.toMatchObject({ code: "vault-authentication-failed" });
    await expect(addressWithCode(upgraded.vault, v1.recoveryCode)).rejects.toMatchObject(failed);
  }, 120_000);

  it("reseals v2 from a code when the password is forgotten", async () => {
    const reset = await upgradeWalletVaultRecoveryCodes(vault, { recoveryCode: codes[0]! }, nextPassword);
    expect(reset.vault.seed).not.toEqual(vault.seed);
    expect(await addressWithPassword(reset.vault, nextPassword)).toBe(address);
    for (const code of codes) await expect(addressWithCode(reset.vault, code)).rejects.toMatchObject(failed);
    await expect(upgradeWalletVaultRecoveryCodes(vault, { recoveryCode: codes[0]! }, nextPassword, 0)).rejects.toMatchObject({ code: "invalid-recovery-code" });
  }, 120_000);
});

describe("strict parsing of both formats", () => {
  it("rejects each malformed v2 shape before any key work", () => {
    const slot = json(vault.recovery[0]);
    const broken: Record<string, unknown>[] = [
      { ...json(vault), recovery: [] },
      { ...json(vault), recovery: Array.from({ length: MAX_RECOVERY_CODES + 1 }, (_, index) => ({ ...slot, hint: `AAA${"ABCDEFGHJKL"[index]}` })) },
      { ...json(vault), recovery: [slot, slot] },
      { ...json(vault), recovery: slot },
      { ...json(vault), recovery: [null] },
      { ...json(vault), version: 3 },
      { ...json(vault), version: 1 },
      { ...json(vault), format: "web2-ish-self-custody-wallet-vault-v3" },
      { ...json(vault), password: null },
      ...["abcd", "ABC", "ABCDE", "ABCI", "AB0D", 1234].map((hint) => ({ ...json(vault), recovery: [{ ...slot, hint }] })),
      { ...json(vault), recovery: [{ ...slot, saltHex: "00" }] },
      { ...json(vault), recovery: [{ ...slot, ivHex: "zz" }] },
      { ...json(vault), recovery: [{ hint: slot["hint"], saltHex: slot["saltHex"] }] },
    ];
    for (const value of broken) {
      expect(() => parseWalletVault(value)).toThrowError(expect.objectContaining({ code: "invalid-vault" }));
    }
  });

  it("keeps the formats apart", async () => {
    expect(parseWalletVault(json(v1.vault))).toEqual(v1.vault);
    expect(() => parseWalletVaultV1(json(vault))).toThrowError(expect.objectContaining({ code: "invalid-vault" }));
    expect(() => parseWalletVaultV2(json(v1.vault))).toThrowError(expect.objectContaining({ code: "invalid-vault" }));
    expect(() => parseWalletVault({ ...json(v1.vault), recovery: [json(vault.recovery[0])] })).toThrowError(expect.objectContaining({ code: "invalid-vault" }));
    // The v1 re-wrap would reissue a single code; it refuses a v2 vault rather than downgrade it.
    await expect(rewrapWalletVaultPassword(vault as unknown as WalletVault, { password }, nextPassword, v1.recoveryCode)).rejects.toMatchObject({ code: "invalid-vault" });
    expect(() => removeWalletVaultRecoveryCode(v1.vault as unknown as WalletVaultV2, "AAAA")).toThrowError(expect.objectContaining({ code: "invalid-vault" }));
  });
});

describe("random account wallets with a code set", () => {
  const setup: AccountWalletSetup = {
    accountId: "8464f4fc-8082-4dab-9d18-a9c191f0173b", mode: "random-vault",
    profileId: profile.id, codecId: profile.codec.id, applicationId: "example-app",
    networkId: "kalvora-testnet", normalizedUsername: "alice", publicSaltHex: "1a".repeat(32),
  };

  it("seals an independent random wallet under the requested number of codes", async () => {
    const first = await createRandomAccountWalletWithRecoveryCodes(setup, profile, password);
    const second = await createRandomAccountWalletWithRecoveryCodes(setup, profile, password, 2);
    expect(first.vault.version).toBe(2);
    expect(first.recoveryCodes).toHaveLength(DEFAULT_RECOVERY_CODE_COUNT);
    expect(second.recoveryCodes).toHaveLength(2);
    expect(first.vault.address).not.toBe(second.vault.address);
    expect(await addressWithCode(first.vault, first.recoveryCodes[4]!)).toBe(first.vault.address);
    await expect(createRandomAccountWalletWithRecoveryCodes({ ...setup, mode: "per-account-deterministic" }, profile, password))
      .rejects.toMatchObject({ code: "invalid-profile" });
  }, 120_000);
});
