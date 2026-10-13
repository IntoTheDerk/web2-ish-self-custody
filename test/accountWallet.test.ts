import { describe, expect, it } from "vitest";
import { createRandomAccountWallet, withAccountWallet, openWalletVaultWithPassword, openWalletVaultWithRecoveryCode, rewrapWalletVaultPassword, parseWalletVault, type AccountWalletSetup } from "../src/index.js";
import { kalvoraEd25519ExternalSalt as profile } from "../src/chains/kalvora.js";

const password = new TextEncoder().encode("correct horse battery staple");
const setup: AccountWalletSetup = {
  accountId: "8464f4fc-8082-4dab-9d18-a9c191f0173b", mode: "per-account-deterministic",
  profileId: profile.id, codecId: profile.codec.id, applicationId: "example-app",
  networkId: "kalvora-testnet", normalizedUsername: "alice", publicSaltHex: "1a".repeat(32),
};

describe("account wallet options", () => {
  it("reconstructs across devices, isolates equal credentials, and changes with the password", async () => {
    const original = await withAccountWallet(setup, profile, password, w => w.identity.address);
    const restored: AccountWalletSetup = JSON.parse(JSON.stringify(setup));
    expect(await withAccountWallet(restored, profile, password, w => w.identity.address)).toBe(original);
    expect(await withAccountWallet({ ...setup, publicSaltHex: "2b".repeat(32) }, profile, password, w => w.identity.address)).not.toBe(original);
    expect(await withAccountWallet(setup, profile, new TextEncoder().encode("a different strong password"), w => w.identity.address)).not.toBe(original);
  });

  it("generates independent random wallets and keeps one through password recovery", async () => {
    const randomSetup = { ...setup, mode: "random-vault" as const };
    const first = await createRandomAccountWallet(randomSetup, profile, password);
    const second = await createRandomAccountWallet(randomSetup, profile, password);
    expect(first.vault.address).not.toBe(second.vault.address);
    const restored: unknown = JSON.parse(JSON.stringify(first.vault));
    expect(await openWalletVaultWithRecoveryCode(parseWalletVault(restored), first.recoveryCode, profile.codec, w => w.identity.address)).toBe(first.vault.address);
    const nextPassword = new TextEncoder().encode("a different strong password");
    const updated = await rewrapWalletVaultPassword(first.vault, { recoveryCode: first.recoveryCode }, nextPassword, first.recoveryCode);
    expect(await openWalletVaultWithPassword(updated, nextPassword, profile.codec, w => w.identity.address)).toBe(first.vault.address);
    await expect(openWalletVaultWithPassword(updated, password, profile.codec, () => null)).rejects.toMatchObject({ code: "vault-authentication-failed" });
  });

  it("rejects mismatched profiles and prevents accidental mode fallback", async () => {
    expect(() => withAccountWallet({ ...setup, profileId: "unknown" }, profile, password, () => null)).toThrow();
    expect(() => withAccountWallet({ ...setup, mode: "random-vault" }, profile, password, () => null)).toThrow();
    await expect(createRandomAccountWallet(setup, profile, password)).rejects.toMatchObject({ code: "invalid-profile" });
  });
});
