import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import signInVector from "../vectors/sign-in-ed25519-external-salt-v1.json" with { type: "json" };
import { createRandomAccountWallet, withAccountWallet, withDerivedWallet, openWalletVaultWithPassword, openWalletVaultWithRecoveryCode, rewrapWalletVaultPassword, parseWalletVault, signInEd25519ExternalSalt, type AccountWalletSetup } from "../src/index.js";
import { kalvoraEd25519ExternalSalt as profile, withKalvoraWalletFromMasterSeed } from "../src/chains/kalvora.js";

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

describe("account wallet modes with application secrets and the sign-in profile", () => {
  const walletSeedLabel = signInVector.kalvoraWallet.masterSeedLabel;
  // The committed sign-in vector, with its salt as the account's salt: a
  // per-account setup changes who owns the salt, not the derivation.
  const signInSetup: AccountWalletSetup = {
    accountId: "0f4c2a51-7d3e-4b8a-9c61-2e5f7a9b3d10", mode: "per-account-deterministic",
    profileId: signInEd25519ExternalSalt.id, codecId: signInEd25519ExternalSalt.codec.id,
    applicationId: signInVector.applicationId, networkId: signInVector.networkId,
    normalizedUsername: signInVector.normalizedUsername, publicSaltHex: signInVector.saltHex,
  };
  const signInPassword = new TextEncoder().encode(signInVector.passwordUtf8);
  const vectorSecret = (label: string) =>
    signInVector.applicationSecrets.secrets.find((entry) => entry.label === label)!.secretHex;

  it("forwards applicationSecrets, matching a direct derivation with the account salt", async () => {
    const labels = ["example-secret-v1", "example-secret-v2"];
    const read = (_: unknown, secrets: ReadonlyMap<string, Uint8Array>) =>
      labels.map((label) => bytesToHex(secrets.get(label)!));
    const viaSetup = await withAccountWallet(setup, profile, password, read, { applicationSecrets: labels });
    const direct = await withDerivedWallet({
      profile, password, username: setup.normalizedUsername,
      context: { applicationId: setup.applicationId, networkId: setup.networkId },
      salt: hexToBytes(setup.publicSaltHex),
    }, read, { applicationSecrets: labels });
    expect(viaSetup).toEqual(direct);
    expect(new Set(viaSetup).size).toBe(2);
    expect(await withAccountWallet(setup, profile, password, (_wallet, secrets) => secrets.size)).toBe(0);
    await expect(withAccountWallet(setup, profile, password, () => null, { applicationSecrets: ["NOT A LABEL"] }))
      .rejects.toMatchObject({ code: "invalid-secret-label" });
  });

  it("derives the sign-in key and its wallet from a per-account setup, as the committed vector", async () => {
    const result = await withAccountWallet(signInSetup, signInEd25519ExternalSalt, signInPassword, (signIn, secrets) => ({
      signIn: signIn.identity.publicKey,
      secret: bytesToHex(secrets.get(walletSeedLabel)!),
      wallet: withKalvoraWalletFromMasterSeed(secrets.get(walletSeedLabel)!, (wallet) => wallet.identity.address),
    }), { applicationSecrets: [walletSeedLabel] });
    expect(result).toEqual({
      signIn: signInVector.signInKey.publicKeyIdentifier,
      secret: vectorSecret(walletSeedLabel),
      wallet: signInVector.kalvoraWallet.address,
    });
  });

  it("refuses the sign-in profile in random-vault mode", async () => {
    await expect(createRandomAccountWallet({ ...signInSetup, mode: "random-vault" }, signInEd25519ExternalSalt, signInPassword))
      .rejects.toMatchObject({ code: "invalid-profile" });
  });
});
