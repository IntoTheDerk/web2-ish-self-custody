import { ed25519 } from "@noble/curves/ed25519.js";
import { beforeAll, describe, expect, it } from "vitest";
import { derivePublicIdentity } from "../src/index.js";
import { zeraEd25519Codec, zeraEd25519ExternalSalt } from "../src/chains/zera.js";
import {
  WALLET_VAULT_FORMAT,
  createWalletVault,
  createWalletVaultFromCredentials,
  generateRecoveryCode,
  normalizeRecoveryCode,
  openWalletVaultWithPassword,
  openWalletVaultWithRecoveryCode,
  parseWalletVault,
  rewrapWalletVaultPassword,
  type WalletVault,
} from "../src/vault.js";

const encoder = new TextEncoder();
const username = "vault-user@example.com";
const walletPassword = encoder.encode("correct horse battery staple etc");
const vaultPassword = encoder.encode("vault unlock passphrase, long enough");
const newVaultPassword = encoder.encode("a different vault passphrase entirely");
const salt = new Uint8Array(32).fill(9);
const context = { applicationId: "democracy-os", networkId: "zera-mainnet" } as const;

const credentials = {
  profile: zeraEd25519ExternalSalt,
  username,
  password: walletPassword,
  context,
  salt,
} as const;

/** Deriving is expensive (scrypt N=65536), so everything reuses one enrolment. */
let derivedAddress: string;
let vault: WalletVault;
let recoveryCode: string;

beforeAll(async () => {
  derivedAddress = (await derivePublicIdentity({ ...credentials })).address;
  const created = await createWalletVaultFromCredentials(
    { ...credentials },
    vaultPassword,
  );
  vault = created.vault;
  recoveryCode = created.recoveryCode;
}, 120_000);

describe("recovery codes", () => {
  it("encodes 256 bits in the unambiguous alphabet", () => {
    const code = generateRecoveryCode();
    expect(code).toMatch(/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{1,4})+$/u);
    // I, O, 0 and 1 are the characters people mis-transcribe.
    expect(code).not.toMatch(/[IO01]/u);
    expect(code.replace(/-/gu, "").length).toBe(52);
  });

  it("never repeats across many draws", () => {
    const codes = new Set(Array.from({ length: 256 }, () => generateRecoveryCode()));
    expect(codes.size).toBe(256);
  });

  it("accepts any grouping or case the user types back", () => {
    const canonical = normalizeRecoveryCode(recoveryCode);
    for (const variant of [
      recoveryCode.toLowerCase(),
      recoveryCode.replace(/-/gu, ""),
      recoveryCode.replace(/-/gu, " "),
      ` ${recoveryCode}\n`,
    ]) {
      expect(normalizeRecoveryCode(variant)).toBe(canonical);
    }
  });

  it("rejects characters the alphabet excludes", () => {
    for (const bad of ["", "   ", `${recoveryCode}I`, `${recoveryCode}0`, "!!!!"]) {
      expect(() => normalizeRecoveryCode(bad)).toThrowError(
        expect.objectContaining({ code: "invalid-recovery-code" }),
      );
    }
  });
});

describe("vault round trip", () => {
  it("preserves the address the credentials already derived", () => {
    expect(vault.address).toBe(derivedAddress);
    expect(vault.format).toBe(WALLET_VAULT_FORMAT);
    expect(vault.profileId).toBe(zeraEd25519ExternalSalt.id);
    expect(vault.codecId).toBe(zeraEd25519Codec.id);
  });

  it("stores no plaintext secret", () => {
    const serialized = JSON.stringify(vault);
    expect(serialized).not.toContain("correct horse");
    expect(serialized).not.toContain("vault unlock");
    expect(serialized).not.toContain(normalizeRecoveryCode(recoveryCode));
  });

  it("opens with the password and signs as the same wallet", async () => {
    const message = encoder.encode("vault signing check");
    const result = await openWalletVaultWithPassword(
      vault,
      vaultPassword,
      zeraEd25519Codec,
      (wallet) => ({
        address: wallet.identity.address,
        publicKeyBytes: wallet.identity.publicKeyBytes,
        signature: wallet.signExactMessageUnsafe(message),
      }),
    );
    expect(result.address).toBe(derivedAddress);
    expect(ed25519.verify(result.signature, message, result.publicKeyBytes)).toBe(true);
  }, 120_000);

  it("opens with the recovery code without the password", async () => {
    const address = await openWalletVaultWithRecoveryCode(
      vault,
      recoveryCode,
      zeraEd25519Codec,
      (wallet) => wallet.identity.address,
    );
    expect(address).toBe(derivedAddress);
  }, 120_000);

  it("closes the wallet scope when the callback returns", async () => {
    let escaped: { signExactMessageUnsafe: (m: Uint8Array) => Uint8Array } | undefined;
    await openWalletVaultWithRecoveryCode(vault, recoveryCode, zeraEd25519Codec, (wallet) => {
      escaped = wallet;
      return null;
    });
    expect(() => escaped?.signExactMessageUnsafe(encoder.encode("later"))).toThrowError(
      expect.objectContaining({ code: "wallet-scope-closed" }),
    );
  }, 120_000);
});

describe("vault rejects the wrong secret or a tampered envelope", () => {
  it("rejects a wrong password and a wrong recovery code identically", async () => {
    await expect(
      openWalletVaultWithPassword(
        vault,
        encoder.encode("not the vault passphrase at all!!"),
        zeraEd25519Codec,
        () => null,
      ),
    ).rejects.toThrowError(expect.objectContaining({ code: "vault-authentication-failed" }));

    await expect(
      openWalletVaultWithRecoveryCode(vault, generateRecoveryCode(), zeraEd25519Codec, () => null),
    ).rejects.toThrowError(expect.objectContaining({ code: "vault-authentication-failed" }));
  }, 120_000);

  it("rejects a relabelled envelope, because the identity is authenticated", async () => {
    for (const field of ["address", "publicKey", "profileId", "codecId", "applicationId"] as const) {
      const tampered = { ...vault, [field]: `${vault[field]}x` };
      await expect(
        openWalletVaultWithRecoveryCode(
          tampered as WalletVault,
          recoveryCode,
          zeraEd25519Codec,
          () => null,
        ),
      ).rejects.toThrowError(expect.objectContaining({ code: "vault-authentication-failed" }));
    }
  }, 120_000);

  it("rejects tampered ciphertext", async () => {
    const flip = (hex: string) => `${hex.slice(0, -1)}${hex.at(-1) === "a" ? "b" : "a"}`;
    const tampered = {
      ...vault,
      recovery: { ...vault.recovery, ciphertextHex: flip(vault.recovery.ciphertextHex) },
    };
    await expect(
      openWalletVaultWithRecoveryCode(tampered, recoveryCode, zeraEd25519Codec, () => null),
    ).rejects.toThrowError(expect.objectContaining({ code: "vault-authentication-failed" }));
  }, 120_000);

  it("rejects a malformed envelope before doing any key work", () => {
    expect(() => parseWalletVault(null)).toThrowError(
      expect.objectContaining({ code: "invalid-vault" }),
    );
    expect(() => parseWalletVault({ ...vault, format: "something-else" })).toThrowError(
      expect.objectContaining({ code: "invalid-vault" }),
    );
    expect(() => parseWalletVault({ ...vault, seed: { ivHex: "zz", ciphertextHex: "aa" } })).toThrowError(
      expect.objectContaining({ code: "invalid-vault" }),
    );
  });
});

describe("changing the password keeps the wallet", () => {
  it("re-wraps without changing the address, and retires only the old password", async () => {
    const rotated = await rewrapWalletVaultPassword(
      vault,
      { password: vaultPassword },
      newVaultPassword,
      recoveryCode,
    );

    // The whole point: a password change is no longer a wallet change.
    expect(rotated.address).toBe(derivedAddress);

    expect(
      await openWalletVaultWithPassword(
        rotated,
        newVaultPassword,
        zeraEd25519Codec,
        (w) => w.identity.address,
      ),
    ).toBe(derivedAddress);

    // The already-written-down recovery code must keep working, or the kit
    // would be invalidated by an ordinary password change.
    expect(
      await openWalletVaultWithRecoveryCode(
        rotated,
        recoveryCode,
        zeraEd25519Codec,
        (w) => w.identity.address,
      ),
    ).toBe(derivedAddress);

    await expect(
      openWalletVaultWithPassword(rotated, vaultPassword, zeraEd25519Codec, () => null),
    ).rejects.toThrowError(expect.objectContaining({ code: "vault-authentication-failed" }));
  }, 180_000);

  it("re-wraps from the recovery code when the password is forgotten", async () => {
    const rotated = await rewrapWalletVaultPassword(
      vault,
      { recoveryCode },
      newVaultPassword,
      recoveryCode,
    );
    expect(rotated.address).toBe(derivedAddress);
    expect(
      await openWalletVaultWithPassword(
        rotated,
        newVaultPassword,
        zeraEd25519Codec,
        (w) => w.identity.address,
      ),
    ).toBe(derivedAddress);
  }, 180_000);
});

describe("createWalletVault input validation", () => {
  it("holds a vault password to the same floor as a derivation password", async () => {
    // Nine characters, and 36 bytes: the floor counts characters, not bytes.
    for (const shortPassword of [encoder.encode("too-short"), encoder.encode("🔐".repeat(9))]) {
      await expect(
        createWalletVault({
          profile: zeraEd25519ExternalSalt,
          context,
          username,
          password: shortPassword,
          seed: new Uint8Array(32).fill(3),
        }),
      ).rejects.toThrowError(expect.objectContaining({ code: "invalid-password" }));
      await expect(
        rewrapWalletVaultPassword(vault, { recoveryCode }, shortPassword, recoveryCode),
      ).rejects.toThrowError(expect.objectContaining({ code: "invalid-password" }));
    }
  });

  it("requires a 32-byte seed", async () => {
    await expect(
      createWalletVault({
        profile: zeraEd25519ExternalSalt,
        context,
        username,
        password: vaultPassword,
        seed: new Uint8Array(31),
      }),
    ).rejects.toThrowError(expect.objectContaining({ code: "invalid-seed" }));
  });
});
