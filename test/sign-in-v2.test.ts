import { ed25519 } from "@noble/curves/ed25519.js";
import { scrypt } from "@noble/hashes/scrypt.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import v1Vector from "../vectors/sign-in-ed25519-external-salt-v1.json" with { type: "json" };
import vector from "../vectors/sign-in-ed25519-external-salt-v2.json" with { type: "json" };
import { kalvoraEd25519ExternalSalt, withKalvoraWalletFromMasterSeed } from "../src/chains/kalvora.js";
import * as core from "../src/index.js";
import {
  createRandomAccountWallet,
  defineDerivationProfile,
  derivePublicIdentity,
  withAccountWallet,
  withDerivedWallet,
  type DerivationCredentials,
} from "../src/index.js";
import { resolveIdentityServiceConfig } from "../src/server/config.js";
import { identityMigrations } from "../src/server/migrations.js";
import {
  SIGN_IN_KEY_DOMAIN,
  signInEd25519Codec,
  signInEd25519ExternalSalt,
  signInEd25519ExternalSaltV2,
  signInHkdfEd25519,
} from "../src/signIn.js";

/**
 * Byte-identity guard and vector checks for the sign-in profile v2.
 *
 * As for v1 (sign-in.test.ts), every value pinned here defines a key and, through
 * the profile id in each application secret's `info`, every wallet an
 * application derives under this profile. If an assertion fails, the fix is a
 * new profile id, not a new expectation. The vector is reproduced
 * independently by scripts/verify_kalvora_external_salt_vector.py.
 */

const encoder = new TextEncoder();
const labels = vector.applicationSecrets.secrets.map((entry) => entry.label);
const credentials = {
  profile: signInEd25519ExternalSaltV2,
  username: vector.username,
  password: encoder.encode(vector.passwordUtf8),
  context: { applicationId: vector.applicationId, networkId: vector.networkId },
  salt: hexToBytes(vector.saltHex),
} as const satisfies DerivationCredentials;

/** scrypt at N=2^18 costs ~0.5-1.5 s per call, and these tests make several. */
const derivationTimeoutMs = 180_000;

function hexSecrets(secrets: ReadonlyMap<string, Uint8Array>): Record<string, string> {
  return Object.fromEntries([...secrets].map(([label, secret]) => [label, bytesToHex(secret)]));
}

describe("sign-in profile v2 constants", () => {
  it("pins the profile exactly, with v1's key step and codec", () => {
    expect(signInEd25519ExternalSaltV2.id).toBe("web2ish-sign-in-ed25519-external-salt-v2");
    expect(signInEd25519ExternalSaltV2.curve).toBe("ed25519");
    expect(signInEd25519ExternalSaltV2.algorithm).toBe(
      "scrypt-sha512-hkdf-sha256-ed25519-external-32-v2",
    );
    expect(signInEd25519ExternalSaltV2.saltPolicy).toBe("external-32");
    expect(signInEd25519ExternalSaltV2.kdf).toEqual({ N: 262_144, r: 8, p: 1, dkLen: 32 });
    expect(signInEd25519ExternalSaltV2.domains).toEqual({
      passwordHash: "web2-ish-self-custody sign-in password hash v2\n",
      entropy: "web2-ish-self-custody sign-in Ed25519 external salt entropy v2",
    });
    expect(signInEd25519ExternalSaltV2.domains.salt).toBeUndefined();
    expect(signInEd25519ExternalSaltV2.keyDerivation?.id).toBe("hkdf-sha256-sign-in-key-v1");
    expect(signInEd25519ExternalSaltV2.keyDerivation?.deriveKey).toBe(signInHkdfEd25519.deriveKey);
    expect(signInEd25519ExternalSaltV2.codec).toBe(signInEd25519Codec);

    expect(vector.profile).toBe(signInEd25519ExternalSaltV2.id);
    expect(vector.algorithm).toBe(signInEd25519ExternalSaltV2.algorithm);
    expect(vector.kdf).toEqual({ name: "scrypt", ...signInEd25519ExternalSaltV2.kdf });
    expect(vector.signInKey.keyDerivation).toBe(signInHkdfEd25519.id);
    expect(vector.signInKey.domain).toBe(SIGN_IN_KEY_DOMAIN);
    expect(vector.signInKey.codec).toBe(signInEd25519Codec.id);
  });

  it("differs from v1 in id, algorithm, both transcript domains and the KDF only", () => {
    const v1 = signInEd25519ExternalSalt;
    const v2 = signInEd25519ExternalSaltV2;
    expect(v2.id).not.toBe(v1.id);
    expect(v2.algorithm).not.toBe(v1.algorithm);
    expect(v2.domains.passwordHash).not.toBe(v1.domains.passwordHash);
    expect(v2.domains.entropy).not.toBe(v1.domains.entropy);
    expect(v2.domains.passwordHash.endsWith("\n")).toBe(true);
    for (const profile of [v1, kalvoraEd25519ExternalSalt]) {
      expect(v2.domains.passwordHash).not.toBe(profile.domains.passwordHash);
      expect(v2.domains.entropy).not.toBe(profile.domains.entropy);
    }
    // Four times v1's N, everything else in the KDF unchanged.
    expect(v2.kdf.N).toBe(v1.kdf.N * 4);
    expect({ ...v2.kdf, N: v1.kdf.N }).toEqual(v1.kdf);
    expect(v2.saltPolicy).toBe(v1.saltPolicy);
    expect(v2.curve).toBe(v1.curve);
    expect(v2.codec).toBe(v1.codec);
    expect(v2.keyDerivation?.id).toBe(v1.keyDerivation?.id);
  });

  it("leaves v1 unchanged", () => {
    expect(signInEd25519ExternalSalt.id).toBe("web2ish-sign-in-ed25519-external-salt-v1");
    expect(signInEd25519ExternalSalt.kdf).toEqual({ N: 65_536, r: 8, p: 1, dkLen: 32 });
    expect(signInEd25519ExternalSalt.domains).toEqual({
      passwordHash: "web2-ish-self-custody sign-in password hash v1\n",
      entropy: "web2-ish-self-custody sign-in Ed25519 external salt entropy v1",
    });
  });

  it("is frozen, survives defineDerivationProfile, and is exported from the core entry", () => {
    for (const value of [
      signInEd25519ExternalSaltV2,
      signInEd25519ExternalSaltV2.kdf,
      signInEd25519ExternalSaltV2.domains,
      signInEd25519ExternalSaltV2.keyDerivation,
    ]) {
      expect(Object.isFrozen(value)).toBe(true);
    }
    expect(defineDerivationProfile(signInEd25519ExternalSaltV2).id).toBe(
      signInEd25519ExternalSaltV2.id,
    );
    expect(core.signInEd25519ExternalSaltV2).toBe(signInEd25519ExternalSaltV2);
  });

  it("names the vector's transcript intermediates with its own domain strings", () => {
    const passwordHash = sha512(
      concatBytes(
        encoder.encode(signInEd25519ExternalSaltV2.domains.passwordHash),
        encoder.encode(vector.passwordUtf8),
      ),
    );
    expect(bytesToHex(passwordHash)).toBe(vector.passwordHashHex);
    const entropy = sha512(
      encoder.encode(
        [
          signInEd25519ExternalSaltV2.domains.entropy,
          vector.applicationId,
          vector.networkId,
          vector.normalizedUsername,
          bytesToHex(passwordHash),
        ].join("\n"),
      ),
    );
    expect(bytesToHex(entropy)).toBe(vector.entropyHex);
    expect(bytesToHex(signInHkdfEd25519.deriveKey(hexToBytes(vector.masterSeedHex)))).toBe(
      vector.signInKey.seedHex,
    );
  });

  it(
    "runs scrypt at N=2^18 to reach the vector's master seed",
    () => {
      const masterSeed = scrypt(hexToBytes(vector.entropyHex), hexToBytes(vector.saltHex), {
        N: 262_144,
        r: 8,
        p: 1,
        dkLen: 32,
      });
      expect(bytesToHex(masterSeed)).toBe(vector.masterSeedHex);
      // At v1's N the same entropy gives a different output.
      const atV1Cost = scrypt(hexToBytes(vector.entropyHex), hexToBytes(vector.saltHex), {
        N: 65_536,
        r: 8,
        p: 1,
        dkLen: 32,
      });
      expect(bytesToHex(atV1Cost)).not.toBe(vector.masterSeedHex);
    },
    derivationTimeoutMs,
  );
});

describe("deriving under the sign-in profile v2", () => {
  it(
    "reproduces the vector through the profile, with secrets, and the wallet through the helper",
    async () => {
      const captured: { masterSeed?: Uint8Array } = {};
      const capturing = defineDerivationProfile({
        ...signInEd25519ExternalSaltV2,
        keyDerivation: {
          id: signInHkdfEd25519.id,
          deriveKey(masterSeed) {
            captured.masterSeed = Uint8Array.from(masterSeed);
            return signInHkdfEd25519.deriveKey(masterSeed);
          },
        },
      });

      const result = await withDerivedWallet(
        { ...credentials, profile: capturing },
        (signIn, secrets) => ({
          identity: signIn.identity,
          signatureHex: bytesToHex(
            signIn.signExactMessageUnsafe(encoder.encode(vector.signInKey.messageUtf8)),
          ),
          secrets: hexSecrets(secrets),
          wallet: withKalvoraWalletFromMasterSeed(
            secrets.get(vector.kalvoraWallet.masterSeedLabel)!,
            (wallet) => ({
              identity: wallet.identity,
              signatureHex: bytesToHex(
                wallet.signExactMessageUnsafe(encoder.encode(vector.kalvoraWallet.messageUtf8)),
              ),
            }),
          ),
        }),
        { applicationSecrets: labels },
      );

      expect(bytesToHex(captured.masterSeed!)).toBe(vector.masterSeedHex);
      expect(result.identity).toMatchObject({
        profileId: vector.profile,
        codecId: vector.signInKey.codec,
        curve: "ed25519",
        normalizedUsername: vector.normalizedUsername,
        address: vector.signInKey.address,
        publicKey: vector.signInKey.publicKeyIdentifier,
        fingerprint: vector.signInKey.fingerprint,
      });
      expect(bytesToHex(result.identity.publicKeyBytes)).toBe(vector.signInKey.publicKeyHex);
      expect(result.signatureHex).toBe(vector.signInKey.signatureHex);
      expect(result.secrets).toEqual(
        Object.fromEntries(
          vector.applicationSecrets.secrets.map((entry) => [entry.label, entry.secretHex]),
        ),
      );
      for (const entry of vector.applicationSecrets.secrets) {
        expect(entry.infoUtf8.split("\n")[1]).toBe(signInEd25519ExternalSaltV2.id);
      }
      expect(result.wallet.identity).toMatchObject({
        derivation: vector.kalvoraWallet.derivation,
        codecId: vector.kalvoraWallet.codec,
        address: vector.kalvoraWallet.address,
        publicKey: vector.kalvoraWallet.publicKeyIdentifier,
        fingerprint: vector.kalvoraWallet.fingerprint,
      });
      expect(bytesToHex(result.wallet.identity.publicKeyBytes)).toBe(
        vector.kalvoraWallet.publicKeyHex,
      );
      expect(result.wallet.signatureHex).toBe(vector.kalvoraWallet.signatureHex);
    },
    derivationTimeoutMs,
  );

  it(
    "gives a different sign-in key, secrets and wallet than v1 for the same credentials",
    async () => {
      for (const field of [
        "passwordUtf8",
        "username",
        "normalizedUsername",
        "applicationId",
        "networkId",
        "saltHex",
      ] as const) {
        expect(vector[field]).toBe(v1Vector[field]);
      }
      const read = (profile: typeof signInEd25519ExternalSaltV2) =>
        withDerivedWallet(
          { ...credentials, profile },
          (wallet, secrets) => ({
            publicKeyHex: bytesToHex(wallet.identity.publicKeyBytes),
            profileId: wallet.identity.profileId,
            codecId: wallet.identity.codecId,
            secrets: hexSecrets(secrets),
          }),
          { applicationSecrets: labels },
        );
      const [v1, v2] = await Promise.all([
        read(signInEd25519ExternalSalt),
        read(signInEd25519ExternalSaltV2),
      ]);

      expect(v1.publicKeyHex).toBe(v1Vector.signInKey.publicKeyHex);
      expect(v2.publicKeyHex).toBe(vector.signInKey.publicKeyHex);
      expect(v2.publicKeyHex).not.toBe(v1.publicKeyHex);
      expect(v2.profileId).not.toBe(v1.profileId);
      // Same codec: both are S_ keys, told apart by the profile id.
      expect(v2.codecId).toBe(v1.codecId);
      expect(vector.masterSeedHex).not.toBe(v1Vector.masterSeedHex);
      for (const label of labels) {
        expect(v2.secrets[label]).not.toBe(v1.secrets[label]);
      }
      expect(vector.kalvoraWallet.publicKeyHex).not.toBe(v1Vector.kalvoraWallet.publicKeyHex);
    },
    derivationTimeoutMs,
  );

  it(
    "accepts application secrets, derivePublicIdentity and the scoped signer like v1",
    async () => {
      const identity = await derivePublicIdentity({ ...credentials });
      expect(identity.publicKey).toBe(vector.signInKey.publicKeyIdentifier);
      expect(identity.profileId).toBe(signInEd25519ExternalSaltV2.id);

      let retained: ((message: Uint8Array) => Uint8Array) | undefined;
      const size = await withDerivedWallet(
        { ...credentials },
        (wallet, secrets) => {
          retained = wallet.signExactMessageUnsafe;
          expect(
            ed25519.verify(
              wallet.signExactMessageUnsafe(Uint8Array.of(1)),
              Uint8Array.of(1),
              wallet.identity.publicKeyBytes,
            ),
          ).toBe(true);
          return secrets.size;
        },
        { applicationSecrets: [labels[0]!] },
      );
      expect(size).toBe(1);
      expect(() => retained!(Uint8Array.of(1))).toThrowError(
        expect.objectContaining({ code: "wallet-scope-closed" }),
      );
      // Labels are checked before any KDF work, as under v1.
      await expect(
        withDerivedWallet({ ...credentials }, () => undefined, {
          applicationSecrets: ["Upper-Case"],
        }),
      ).rejects.toMatchObject({ code: "invalid-secret-label" });
    },
    derivationTimeoutMs,
  );

  it(
    "works through withAccountWallet in per-account-deterministic mode",
    async () => {
      const setup = {
        mode: "per-account-deterministic",
        accountId: "6f1c9a52-3d7e-4b8a-9c2f-1e4d5a6b7c8d",
        publicSaltHex: vector.saltHex,
        normalizedUsername: vector.normalizedUsername,
        applicationId: vector.applicationId,
        networkId: vector.networkId,
        profileId: signInEd25519ExternalSaltV2.id,
        codecId: signInEd25519Codec.id,
      } as const;
      const result = await withAccountWallet(
        setup,
        signInEd25519ExternalSaltV2,
        encoder.encode(vector.passwordUtf8),
        (signIn, secrets) => ({
          publicKey: signIn.identity.publicKey,
          secret: bytesToHex(secrets.get(labels[0]!)!),
        }),
        { applicationSecrets: [labels[0]!] },
      );
      expect(result.publicKey).toBe(vector.signInKey.publicKeyIdentifier);
      expect(result.secret).toBe(vector.applicationSecrets.secrets[0]!.secretHex);
    },
    derivationTimeoutMs,
  );
});

describe("modes that refuse the sign-in profile refuse v2 too", () => {
  it("createRandomAccountWallet refuses it", async () => {
    await expect(
      createRandomAccountWallet(
        {
          mode: "random-vault",
          accountId: "6f1c9a52-3d7e-4b8a-9c2f-1e4d5a6b7c8d",
          // A well-formed setup, so the refusal is the profile's, not checkSetup's.
          publicSaltHex: vector.saltHex,
          normalizedUsername: vector.normalizedUsername,
          applicationId: vector.applicationId,
          networkId: vector.networkId,
          profileId: signInEd25519ExternalSaltV2.id,
          codecId: signInEd25519Codec.id,
        },
        signInEd25519ExternalSaltV2,
        encoder.encode(vector.passwordUtf8),
      ),
    ).rejects.toMatchObject({
      code: "invalid-profile",
      message: expect.stringMatching(/random-vault mode needs a chain wallet profile/u),
    });
  });

  it("the identity service serves it in the deterministic modes and refuses random-vault", () => {
    const base = {
      serviceProfileId: "example-account-v2",
      profile: signInEd25519ExternalSaltV2,
      applicationId: vector.applicationId,
      networkId: vector.networkId,
      tablePrefix: "example_id",
    } as const;
    for (const walletMode of ["service-deterministic", "per-account-deterministic"] as const) {
      expect(resolveIdentityServiceConfig({ ...base, walletMode }).profile).toBe(
        signInEd25519ExternalSaltV2,
      );
    }
    const sql = identityMigrations(resolveIdentityServiceConfig(base))
      .flatMap((migration) => migration.statements)
      .join("\n;\n");
    expect(sql).toContain("profile_id = 'web2ish-sign-in-ed25519-external-salt-v2'");
    expect(sql).toContain("algorithm = 'scrypt-sha512-hkdf-sha256-ed25519-external-32-v2'");
    expect(sql).toContain("codec_id = 'web2ish-sign-in-ed25519-hex-v1'");
    expect(sql).toContain("kdf_n = 262144");
    expect(() => resolveIdentityServiceConfig({ ...base, walletMode: "random-vault" })).toThrowError(
      expect.objectContaining({ code: "invalid-service-profile" }),
    );
  });
});
