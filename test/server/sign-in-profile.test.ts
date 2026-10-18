import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import vector from "../../vectors/sign-in-ed25519-external-salt-v1.json" with { type: "json" };
import { withKalvoraWalletFromMasterSeed } from "../../src/chains/kalvora.js";
import { signInEd25519ExternalSalt } from "../../src/index.js";
import {
  buildChallengeMessage,
  canonicalWalletIdentity,
  verifyChallengeSignature,
} from "../../src/server/challenge.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import { identityMigrations } from "../../src/server/migrations.js";
import { platformSaltMigration } from "../../src/server/serviceProfile.js";

/**
 * The identity service needs no code for the sign-in profile: it is generic
 * over the profile and its codec. These checks pin that it accepts the profile,
 * bakes its ids into the schema, and, through the sign-in codec, refuses a
 * Kalvora key outright. The real-PostgreSQL register and login flow is in
 * sign-in.integration.test.ts.
 */

const encoder = new TextEncoder();
const walletSeedHex = vector.applicationSecrets.secrets.find(
  (entry) => entry.label === vector.kalvoraWallet.masterSeedLabel,
)!.secretHex;

const config = resolveIdentityServiceConfig({
  serviceProfileId: "example-account-v1",
  profile: signInEd25519ExternalSalt,
  applicationId: vector.applicationId,
  networkId: vector.networkId,
  tablePrefix: "example_id",
});

const challengeMessage = buildChallengeMessage({
  serviceProfileId: config.serviceProfileId,
  applicationId: config.applicationId,
  networkId: config.networkId,
  purpose: "registration",
  usernameNormalized: vector.normalizedUsername,
  nonceHex: "5c".repeat(32),
  expiresAt: new Date("2026-03-04T05:06:07.008Z"),
});

function expectIdentityError(run: () => unknown, code: IdentityErrorCode): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe(code);
    return;
  }
  throw new Error(`Expected an IdentityError with code "${code}" but nothing was thrown.`);
}

describe("the identity service under the sign-in profile", () => {
  it("resolves a config around it", () => {
    expect(config.profile).toBe(signInEd25519ExternalSalt);
    expect(config.profile.codec.id).toBe("web2ish-sign-in-ed25519-hex-v1");
  });

  it("bakes the sign-in ids into the schema, and no Kalvora id", () => {
    const sql = identityMigrations(config)
      .flatMap((migration) => migration.statements)
      .join("\n;\n");
    expect(sql).toContain("profile_id = 'web2ish-sign-in-ed25519-external-salt-v1'");
    expect(sql).toContain("algorithm = 'scrypt-sha512-hkdf-sha256-ed25519-external-32-v1'");
    expect(sql).toContain("codec_id = 'web2ish-sign-in-ed25519-hex-v1'");
    expect(sql).toContain("kdf_n = 65536");
    expect(sql).not.toContain("kalvora-ed25519-base58-v1");
    expect(sql).not.toContain("web2ish-kalvora");
    expect(sql).not.toContain("slip10");

    // A salt-only host emits the same version-1 SQL.
    expect(platformSaltMigration(config).statements).toEqual(
      identityMigrations(config)[0]!.statements,
    );
  });

  it("canonicalizes the sign-in key and verifies its challenge signature", () => {
    const identity = canonicalWalletIdentity(config.profile.codec, {
      publicKey: vector.signInKey.publicKeyIdentifier,
      address: vector.signInKey.address,
    });
    expect(identity.codecId).toBe(vector.signInKey.codec);
    expect(identity.publicKey).toBe(vector.signInKey.publicKeyIdentifier);
    expect(identity.address).toBe(vector.signInKey.address);
    // The CHECK is `address_normalized = lower(address)`; the S_ tag folds.
    expect(identity.addressNormalized).toBe(vector.signInKey.address.toLowerCase());
    expect(bytesToHex(identity.publicKeyBytes)).toBe(vector.signInKey.publicKeyHex);

    const signature = bytesToHex(
      ed25519.sign(encoder.encode(challengeMessage), hexToBytes(vector.signInKey.seedHex)),
    );
    expect(verifyChallengeSignature(identity, challengeMessage, signature)).toBe(true);

    // The application's Kalvora wallet cannot answer for the sign-in key.
    const walletSignature = withKalvoraWalletFromMasterSeed(hexToBytes(walletSeedHex), (wallet) =>
      bytesToHex(wallet.signExactMessageUnsafe(encoder.encode(challengeMessage))),
    );
    expect(verifyChallengeSignature(identity, challengeMessage, walletSignature)).toBe(false);
  });

  it("refuses a Kalvora-codec key, and any non-canonical sign-in key, at enrollment", () => {
    const kalvora = vector.kalvoraWallet;
    for (const input of [
      { publicKey: kalvora.publicKeyIdentifier, address: kalvora.address },
      { publicKey: kalvora.publicKeyIdentifier, address: vector.signInKey.address },
      { publicKey: `A_${vector.signInKey.publicKeyHex}`, address: vector.signInKey.address },
      {
        publicKey: vector.signInKey.publicKeyIdentifier.toUpperCase(),
        address: vector.signInKey.address,
      },
      {
        publicKey: `S_${vector.signInKey.publicKeyHex.toUpperCase()}`,
        address: vector.signInKey.address,
      },
      { publicKey: ` ${vector.signInKey.publicKeyIdentifier}`, address: vector.signInKey.address },
      { publicKey: vector.signInKey.publicKeyHex, address: vector.signInKey.address },
    ]) {
      expectIdentityError(
        () => canonicalWalletIdentity(config.profile.codec, input),
        "invalid-public-key",
      );
    }

    // A sign-in key enrolled under a Kalvora address is refused too.
    expectIdentityError(
      () =>
        canonicalWalletIdentity(config.profile.codec, {
          publicKey: vector.signInKey.publicKeyIdentifier,
          address: kalvora.address,
        }),
      "invalid-address",
    );
  });
});
