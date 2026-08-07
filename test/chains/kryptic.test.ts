import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import zeraVector from "../../vectors/zera-ed25519-external-salt-v1.json" with { type: "json" };
import { zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import { derivePublicIdentity, withDerivedWallet } from "../../src/index.js";
import {
  buildChallengeMessage,
  canonicalWalletIdentity,
  verifyChallengeSignature,
} from "../../src/server/challenge.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import { identityMigrations } from "../../src/server/migrations.js";
import {
  krypticExternalSalt,
  krypticHexCodec,
  krypticStateless,
  krypticZeraTranscript,
} from "../support/kryptic-chain.js";

/**
 * The chain-agnosticism proof.
 *
 * Everything below runs the throwaway `kryptic` chain — hex addresses behind a
 * `k_` tag — through the same derivation, challenge, and identity-service code
 * ZERA uses, with no branch anywhere that knows either chain's name. If the
 * core ever grows a ZERA-shaped assumption, these fail and the ZERA suites do
 * not, which is precisely the signal that would otherwise be missed.
 */

const encoder = new TextEncoder();
const password = encoder.encode(zeraVector.passwordUtf8);
const salt = hexToBytes(zeraVector.saltHex);
const context = {
  applicationId: zeraVector.applicationId,
  networkId: zeraVector.networkId,
};

/** scrypt at N=65536 costs ~200ms per call, so each derivation is memoized. */
const derivationTimeoutMs = 60_000;

const hex64 = /^[0-9a-f]{64}$/u;

const challengeMessage = buildChallengeMessage({
  serviceProfileId: "kryptic.identity",
  applicationId: context.applicationId,
  networkId: context.networkId,
  purpose: "registration",
  usernameNormalized: "jesse@example.com",
  nonceHex: "5c".repeat(32),
  expiresAt: new Date("2026-03-04T05:06:07.008Z"),
});

type WalletFixture = Readonly<{
  profileId: string;
  codecId: string;
  address: string;
  publicKey: string;
  publicKeyHex: string;
  challengeSignatureHex: string;
}>;

let krypticFixturePromise: Promise<WalletFixture> | undefined;

function krypticFixture(): Promise<WalletFixture> {
  return (krypticFixturePromise ??= withDerivedWallet(
    {
      profile: krypticExternalSalt,
      username: zeraVector.username,
      password,
      context,
      salt,
    },
    (wallet): WalletFixture =>
      Object.freeze({
        profileId: wallet.identity.profileId,
        codecId: wallet.identity.codecId,
        address: wallet.identity.address,
        publicKey: wallet.identity.publicKey,
        publicKeyHex: bytesToHex(wallet.identity.publicKeyBytes),
        challengeSignatureHex: bytesToHex(
          wallet.signExactMessageUnsafe(encoder.encode(challengeMessage)),
        ),
      }),
  ));
}

describe("a second chain on the same core", () => {
  it(
    "derives a wallet spelled in the second chain's own convention",
    async () => {
      const wallet = await krypticFixture();

      expect(wallet.profileId).toBe("kryptic-ed25519-external-salt-v1");
      expect(wallet.codecId).toBe("kryptic-hex-v1");
      expect(wallet.address).toMatch(hex64);
      expect(wallet.address).toBe(wallet.publicKeyHex);
      expect(wallet.publicKey).toBe(`k_${wallet.publicKeyHex}`);

      // Nothing about the ZERA convention leaks into it.
      expect(wallet.publicKey.startsWith("A_")).toBe(false);
      expect(wallet.address).not.toBe(zeraVector.address);
      expect(wallet.publicKeyHex).not.toBe(zeraVector.publicKeyHex);
    },
    derivationTimeoutMs,
  );

  it(
    "signs and verifies under the generic signature path",
    async () => {
      const wallet = await krypticFixture();

      expect(
        ed25519.verify(
          hexToBytes(wallet.challengeSignatureHex),
          encoder.encode(challengeMessage),
          hexToBytes(wallet.publicKeyHex),
        ),
      ).toBe(true);
    },
    derivationTimeoutMs,
  );

  it(
    "round-trips through the identity service's canonicalization and verification",
    async () => {
      const wallet = await krypticFixture();

      const identity = canonicalWalletIdentity(krypticHexCodec, {
        publicKey: wallet.publicKey,
        address: wallet.address,
      });

      expect(identity.curve).toBe("ed25519");
      expect(identity.codecId).toBe("kryptic-hex-v1");
      expect(identity.address).toBe(wallet.address);
      expect(identity.publicKey).toBe(wallet.publicKey);
      expect(bytesToHex(identity.publicKeyBytes)).toBe(wallet.publicKeyHex);

      expect(
        verifyChallengeSignature(identity, challengeMessage, wallet.challengeSignatureHex),
      ).toBe(true);
      expect(
        verifyChallengeSignature(identity, `${challengeMessage} `, wallet.challengeSignatureHex),
      ).toBe(false);
    },
    derivationTimeoutMs,
  );

  it(
    "rejects a mismatched address and a foreign chain's identifier",
    async () => {
      const wallet = await krypticFixture();

      expect(() =>
        canonicalWalletIdentity(krypticHexCodec, {
          publicKey: wallet.publicKey,
          address: zeraVector.address,
        }),
      ).toThrowError(expect.objectContaining({ code: "invalid-address" }));

      expect(() =>
        canonicalWalletIdentity(krypticHexCodec, {
          publicKey: zeraVector.publicKeyIdentifier,
          address: zeraVector.address,
        }),
      ).toThrowError(expect.objectContaining({ code: "invalid-public-key" }));
    },
    derivationTimeoutMs,
  );

  it(
    "supports the derived-from-username salt policy just as well",
    async () => {
      const stateless = await derivePublicIdentity({
        profile: krypticStateless,
        username: zeraVector.username,
        password,
        context,
      });
      const external = await krypticFixture();

      expect(stateless.profileId).toBe("kryptic-ed25519-v1");
      expect(stateless.codecId).toBe("kryptic-hex-v1");
      expect(stateless.address).toMatch(hex64);
      expect(stateless.address).not.toBe(external.address);
    },
    derivationTimeoutMs,
  );
});

describe("the codec is a presentation seam, not a derivation input", () => {
  it(
    "reproduces the committed ZERA key bytes under a different address encoding",
    async () => {
      // Same transcript domains, same KDF, same credentials, same salt — only
      // the codec and the profile id differ, and the profile id is not signed.
      const mirrored = await derivePublicIdentity({
        profile: krypticZeraTranscript,
        username: zeraVector.username,
        password,
        context,
        salt,
      });

      expect(bytesToHex(mirrored.publicKeyBytes)).toBe(zeraVector.publicKeyHex);
      expect(mirrored.address).toBe(zeraVector.publicKeyHex);
      expect(mirrored.publicKey).toBe(`k_${zeraVector.publicKeyHex}`);
      expect(mirrored.codecId).toBe("kryptic-hex-v1");
      expect(mirrored.profileId).toBe("kryptic-zera-transcript-v1");

      // The transcript is copied from the real profile rather than retyped, so
      // this stays a statement about the core rather than about a duplicate.
      expect(krypticZeraTranscript.domains).toEqual(zeraEd25519ExternalSalt.domains);
      expect(krypticZeraTranscript.kdf).toEqual(zeraEd25519ExternalSalt.kdf);
    },
    derivationTimeoutMs,
  );
});

describe("the identity service accepts a second chain unchanged", () => {
  const config = resolveIdentityServiceConfig({
    serviceProfileId: "kryptic.identity",
    profile: krypticExternalSalt,
    applicationId: "knight-armor",
    networkId: "kryptic-testnet",
    tablePrefix: "kryptic_id",
  });

  it("resolves a config around the second chain's profile", () => {
    expect(config.profile).toBe(krypticExternalSalt);
    expect(config.profile.codec.id).toBe("kryptic-hex-v1");
  });

  it("records the second chain's codec id in the wallet binding constraint", () => {
    const sql = identityMigrations(config)
      .flatMap((migration) => migration.statements)
      .join("\n;\n");

    expect(sql).toContain("codec_id text NOT NULL");
    expect(sql).toContain("codec_id = 'kryptic-hex-v1'");
    expect(sql).toContain("profile_id = 'kryptic-ed25519-external-salt-v1'");
    expect(sql).toContain("algorithm = 'scrypt-sha512-ed25519-external-32-v1'");
    // No ZERA identifier may reach a non-ZERA deployment's schema.
    expect(sql).not.toContain("zera-ed25519-base58-v1");
    expect(sql).not.toContain("web2ish-zera");
  });
});
