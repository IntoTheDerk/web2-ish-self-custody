import { ed25519 } from "@noble/curves/ed25519.js";
import { extract } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { beforeEach, describe, expect, it, vi } from "vitest";
import kalvoraVector from "../vectors/kalvora-ed25519-external-salt-v1.json" with { type: "json" };
import kalvoraSecretVector from "../vectors/kalvora-ed25519-external-salt-v1.application-secret-v1.json" with { type: "json" };
import vector from "../vectors/sign-in-ed25519-external-salt-v1.json" with { type: "json" };
import {
  kalvoraEd25519Codec,
  kalvoraEd25519ExternalSalt,
  withKalvoraWalletFromMasterSeed,
} from "../src/chains/kalvora.js";
import * as core from "../src/index.js";
import {
  DerivationError,
  assertCodecRoundTrip,
  defineDerivationProfile,
  derivePublicIdentity,
  withDerivedWallet,
  type DerivationCredentials,
} from "../src/index.js";
import {
  SIGN_IN_KEY_DOMAIN,
  signInEd25519Codec,
  signInEd25519ExternalSalt,
  signInHkdfEd25519,
} from "../src/signIn.js";

/**
 * Byte-identity guard and vector checks for the sign-in profile.
 *
 * As with the Kalvora profile, every value pinned here defines a key: an edit
 * to `src/signIn.ts` that changed one would silently move every enrolled
 * sign-in key, and with it every application secret derived under this profile
 * id (an application's wallet among them). If an assertion fails, the fix is a
 * new profile id, not a new expectation.
 *
 * `hmac` and `extract` are wrapped, not replaced: every call still runs the
 * real function, and the wrappers keep a copy of each output so the suite can
 * prove that the sign-in step's PRK is zeroed, that the key is HMAC's own
 * output, and which application-secret PRK the core extracted.
 */
const probe = vi.hoisted(() => ({ outputs: [] as Uint8Array[], prkCopies: [] as Uint8Array[] }));
vi.mock("@noble/hashes/hkdf.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@noble/hashes/hkdf.js")>();
  return {
    ...actual,
    extract: vi.fn((...args: Parameters<typeof actual.extract>) => {
      const prk = actual.extract(...args);
      probe.prkCopies.push(Uint8Array.from(prk));
      return prk;
    }),
  };
});
vi.mock("@noble/hashes/hmac.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@noble/hashes/hmac.js")>();
  const wrapped = vi.fn((...args: Parameters<typeof actual.hmac>) => {
    const output = actual.hmac(...args);
    probe.outputs.push(Uint8Array.from(output));
    return output;
  });
  return { ...actual, hmac: Object.assign(wrapped, { create: actual.hmac.create }) };
});
const hmacCalls = vi.mocked(hmac);
const extractCalls = vi.mocked(extract);

beforeEach(() => {
  hmacCalls.mockClear();
  extractCalls.mockClear();
  probe.outputs.length = 0;
  probe.prkCopies.length = 0;
});

const encoder = new TextEncoder();
const labels = vector.applicationSecrets.secrets.map((entry) => entry.label);
const expectedSecret = new Map(
  vector.applicationSecrets.secrets.map((entry) => [entry.label, entry.secretHex]),
);
const credentials = {
  profile: signInEd25519ExternalSalt,
  username: vector.username,
  password: encoder.encode(vector.passwordUtf8),
  context: { applicationId: vector.applicationId, networkId: vector.networkId },
  salt: hexToBytes(vector.saltHex),
} as const satisfies DerivationCredentials;

/** scrypt at N=65536 costs ~200ms per call, and these tests make several. */
const derivationTimeoutMs = 120_000;

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

function hexSecrets(secrets: ReadonlyMap<string, Uint8Array>): Record<string, string> {
  return Object.fromEntries([...secrets].map(([label, secret]) => [label, bytesToHex(secret)]));
}

describe("sign-in profile constants", () => {
  it("pins the profile, its key step and its codec exactly", () => {
    expect(signInEd25519ExternalSalt.id).toBe("web2ish-sign-in-ed25519-external-salt-v1");
    expect(signInEd25519ExternalSalt.curve).toBe("ed25519");
    expect(signInEd25519ExternalSalt.algorithm).toBe(
      "scrypt-sha512-hkdf-sha256-ed25519-external-32-v1",
    );
    expect(signInEd25519ExternalSalt.saltPolicy).toBe("external-32");
    expect(signInEd25519ExternalSalt.kdf).toEqual({ N: 65_536, r: 8, p: 1, dkLen: 32 });
    expect(signInEd25519ExternalSalt.domains).toEqual({
      passwordHash: "web2-ish-self-custody sign-in password hash v1\n",
      entropy: "web2-ish-self-custody sign-in Ed25519 external salt entropy v1",
    });
    expect(signInEd25519ExternalSalt.domains.salt).toBeUndefined();
    // defineDerivationProfile freezes a copy of the step: same id, same function.
    expect(signInEd25519ExternalSalt.keyDerivation?.id).toBe(signInHkdfEd25519.id);
    expect(signInEd25519ExternalSalt.keyDerivation?.deriveKey).toBe(signInHkdfEd25519.deriveKey);
    expect(signInHkdfEd25519.id).toBe("hkdf-sha256-sign-in-key-v1");
    expect(SIGN_IN_KEY_DOMAIN).toBe("web2-ish-self-custody sign-in key v1");
    expect(signInEd25519ExternalSalt.codec).toBe(signInEd25519Codec);
    expect(signInEd25519Codec.id).toBe("web2ish-sign-in-ed25519-hex-v1");

    // Same values as the vector and the Python verifier read.
    expect(vector.profile).toBe(signInEd25519ExternalSalt.id);
    expect(vector.algorithm).toBe(signInEd25519ExternalSalt.algorithm);
    expect(vector.signInKey.keyDerivation).toBe(signInHkdfEd25519.id);
    expect(vector.signInKey.domain).toBe(SIGN_IN_KEY_DOMAIN);
    expect(vector.signInKey.codec).toBe(signInEd25519Codec.id);
  });

  it("shares no domain, id or codec with the Kalvora profile, and keeps its KDF", () => {
    expect(signInEd25519ExternalSalt.id).not.toBe(kalvoraEd25519ExternalSalt.id);
    expect(signInEd25519ExternalSalt.algorithm).not.toBe(kalvoraEd25519ExternalSalt.algorithm);
    expect(signInEd25519ExternalSalt.domains.passwordHash).not.toBe(
      kalvoraEd25519ExternalSalt.domains.passwordHash,
    );
    expect(signInEd25519ExternalSalt.domains.entropy).not.toBe(
      kalvoraEd25519ExternalSalt.domains.entropy,
    );
    expect(signInHkdfEd25519.id).not.toBe(kalvoraEd25519ExternalSalt.keyDerivation?.id);
    expect(signInEd25519Codec.id).not.toBe(kalvoraEd25519Codec.id);
    expect(signInEd25519ExternalSalt.kdf).toEqual(kalvoraEd25519ExternalSalt.kdf);
    expect(signInEd25519ExternalSalt.domains.passwordHash.endsWith("\n")).toBe(true);
  });

  it("is frozen, survives defineDerivationProfile, and is exported from the core entry", () => {
    for (const value of [
      signInEd25519ExternalSalt,
      signInEd25519ExternalSalt.kdf,
      signInEd25519ExternalSalt.domains,
      signInEd25519ExternalSalt.keyDerivation,
      signInEd25519Codec,
      signInHkdfEd25519,
    ]) {
      expect(Object.isFrozen(value)).toBe(true);
    }
    expect(defineDerivationProfile(signInEd25519ExternalSalt).id).toBe(
      signInEd25519ExternalSalt.id,
    );
    expect(core.signInEd25519ExternalSalt).toBe(signInEd25519ExternalSalt);
    expect(core.signInEd25519Codec).toBe(signInEd25519Codec);
    expect(core.signInHkdfEd25519).toBe(signInHkdfEd25519);
    expect(core.SIGN_IN_KEY_DOMAIN).toBe(SIGN_IN_KEY_DOMAIN);
  });

  it("names the vector's transcript intermediates with its own domain strings", () => {
    const passwordHash = sha512(
      concatBytes(
        encoder.encode(signInEd25519ExternalSalt.domains.passwordHash),
        encoder.encode(vector.passwordUtf8),
      ),
    );
    expect(bytesToHex(passwordHash)).toBe(vector.passwordHashHex);
    const entropy = sha512(
      encoder.encode(
        [
          signInEd25519ExternalSalt.domains.entropy,
          vector.applicationId,
          vector.networkId,
          vector.normalizedUsername,
          bytesToHex(passwordHash),
        ].join("\n"),
      ),
    );
    expect(bytesToHex(entropy)).toBe(vector.entropyHex);
  });
});

describe("the sign-in codec", () => {
  const publicKeyBytes = Uint8Array.from({ length: 32 }, (_, index) => index * 7);
  const identifier = `S_${bytesToHex(publicKeyBytes)}`;

  it("spells the address and the identifier as S_ and 64 lowercase hex digits", () => {
    expect(signInEd25519Codec.encodeAddress(publicKeyBytes)).toBe(identifier);
    expect(signInEd25519Codec.encodePublicKey(publicKeyBytes)).toBe(identifier);
    expect(identifier).toHaveLength(66);
    expect(signInEd25519Codec.decodePublicKey(identifier)).toEqual(publicKeyBytes);
    expect(() => assertCodecRoundTrip(signInEd25519Codec, publicKeyBytes)).not.toThrow();
    expect(() => assertCodecRoundTrip(signInEd25519Codec, new Uint8Array(32))).not.toThrow();
    expect(() =>
      assertCodecRoundTrip(signInEd25519Codec, new Uint8Array(32).fill(0xff)),
    ).not.toThrow();
  });

  it("encodes only a 32-byte public key", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(0)]) {
      expect(() => signInEd25519Codec.encodeAddress(bad)).toThrowError(
        expect.objectContaining({ code: "invalid-public-key" }),
      );
      expect(() => signInEd25519Codec.encodePublicKey(bad)).toThrowError(
        expect.objectContaining({ code: "invalid-public-key" }),
      );
    }
    expect(() =>
      signInEd25519Codec.encodePublicKey(Array.from(publicKeyBytes) as unknown as Uint8Array),
    ).toThrowError(expect.objectContaining({ code: "invalid-public-key" }));
  });

  it("decodes exactly ^S_[0-9a-f]{64}$ and refuses everything else", () => {
    const hex = identifier.slice(2);
    for (const rejected of [
      kalvoraVector.publicKeyIdentifier,
      kalvoraVector.address,
      `A_${hex}`,
      `S_${hex.toUpperCase()}`,
      `S_${hex.slice(0, 63)}A`,
      `s_${hex}`,
      hex,
      `_${hex}`,
      `S${hex}`,
      `S__${hex}`,
      ` ${identifier}`,
      `${identifier} `,
      `${identifier}\n`,
      `\t${identifier}`,
      `S_ ${hex}`,
      `S_${hex.slice(0, 32)} ${hex.slice(32)}`,
      `S_${hex.slice(0, 63)}`,
      `S_${hex}0`,
      `S_${hex.slice(0, 63)}g`,
      `S_0x${hex.slice(2)}`,
      `${identifier}${identifier}`,
      "S_",
      "",
    ]) {
      expect(() => signInEd25519Codec.decodePublicKey(rejected), JSON.stringify(rejected)).toThrowError(
        expect.objectContaining({ name: "DerivationError", code: "invalid-public-key" }),
      );
    }
    for (const rejected of [42, null, undefined, publicKeyBytes]) {
      expect(() =>
        signInEd25519Codec.decodePublicKey(rejected as unknown as string),
      ).toThrowError(expect.objectContaining({ code: "invalid-public-key" }));
    }
  });

  it("is refused by the Kalvora codec, and the Kalvora identifier by it", () => {
    expect(() => kalvoraEd25519Codec.decodePublicKey(identifier)).toThrowError(
      expect.objectContaining({ code: "invalid-public-key" }),
    );
    expect(() =>
      signInEd25519Codec.decodePublicKey(kalvoraEd25519Codec.encodePublicKey(publicKeyBytes)),
    ).toThrowError(expect.objectContaining({ code: "invalid-public-key" }));
  });

  it("gives a fingerprint and an address that fit the identity-service checks", () => {
    expect(vector.signInKey.fingerprint).toMatch(/^S[0-9A-F]{3}( [0-9A-F]{4}){3}$/u);
    expect(vector.signInKey.address.length).toBeGreaterThanOrEqual(8);
    expect(vector.signInKey.address.length).toBeLessThanOrEqual(128);
    expect(vector.signInKey.publicKeyIdentifier.length).toBeLessThanOrEqual(160);
  });
});

describe("the sign-in key step", () => {
  const masterSeed = hexToBytes(vector.masterSeedHex);

  it("is one-block HKDF-SHA256 with the domain as salt and info, and zeroes its PRK", () => {
    const before = Uint8Array.from(masterSeed);
    const seed = signInHkdfEd25519.deriveKey(masterSeed);

    expect(bytesToHex(seed)).toBe(vector.signInKey.seedHex);
    expect(masterSeed).toEqual(before);
    expect(hmacCalls).toHaveBeenCalledTimes(2);

    const domain = encoder.encode(SIGN_IN_KEY_DOMAIN);
    const [extractHash, extractKey, extractData] = hmacCalls.mock.calls[0]!;
    expect(extractHash).toBe(sha256);
    expect(extractKey).toEqual(domain);
    expect(extractData).toBe(masterSeed);
    const prk = hmacCalls.mock.results[0]!.value as Uint8Array;
    expect(bytesToHex(probe.outputs[0]!)).toBe(vector.signInKey.prkHex);
    expect(isZero(prk)).toBe(true);

    const [expandHash, expandKey, expandData] = hmacCalls.mock.calls[1]!;
    expect(expandHash).toBe(sha256);
    expect(expandKey).toBe(prk);
    expect(expandData).toEqual(concatBytes(domain, Uint8Array.of(0x01)));
    // The key is HMAC's own output: there is no other copy to clear.
    expect(hmacCalls.mock.results[1]!.value).toBe(seed);
  });

  it("refuses anything but the 32-byte scrypt output", () => {
    for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(64), "x", null]) {
      expect(() => signInHkdfEd25519.deriveKey(bad as unknown as Uint8Array)).toThrowError(
        expect.objectContaining({ code: "invalid-seed" }),
      );
    }
    expect(hmacCalls).not.toHaveBeenCalled();
  });
});

describe("deriving under the sign-in profile", () => {
  it(
    "reproduces the vector through the profile, with secrets, and the wallet through the helper",
    async () => {
      const captured: { masterSeed?: Uint8Array; seed?: Uint8Array } = {};
      // The profile's own id and transcript, so the secrets are the committed
      // ones; the step only keeps copies of what it is handed and returns.
      const capturing = defineDerivationProfile({
        ...signInEd25519ExternalSalt,
        keyDerivation: {
          id: signInHkdfEd25519.id,
          deriveKey(masterSeed) {
            captured.masterSeed = Uint8Array.from(masterSeed);
            const key = signInHkdfEd25519.deriveKey(masterSeed);
            captured.seed = Uint8Array.from(key);
            return key;
          },
        },
      });

      let liveSeed: Uint8Array | undefined;
      const result = await withDerivedWallet(
        { ...credentials, profile: capturing },
        (signIn, secrets) => {
          liveSeed = hmacCalls.mock.results
            .map((entry) => entry.value as Uint8Array)
            .find((output) => bytesToHex(output) === vector.signInKey.seedHex);
          return {
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
          };
        },
        { applicationSecrets: labels },
      );

      expect(bytesToHex(captured.masterSeed!)).toBe(vector.masterSeedHex);
      expect(bytesToHex(captured.seed!)).toBe(vector.signInKey.seedHex);
      // The core zeroes the key step's output once the callback returns.
      expect(liveSeed).toBeDefined();
      expect(isZero(liveSeed!)).toBe(true);

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
      expect(result.secrets).toEqual(Object.fromEntries(expectedSecret));
      // One application-secret PRK, extracted from the same scrypt output
      // under its own domain and zeroed (application-secrets.test.ts).
      expect(extractCalls).toHaveBeenCalledTimes(1);
      expect(extractCalls.mock.calls[0]![2]).toEqual(
        encoder.encode(vector.applicationSecrets.construction),
      );
      expect(probe.prkCopies.map((prk) => bytesToHex(prk))).toEqual([
        vector.applicationSecrets.prkHex,
      ]);
      expect(isZero(extractCalls.mock.results[0]!.value as Uint8Array)).toBe(true);

      expect(result.wallet.identity).toMatchObject({
        derivation: vector.kalvoraWallet.derivation,
        codecId: vector.kalvoraWallet.codec,
        curve: "ed25519",
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
    "gives a different key, and different secrets for the same labels, than the Kalvora profile",
    async () => {
      // The two vectors share their credentials, context and salt.
      for (const field of [
        "passwordUtf8",
        "username",
        "normalizedUsername",
        "applicationId",
        "networkId",
        "saltHex",
      ] as const) {
        expect(vector[field]).toBe(kalvoraVector[field]);
      }

      const read = (profile: typeof signInEd25519ExternalSalt) =>
        withDerivedWallet(
          { ...credentials, profile },
          (wallet, secrets) => ({
            publicKeyHex: bytesToHex(wallet.identity.publicKeyBytes),
            publicKey: wallet.identity.publicKey,
            secrets: hexSecrets(secrets),
          }),
          { applicationSecrets: [...labels, kalvoraSecretVector.secrets[1]!.label] },
        );
      const [signIn, kalvora] = await Promise.all([
        read(signInEd25519ExternalSalt),
        read(kalvoraEd25519ExternalSalt),
      ]);

      expect(kalvora.publicKeyHex).toBe(kalvoraVector.publicKeyHex);
      expect(signIn.publicKeyHex).toBe(vector.signInKey.publicKeyHex);
      expect(signIn.publicKeyHex).not.toBe(kalvora.publicKeyHex);
      expect(signIn.publicKey).not.toBe(kalvora.publicKey);
      // Nor is it the Kalvora wallet the application derives from a secret.
      expect(signIn.publicKeyHex).not.toBe(vector.kalvoraWallet.publicKeyHex);
      expect(vector.kalvoraWallet.publicKeyHex).not.toBe(kalvoraVector.publicKeyHex);

      expect(kalvora.secrets["example-secret-v1"]).toBe(kalvoraSecretVector.secrets[0]!.secretHex);
      const all = [...Object.values(signIn.secrets), ...Object.values(kalvora.secrets)];
      expect(new Set(all).size).toBe(all.length);
      for (const label of Object.keys(signIn.secrets)) {
        expect(signIn.secrets[label]).not.toBe(kalvora.secrets[label]);
      }
    },
    derivationTimeoutMs,
  );

  it(
    "accepts application secrets, and derivePublicIdentity, like any one-way profile",
    async () => {
      const identity = await derivePublicIdentity({ ...credentials });
      expect(identity.publicKey).toBe(vector.signInKey.publicKeyIdentifier);
      expect(identity.profileId).toBe(signInEd25519ExternalSalt.id);

      const size = await withDerivedWallet(
        { ...credentials },
        (_wallet, secrets) => secrets.size,
        { applicationSecrets: [labels[0]!] },
      );
      expect(size).toBe(1);

      // The signer is the core's, with its bounds and its scope.
      let retained: ((message: Uint8Array) => Uint8Array) | undefined;
      await withDerivedWallet({ ...credentials }, (wallet) => {
        retained = wallet.signExactMessageUnsafe;
        expect(() => wallet.signExactMessageUnsafe(new Uint8Array(0))).toThrowError(
          expect.objectContaining({ code: "invalid-message" }),
        );
        expect(
          ed25519.verify(
            wallet.signExactMessageUnsafe(Uint8Array.of(1)),
            Uint8Array.of(1),
            wallet.identity.publicKeyBytes,
          ),
        ).toBe(true);
      });
      expect(() => retained!(Uint8Array.of(1))).toThrowError(
        expect.objectContaining({ code: "wallet-scope-closed" } satisfies Partial<DerivationError>),
      );
    },
    derivationTimeoutMs,
  );
});
