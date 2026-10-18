import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import {
  KEY_TYPE,
  deriveHDPrivateKey,
  generateKalvoraAddress,
  generateKalvoraPublicKeyIdentifier,
} from "kalvora.js/wallet";
// @ts-expect-error Node typings are intentionally not a browser SDK dependency.
import { Buffer } from "node:buffer";
// @ts-expect-error Node typings are intentionally not a browser SDK dependency.
import { runInNewContext } from "node:vm";
import { beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import vector from "../../vectors/sign-in-ed25519-external-salt-v1.json" with { type: "json" };
import {
  KALVORA_DERIVATION_PATH,
  kalvoraEd25519Codec,
  kalvoraEd25519ExternalSalt,
  kalvoraSlip10Ed25519,
  withKalvoraWalletFromMasterSeed,
  type KalvoraMasterSeedWallet,
} from "../../src/chains/kalvora.js";
import {
  signInEd25519ExternalSalt,
  withDerivedWallet,
  type DerivationCredentials,
  type DerivationError,
} from "../../src/index.js";

/**
 * kalvora.js's SLIP-0010 function is wrapped, not replaced: every call still
 * runs it. The wrapper records the seed array it is handed and the key array it
 * returns, so the suite can prove the helper works on its own copy of the
 * caller's seed and zeroes both that copy and the key.
 */
const probe = vi.hoisted(() => ({ seeds: [] as Uint8Array[], keys: [] as Uint8Array[] }));
vi.mock("kalvora.js/wallet", async (importOriginal) => {
  const actual = await importOriginal<typeof import("kalvora.js/wallet")>();
  return {
    ...actual,
    deriveHDPrivateKey: vi.fn((...args: Parameters<typeof actual.deriveHDPrivateKey>) => {
      const key = actual.deriveHDPrivateKey(...args);
      probe.seeds.push(args[0]);
      probe.keys.push(key);
      return key;
    }),
  };
});
const slip10Calls = vi.mocked(deriveHDPrivateKey);

beforeEach(() => {
  slip10Calls.mockClear();
  probe.seeds.length = 0;
  probe.keys.length = 0;
});

const encoder = new TextEncoder();
const walletSecret = vector.applicationSecrets.secrets.find(
  (entry) => entry.label === vector.kalvoraWallet.masterSeedLabel,
)!;

function masterSeed(): Uint8Array {
  return hexToBytes(walletSecret.secretHex);
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

describe("withKalvoraWalletFromMasterSeed", () => {
  it("reproduces the vector's Kalvora wallet from its master seed", () => {
    const result = withKalvoraWalletFromMasterSeed(masterSeed(), (wallet) => ({
      identity: wallet.identity,
      signatureHex: bytesToHex(
        wallet.signExactMessageUnsafe(encoder.encode(vector.kalvoraWallet.messageUtf8)),
      ),
    }));

    expect(result.identity).toEqual({
      derivation: vector.kalvoraWallet.derivation,
      codecId: vector.kalvoraWallet.codec,
      curve: "ed25519",
      address: vector.kalvoraWallet.address,
      publicKey: vector.kalvoraWallet.publicKeyIdentifier,
      publicKeyBytes: hexToBytes(vector.kalvoraWallet.publicKeyHex),
      fingerprint: vector.kalvoraWallet.fingerprint,
    });
    expect(result.identity.derivation).toBe(kalvoraSlip10Ed25519.id);
    expect(result.identity.codecId).toBe(kalvoraEd25519Codec.id);
    expect(result.signatureHex).toBe(vector.kalvoraWallet.signatureHex);
    expect(Object.isFrozen(result.identity)).toBe(true);
  });

  it("is the kalvora.js wallet, and the Kalvora profile's key step, for that seed", () => {
    const seed = masterSeed();
    const key = deriveHDPrivateKey(seed, KALVORA_DERIVATION_PATH, KEY_TYPE.ED25519);
    const publicKeyBytes = ed25519.getPublicKey(key);
    const identity = withKalvoraWalletFromMasterSeed(seed, (wallet) => wallet.identity);

    expect(identity.publicKeyBytes).toEqual(publicKeyBytes);
    expect(identity.address).toBe(generateKalvoraAddress(publicKeyBytes, KEY_TYPE.ED25519));
    expect(identity.publicKey).toBe(
      generateKalvoraPublicKeyIdentifier(publicKeyBytes, KEY_TYPE.ED25519),
    );
    expect(ed25519.getPublicKey(kalvoraEd25519ExternalSalt.keyDerivation!.deriveKey(seed))).toEqual(
      publicKeyBytes,
    );
    expect(kalvoraEd25519Codec.decodePublicKey(identity.publicKey)).toEqual(publicKeyBytes);
  });

  it("works on its own copy of the seed and zeroes that copy and the key on return", () => {
    const seed = masterSeed();
    let signedWith: Uint8Array | undefined;
    const signature = withKalvoraWalletFromMasterSeed(seed, (wallet) => {
      expect(slip10Calls).toHaveBeenCalledTimes(1);
      const [handed, path, keyType] = slip10Calls.mock.calls[0]!;
      expect(handed).not.toBe(seed);
      expect(path).toBe(KALVORA_DERIVATION_PATH);
      expect(keyType).toBe(KEY_TYPE.ED25519);
      // The copy is cleared as soon as the key exists; the key is live here.
      expect(isZero(probe.seeds[0]!)).toBe(true);
      signedWith = probe.keys[0]!;
      expect(isZero(signedWith)).toBe(false);
      return wallet.signExactMessageUnsafe(Uint8Array.of(1, 2, 3));
    });

    expect(isZero(signedWith!)).toBe(true);
    // The caller's seed is the caller's to zero: untouched.
    expect(bytesToHex(seed)).toBe(walletSecret.secretHex);
    expect(
      ed25519.verify(signature, Uint8Array.of(1, 2, 3), hexToBytes(vector.kalvoraWallet.publicKeyHex)),
    ).toBe(true);
  });

  it("closes the signer and zeroes the key when the callback returns or throws", () => {
    let retained: KalvoraMasterSeedWallet | undefined;
    withKalvoraWalletFromMasterSeed(masterSeed(), (wallet) => {
      retained = wallet;
    });
    expect(isZero(probe.keys[0]!)).toBe(true);
    expect(() => retained!.signExactMessageUnsafe(Uint8Array.of(1))).toThrowError(
      expect.objectContaining({ code: "wallet-scope-closed" } satisfies Partial<DerivationError>),
    );
    // Public identity stays readable; only the signer closes.
    expect(retained!.identity.address).toBe(vector.kalvoraWallet.address);

    const failure = new Error("callback failed");
    let thrownFrom: KalvoraMasterSeedWallet | undefined;
    expect(() =>
      withKalvoraWalletFromMasterSeed(masterSeed(), (wallet) => {
        thrownFrom = wallet;
        throw failure;
      }),
    ).toThrow(failure);
    expect(isZero(probe.keys[1]!)).toBe(true);
    expect(() => thrownFrom!.signExactMessageUnsafe(Uint8Array.of(1))).toThrowError(
      expect.objectContaining({ code: "wallet-scope-closed" }),
    );
  });

  it("refuses an async callback or any thenable result, after zeroing the key", () => {
    const outcomes: unknown[] = [
      () => Promise.resolve("not allowed"),
      async () => "not allowed",
      () => ({ then: () => undefined }),
    ];
    for (const [index, useWallet] of outcomes.entries()) {
      let retained: KalvoraMasterSeedWallet | undefined;
      expect(() =>
        withKalvoraWalletFromMasterSeed(masterSeed(), (wallet) => {
          retained = wallet;
          return (useWallet as () => unknown)();
        }),
      ).toThrowError(expect.objectContaining({ code: "async-wallet-scope" }));
      expect(isZero(probe.keys[index]!)).toBe(true);
      expect(() => retained!.signExactMessageUnsafe(Uint8Array.of(1))).toThrowError(
        expect.objectContaining({ code: "wallet-scope-closed" }),
      );
    }
  });

  it("signs 1 to 1,048,576 bytes, as withDerivedWallet does, and nothing else", () => {
    withKalvoraWalletFromMasterSeed(masterSeed(), (wallet) => {
      const largest = new Uint8Array(1_048_576).fill(7);
      expect(
        ed25519.verify(wallet.signExactMessageUnsafe(largest), largest, wallet.identity.publicKeyBytes),
      ).toBe(true);
      for (const bad of [
        new Uint8Array(0),
        new Uint8Array(1_048_577),
        "message",
        [1, 2, 3],
        new DataView(new ArrayBuffer(8)),
        null,
      ]) {
        expect(() => wallet.signExactMessageUnsafe(bad as unknown as Uint8Array)).toThrowError(
          expect.objectContaining({ code: "invalid-message" }),
        );
      }
    });
  });

  it("refuses a seed that is not exactly 32 bytes in a plain Uint8Array, before deriving", () => {
    const useWallet = vi.fn();
    class Subclass extends Uint8Array {}
    // Real length 16; every property-based read says 32.
    class LengthLiar extends Uint8Array {}
    for (const name of ["byteLength", "length"]) {
      Object.defineProperty(LengthLiar.prototype, name, { get: () => 32 });
    }
    const ownLengthLiar = new Uint8Array(16).fill(7);
    Object.defineProperty(ownLengthLiar, "byteLength", { get: () => 32 });
    Object.defineProperty(ownLengthLiar, "length", { get: () => 32 });
    for (const bad of [
      new Uint8Array(32),
      new Subclass(masterSeed()),
      Buffer.from(masterSeed()),
      new LengthLiar(16).fill(7),
      ownLengthLiar,
      runInNewContext("class Sub extends Uint8Array {}; new Sub(32).fill(1)"),
      new Uint8Array(31),
      new Uint8Array(33),
      new Uint8Array(0),
      new Uint8Array(64),
      new Uint8ClampedArray(32),
      new Int8Array(32),
      new Uint16Array(16),
      new DataView(new ArrayBuffer(32)),
      new ArrayBuffer(32),
      Array.from({ length: 32 }, () => 1),
      walletSecret.secretHex,
      null,
      undefined,
    ]) {
      expect(() =>
        withKalvoraWalletFromMasterSeed(bad as unknown as Uint8Array, useWallet),
      ).toThrowError(expect.objectContaining({ name: "DerivationError", code: "invalid-seed" }));
    }
    expect(useWallet).not.toHaveBeenCalled();
    expect(slip10Calls).not.toHaveBeenCalled();
  });

  it("accepts a genuine Uint8Array from another realm or a 32-byte view, and reads its slots", () => {
    const crossRealm = runInNewContext(
      `Uint8Array.from(${JSON.stringify(Array.from(masterSeed()))})`,
    ) as Uint8Array;
    expect(crossRealm).not.toBeInstanceOf(Uint8Array);
    expect(withKalvoraWalletFromMasterSeed(crossRealm, (wallet) => wallet.identity.address)).toBe(
      vector.kalvoraWallet.address,
    );

    const backing = new Uint8Array(96).fill(0xa5);
    backing.set(masterSeed(), 40);
    const view = backing.subarray(40, 72);
    expect(withKalvoraWalletFromMasterSeed(view, (wallet) => wallet.identity.address)).toBe(
      vector.kalvoraWallet.address,
    );

    // A plain array whose own properties lie: an iterator that yields other
    // bytes, and a length that says 64. The helper reads neither.
    const lying = masterSeed();
    Object.defineProperty(lying, Symbol.iterator, {
      value: function* () {
        yield* new Uint8Array(64).fill(9);
      },
    });
    Object.defineProperty(lying, "length", { get: () => 64 });
    expect(withKalvoraWalletFromMasterSeed(lying, (wallet) => wallet.identity.address)).toBe(
      vector.kalvoraWallet.address,
    );
    // Three calls, each handed a 32-byte copy of the real bytes.
    expect(probe.seeds.map((seed) => seed.byteLength)).toEqual([32, 32, 32]);
  });

  it(
    "refuses an application secret kept past its withDerivedWallet scope",
    async () => {
      const credentials = {
        profile: signInEd25519ExternalSalt,
        username: vector.username,
        password: encoder.encode(vector.passwordUtf8),
        context: { applicationId: vector.applicationId, networkId: vector.networkId },
        salt: hexToBytes(vector.saltHex),
      } as const satisfies DerivationCredentials;
      const label = vector.kalvoraWallet.masterSeedLabel;

      let kept: Uint8Array | undefined;
      const insideScope = await withDerivedWallet(
        credentials,
        (_signIn, secrets) => {
          kept = secrets.get(label);
          return withKalvoraWalletFromMasterSeed(kept!, (wallet) => wallet.identity.address);
        },
        { applicationSecrets: [label] },
      );
      expect(insideScope).toBe(vector.kalvoraWallet.address);
      slip10Calls.mockClear();

      // The SDK zeroed the secret when the scope ended. Opening a wallet from
      // it would give the all-zero seed's wallet, whose key anyone can compute.
      expect(isZero(kept!)).toBe(true);
      const useWallet = vi.fn();
      expect(() => withKalvoraWalletFromMasterSeed(kept!, useWallet)).toThrowError(
        expect.objectContaining({ name: "DerivationError", code: "invalid-seed" }),
      );
      expect(useWallet).not.toHaveBeenCalled();
      expect(slip10Calls).not.toHaveBeenCalled();
    },
    120_000,
  );

  it("returns the callback's result synchronously, with its own type", () => {
    const result = withKalvoraWalletFromMasterSeed(masterSeed(), (wallet) => wallet.identity.address);
    expect(result).toBe(vector.kalvoraWallet.address);
    expectTypeOf(withKalvoraWalletFromMasterSeed(masterSeed(), () => 1)).toEqualTypeOf<number>();
    expectTypeOf<KalvoraMasterSeedWallet["identity"]>().toEqualTypeOf<
      Readonly<{
        derivation: string;
        codecId: string;
        curve: "ed25519";
        address: string;
        publicKey: string;
        publicKeyBytes: Uint8Array;
        fingerprint: string;
      }>
    >();

    // The identity's key bytes are a copy: editing them changes nothing signed.
    withKalvoraWalletFromMasterSeed(masterSeed(), (wallet) => {
      wallet.identity.publicKeyBytes.fill(0);
      const signature = wallet.signExactMessageUnsafe(Uint8Array.of(9));
      expect(
        ed25519.verify(signature, Uint8Array.of(9), hexToBytes(vector.kalvoraWallet.publicKeyHex)),
      ).toBe(true);
    });
  });
});
