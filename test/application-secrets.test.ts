import { ed25519 } from "@noble/curves/ed25519.js";
import { extract } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { beforeEach, describe, expect, expectTypeOf, it, vi } from "vitest";
import vector from "../vectors/kalvora-ed25519-external-salt-v1.json" with { type: "json" };
import secretVector from "../vectors/kalvora-ed25519-external-salt-v1.application-secret-v1.json" with { type: "json" };
import { kalvoraEd25519ExternalSalt } from "../src/chains/kalvora.js";
import { deriveWalletSeedUnsafe } from "../src/derive.js";
import {
  createWalletVaultFromCredentials,
  DerivationError,
  defineDerivationProfile,
  withDerivedWallet,
  type DerivationCredentials,
  type DerivationProfile,
  type DerivedIdentity,
  type DerivedWallet,
} from "../src/index.js";
import {
  krypticExternalSalt,
  krypticKalvoraTranscript,
  krypticStateless,
} from "./support/kryptic-chain.js";

/**
 * The HKDF and HMAC modules are wrapped, not replaced: every call still runs
 * the real function. The wrappers record calls and keep a copy of each PRK, so
 * the suite can prove when a PRK is computed, that the one handed back is
 * zeroed, and that each secret is HMAC's own output array rather than a copy.
 */
const probe = vi.hoisted(() => ({ prkCopies: [] as Uint8Array[] }));
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
  return { ...actual, hmac: Object.assign(vi.fn(actual.hmac), { create: actual.hmac.create }) };
});
const extractCalls = vi.mocked(extract);
const hmacCalls = vi.mocked(hmac);

/** The HMAC calls keyed by a PRK that `extract` returned: one per secret. */
function expansions(): { info: Uint8Array; output: Uint8Array; prk: Uint8Array }[] {
  const prks = new Set(extractCalls.mock.results.map((result) => result.value as Uint8Array));
  return hmacCalls.mock.calls.flatMap(([hash, key, message], index) =>
    hash === sha256 && prks.has(key as Uint8Array)
      ? [
          {
            prk: key as Uint8Array,
            info: message as Uint8Array,
            output: hmacCalls.mock.results[index]!.value as Uint8Array,
          },
        ]
      : [],
  );
}

const encoder = new TextEncoder();
const labels = secretVector.secrets.map((entry) => entry.label);
const expectedSecret = new Map(secretVector.secrets.map((entry) => [entry.label, entry.secretHex]));
const credentials = {
  profile: kalvoraEd25519ExternalSalt,
  username: secretVector.username,
  password: encoder.encode(secretVector.passwordUtf8),
  context: { applicationId: secretVector.applicationId, networkId: secretVector.networkId },
  salt: hexToBytes(secretVector.saltHex),
} as const;

/** scrypt at N=65536 costs ~200ms per call, and these tests make several. */
const derivationTimeoutMs = 120_000;

function hexSecrets(secrets: ReadonlyMap<string, Uint8Array>): Record<string, string> {
  return Object.fromEntries([...secrets].map(([label, secret]) => [label, bytesToHex(secret)]));
}

function isZero(bytes: Uint8Array): boolean {
  return bytes.every((byte) => byte === 0);
}

beforeEach(() => {
  extractCalls.mockClear();
  hmacCalls.mockClear();
  probe.prkCopies.length = 0;
});

describe("application secrets", () => {
  it(
    "reproduce the committed vector, from one PRK that is zeroed before the callback",
    async () => {
      const result = await withDerivedWallet(
        { ...credentials },
        (wallet, secrets) => {
          // One Extract keyed by the domain string, zeroed already; one Expand
          // per label, each from that same PRK with the committed info bytes.
          // Expand is its single block T(1) = HMAC(PRK, info || 0x01), and the
          // map holds HMAC's own output, so zeroing it leaves no other copy.
          expect(extractCalls).toHaveBeenCalledTimes(1);
          const [, , salt] = extractCalls.mock.calls[0]!;
          expect(salt).toEqual(encoder.encode(secretVector.construction));
          const prk = extractCalls.mock.results[0]!.value as Uint8Array;
          expect(prk).toHaveLength(32);
          expect(isZero(prk)).toBe(true);
          const blocks = expansions();
          expect(blocks).toHaveLength(labels.length);
          for (const [index, entry] of secretVector.secrets.entries()) {
            const block = blocks[index]!;
            expect(block.prk).toBe(prk);
            expect(block.info).toEqual(
              concatBytes(encoder.encode(entry.infoUtf8), Uint8Array.of(0x01)),
            );
            expect(block.output).toHaveLength(32);
            expect(secrets.get(entry.label)).toBe(block.output);
          }
          return { identity: wallet.identity, secrets: hexSecrets(secrets) };
        },
        { applicationSecrets: labels },
      );

      expect(result.identity.publicKey).toBe(secretVector.publicKeyIdentifier);
      expect(bytesToHex(result.identity.publicKeyBytes)).toBe(secretVector.publicKeyHex);
      expect(result.secrets).toEqual(Object.fromEntries(expectedSecret));
      expect(probe.prkCopies.map((prk) => bytesToHex(prk))).toEqual([secretVector.prkHex]);
    },
    derivationTimeoutMs,
  );

  it(
    "are deterministic and do not depend on request order or on the other labels",
    async () => {
      const read = (requested: readonly string[]) =>
        withDerivedWallet({ ...credentials }, (_wallet, secrets) => hexSecrets(secrets), {
          applicationSecrets: requested,
        });
      const [forward, reversed, single, again] = await Promise.all([
        read(labels),
        read([...labels].reverse()),
        read([labels[1]!]),
        read(labels),
      ]);

      expect(Object.keys(forward)).toEqual(labels);
      expect(Object.keys(reversed)).toEqual([...labels].reverse());
      expect(reversed).toEqual(forward);
      expect(again).toEqual(forward);
      expect(single).toEqual({ [labels[1]!]: forward[labels[1]!] });
    },
    derivationTimeoutMs,
  );

  it(
    "separate labels, and bind the profile id, context, username, password and salt",
    async () => {
      const label = labels[0]!;
      const read = (overrides: Partial<DerivationCredentials>) =>
        withDerivedWallet(
          { ...credentials, ...overrides },
          (wallet, secrets) => ({
            publicKey: bytesToHex(wallet.identity.publicKeyBytes),
            secret: bytesToHex(secrets.get(label)!),
          }),
          { applicationSecrets: [label] },
        );
      const base = { publicKey: secretVector.publicKeyHex, secret: expectedSecret.get(label)! };
      const variants = await Promise.all([
        // Kalvora's exact transcript under another profile id: the very same
        // wallet, so only the id in `info` separates the secrets.
        read({ profile: krypticKalvoraTranscript }),
        read({ username: "other@example.com" }),
        read({ context: { ...credentials.context, applicationId: "other-app" } }),
        read({ context: { ...credentials.context, networkId: "kalvora-testnet" } }),
        read({ password: encoder.encode(`${secretVector.passwordUtf8}!`) }),
        read({ salt: new Uint8Array(32).fill(7) }),
      ]);

      expect(variants[0]!.publicKey).toBe(base.publicKey);
      const secrets = [base.secret, expectedSecret.get(labels[1]!)!, ...variants.map((v) => v.secret)];
      expect(new Set(secrets).size).toBe(secrets.length);
    },
    derivationTimeoutMs,
  );

  it("validate every label, and refuse duplicates, before any KDF work", async () => {
    const onProgress = vi.fn();
    const attempt = (options: unknown) =>
      withDerivedWallet({ ...credentials, onProgress }, () => undefined, options as never);

    for (const rejected of [
      "",
      "ab",
      "Example-secret-v1",
      "-example",
      ".example",
      "_example",
      "example secret",
      "example\nsecret",
      "example-secret-v1\n",
      " example-secret-v1",
      "example/secret",
      "exämple-secret",
      "a".repeat(81),
      42,
      null,
      undefined,
    ]) {
      await expect(
        attempt({ applicationSecrets: [rejected] }),
        `label ${JSON.stringify(rejected)} must be rejected`,
      ).rejects.toMatchObject({ code: "invalid-secret-label" } satisfies Partial<DerivationError>);
    }
    for (const options of [
      { applicationSecrets: ["example-secret-v1", "example-secret-v1"] },
      { applicationSecrets: ["abc", "def", "abc"] },
      { applicationSecrets: "example-secret-v1" },
      { applicationSecrets: { 0: "example-secret-v1", length: 1 } },
      // A hole in a sparse array is not a label.
      { applicationSecrets: [, "example-secret-v1"] },
      null,
      "example-secret-v1",
    ]) {
      await expect(attempt(options)).rejects.toMatchObject({
        code: "invalid-secret-label",
      } satisfies Partial<DerivationError>);
    }
    expect(onProgress).not.toHaveBeenCalled();
    expect(extractCalls).not.toHaveBeenCalled();

    // @ts-expect-error a bare string is not a label list
    const bareString: Parameters<typeof withDerivedWallet>[2] = { applicationSecrets: "abc" };
    expect(bareString).toBeDefined();
  });

  it(
    "accept the edges of the label alphabet, and snapshot the labels before deriving",
    async () => {
      const edges = ["abc", "0.a_b:c-d", "z".repeat(80)];
      const requested = [labels[0]!, ...edges];
      const result = await withDerivedWallet(
        {
          ...credentials,
          onProgress() {
            // A caller that edits its array mid-derivation changes nothing.
            requested[0] = labels[1]!;
            requested.push("late-label");
          },
        },
        (_wallet, secrets) => hexSecrets(secrets),
        { applicationSecrets: requested },
      );

      expect(Object.keys(result)).toEqual([labels[0], ...edges]);
      expect(result[labels[0]!]).toBe(expectedSecret.get(labels[0]!));
    },
    derivationTimeoutMs,
  );

  it(
    "are zeroed when the callback returns, throws, or returns a promise",
    async () => {
      const options = { applicationSecrets: labels };

      let retained: ReadonlyMap<string, Uint8Array> | undefined;
      let replaced: Uint8Array | undefined;
      let copy: Uint8Array | undefined;
      await withDerivedWallet(
        { ...credentials },
        (_wallet, secrets) => {
          retained = secrets;
          // The documented way to keep a secret: copy it inside the callback.
          copy = Uint8Array.from(secrets.get(labels[0]!)!);
          // Editing the map does not stop the original arrays being cleared.
          replaced = secrets.get(labels[1]!);
          (secrets as Map<string, Uint8Array>).set(labels[1]!, new Uint8Array(32).fill(9));
        },
        options,
      );
      expect(retained?.size).toBe(labels.length);
      expect(isZero(retained!.get(labels[0]!)!)).toBe(true);
      expect(replaced).toHaveLength(32);
      expect(isZero(replaced!)).toBe(true);
      expect(bytesToHex(copy!)).toBe(expectedSecret.get(labels[0]!));

      const originals: Uint8Array[] = [];
      const failure = new Error("callback failed");
      await expect(
        withDerivedWallet(
          { ...credentials },
          (_wallet, secrets) => {
            originals.push(...secrets.values());
            (secrets as Map<string, Uint8Array>).clear();
            throw failure;
          },
          options,
        ),
      ).rejects.toBe(failure);
      expect(originals).toHaveLength(labels.length);
      expect(originals.every(isZero)).toBe(true);

      const fromAsync: Uint8Array[] = [];
      await expect(
        withDerivedWallet(
          { ...credentials },
          (_wallet, secrets) => {
            fromAsync.push(...secrets.values());
            return Promise.resolve("not allowed");
          },
          options,
        ),
      ).rejects.toMatchObject({ code: "async-wallet-scope" } satisfies Partial<DerivationError>);
      expect(fromAsync).toHaveLength(labels.length);
      expect(fromAsync.every(isZero)).toBe(true);
    },
    derivationTimeoutMs,
  );

  it(
    "are refused, before any KDF work, by a profile without a key-derivation step",
    async () => {
      const onProgress = vi.fn();
      for (const profile of [krypticExternalSalt, krypticStateless]) {
        expect(profile.keyDerivation).toBeUndefined();
        const salted = profile.saltPolicy === "external-32";
        await expect(
          withDerivedWallet(
            {
              profile,
              username: credentials.username,
              password: credentials.password,
              context: { applicationId: "example-app", networkId: "kryptic-testnet" },
              ...(salted ? { salt: credentials.salt } : {}),
              onProgress,
            },
            () => undefined,
            { applicationSecrets: [labels[0]!] },
          ),
        ).rejects.toMatchObject({ code: "secret-unavailable" } satisfies Partial<DerivationError>);
      }
      expect(onProgress).not.toHaveBeenCalled();

      // Requesting none is not requesting one: the wallet still derives.
      const size = await withDerivedWallet(
        {
          profile: krypticExternalSalt,
          username: credentials.username,
          password: credentials.password,
          context: { applicationId: "example-app", networkId: "kryptic-testnet" },
          salt: credentials.salt,
        },
        (_wallet, secrets) => secrets.size,
        { applicationSecrets: [] },
      );
      expect(size).toBe(0);
      expect(extractCalls).not.toHaveBeenCalled();
    },
    derivationTimeoutMs,
  );

  it(
    "are refused by a key-derivation step that returns the scrypt output unchanged",
    async () => {
      // The wallet key would be the scrypt output, so the wallet key alone
      // would compute every secret. The core sees this only after scrypt.
      const returned: Uint8Array[] = [];
      const onProgress = vi.fn();
      const identityStep = defineDerivationProfile({
        ...kalvoraEd25519ExternalSalt,
        id: "example-identity-step-v1",
        keyDerivation: {
          id: "identity",
          deriveKey(masterSeed) {
            const key = masterSeed.slice();
            returned.push(key);
            return key;
          },
        },
      });

      await expect(
        withDerivedWallet(
          { ...credentials, profile: identityStep, onProgress },
          () => undefined,
          { applicationSecrets: [labels[0]!] },
        ),
      ).rejects.toMatchObject({ code: "secret-unavailable" } satisfies Partial<DerivationError>);
      expect(onProgress).toHaveBeenCalled();
      expect(returned).toHaveLength(1);
      expect(isZero(returned[0]!)).toBe(true);
      expect(extractCalls).not.toHaveBeenCalled();
      expect(expansions()).toHaveLength(0);

      // Requesting none still derives that profile's wallet.
      const publicKey = await withDerivedWallet(
        { ...credentials, profile: identityStep },
        (wallet) => bytesToHex(wallet.identity.publicKeyBytes),
      );
      expect(publicKey).toMatch(/^[0-9a-f]{64}$/u);
      expect(publicKey).not.toBe(secretVector.publicKeyHex);
    },
    derivationTimeoutMs,
  );

  it(
    "are refused, not silently left out, when an unfrozen profile loses its step mid-derivation",
    async () => {
      // Not a `defineDerivationProfile` result, so nothing stops the edit.
      const mutable: { -readonly [K in keyof DerivationProfile]: DerivationProfile[K] } = {
        ...kalvoraEd25519ExternalSalt,
      };
      await expect(
        withDerivedWallet(
          {
            ...credentials,
            profile: mutable,
            onProgress() {
              delete mutable.keyDerivation;
            },
          },
          (_wallet, secrets) => secrets.size,
          { applicationSecrets: [labels[0]!] },
        ),
      ).rejects.toMatchObject({ code: "secret-unavailable" } satisfies Partial<DerivationError>);
      expect(mutable.keyDerivation).toBeUndefined();
      expect(extractCalls).not.toHaveBeenCalled();
    },
    derivationTimeoutMs,
  );

  it(
    "cannot be handed back by returning them, since they are zero by then",
    async () => {
      const label = labels[0]!;
      const shapes: readonly [string, (secrets: ReadonlyMap<string, Uint8Array>) => unknown][] = [
        ["the array", (secrets) => secrets.get(label)],
        ["the map", (secrets) => secrets],
        ["a view of the array", (secrets) => secrets.get(label)!.subarray(1)],
        ["a DataView of its buffer", (secrets) => new DataView(secrets.get(label)!.buffer)],
        ["its buffer", (secrets) => secrets.get(label)!.buffer],
      ];
      const handed: Uint8Array[][] = shapes.map(() => []);
      const outcomes = await Promise.allSettled(
        shapes.map(([, shape], index) =>
          withDerivedWallet(
            { ...credentials },
            (_wallet, secrets) => {
              handed[index]!.push(...secrets.values());
              return shape(secrets);
            },
            { applicationSecrets: labels },
          ),
        ),
      );

      for (const [index, outcome] of outcomes.entries()) {
        const name = shapes[index]![0];
        expect(outcome.status, `returning ${name} must be refused`).toBe("rejected");
        expect((outcome as PromiseRejectedResult).reason).toMatchObject({
          code: "wallet-scope-closed",
        } satisfies Partial<DerivationError>);
        expect(handed[index], name).toHaveLength(labels.length);
        expect(handed[index]!.every(isZero), `${name} must still be zeroed`).toBe(true);
      }

      // A copy is the documented way out, and is not refused.
      const copy = await withDerivedWallet(
        { ...credentials },
        (_wallet, secrets) => Uint8Array.from(secrets.get(label)!),
        { applicationSecrets: [label] },
      );
      expect(bytesToHex(copy)).toBe(expectedSecret.get(label));
    },
    derivationTimeoutMs,
  );

  it(
    "are never computed on the seed path, nor when none are requested",
    async () => {
      const derived = await deriveWalletSeedUnsafe({ ...credentials });
      try {
        expect(Object.keys(derived).sort()).toEqual(["identity", "seed"]);
        expect(derived.identity.publicKey).toBe(vector.publicKeyIdentifier);
      } finally {
        derived.seed.fill(0);
      }

      // The vault's one use of that path.
      const { vault } = await createWalletVaultFromCredentials(
        { ...credentials },
        encoder.encode("another test-only vault password"),
      );
      expect(vault.publicKey).toBe(vector.publicKeyIdentifier);

      const size = await withDerivedWallet({ ...credentials }, (_wallet, secrets) => secrets.size);
      expect(size).toBe(0);

      expect(extractCalls).not.toHaveBeenCalled();
      expect(expansions()).toHaveLength(0);
      expect(hmacCalls.mock.calls.filter(([hash]) => hash === sha256)).toHaveLength(0);
      expect(probe.prkCopies).toHaveLength(0);
    },
    derivationTimeoutMs,
  );

  it(
    "differ from the wallet key, the scrypt output, the PRK and any signature",
    async () => {
      const captured: { masterSeed?: Uint8Array; seed?: Uint8Array } = {};
      const keyDerivation = kalvoraEd25519ExternalSalt.keyDerivation!;
      // Kalvora's own id and transcript, so the secrets are the committed ones;
      // the step only keeps copies of what it is handed and what it returns.
      const capturing = defineDerivationProfile({
        ...kalvoraEd25519ExternalSalt,
        keyDerivation: {
          id: keyDerivation.id,
          deriveKey(masterSeed) {
            captured.masterSeed = Uint8Array.from(masterSeed);
            const key = keyDerivation.deriveKey(masterSeed);
            captured.seed = Uint8Array.from(key);
            return key;
          },
        },
      });

      const { identity, secrets, signatures } = await withDerivedWallet(
        { ...credentials, profile: capturing },
        (wallet, derivedSecrets) => {
          const copies = [...derivedSecrets].map(([label, secret]) => [label, Uint8Array.from(secret)] as const);
          const messages = [
            encoder.encode(vector.messageUtf8),
            encoder.encode(secretVector.construction),
            ...secretVector.secrets.flatMap((entry) => [
              encoder.encode(entry.label),
              encoder.encode(entry.infoUtf8),
            ]),
            ...copies.map(([, secret]) => secret),
          ];
          return {
            identity: wallet.identity,
            secrets: copies,
            signatures: messages.map((message) => wallet.signExactMessageUnsafe(message)),
          };
        },
        { applicationSecrets: labels },
      );

      expect(bytesToHex(identity.publicKeyBytes)).toBe(vector.publicKeyHex);
      expect(ed25519.getPublicKey(captured.seed!)).toEqual(identity.publicKeyBytes);
      const forbidden = new Set([
        bytesToHex(captured.masterSeed!),
        bytesToHex(captured.seed!),
        bytesToHex(identity.publicKeyBytes),
        ...probe.prkCopies.map((prk) => bytesToHex(prk)),
        ...signatures.flatMap((signature) => [
          bytesToHex(signature.subarray(0, 32)),
          bytesToHex(signature.subarray(32)),
        ]),
      ]);
      expect(probe.prkCopies).toHaveLength(1);
      for (const [label, secret] of secrets) {
        expect(bytesToHex(secret)).toBe(expectedSecret.get(label));
        expect(forbidden.has(bytesToHex(secret))).toBe(false);
        // Not the wallet key under another name either.
        expect(ed25519.getPublicKey(secret)).not.toEqual(identity.publicKeyBytes);
      }
      expect(new Set(secrets.map(([, secret]) => bytesToHex(secret))).size).toBe(secrets.length);
    },
    derivationTimeoutMs,
  );

  it(
    "leave the wallet type unchanged, so a one-parameter callback still type-checks",
    async () => {
      const oneParameter: (wallet: DerivedWallet) => string = (wallet) => wallet.identity.address;
      await expect(withDerivedWallet({ ...credentials }, oneParameter)).resolves.toBe(vector.address);

      expectTypeOf(withDerivedWallet).parameter(1).parameter(0).toEqualTypeOf<DerivedWallet>();
      expectTypeOf(withDerivedWallet)
        .parameter(1)
        .parameter(1)
        .toEqualTypeOf<ReadonlyMap<string, Uint8Array>>();
      expectTypeOf<DerivedWallet>().toEqualTypeOf<
        Readonly<{
          identity: DerivedIdentity;
          signExactMessageUnsafe: (message: Uint8Array) => Uint8Array;
        }>
      >();
    },
    derivationTimeoutMs,
  );
});
