import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { kalvoraEd25519ExternalSalt } from "../../src/chains/kalvora.js";
import { signInEd25519ExternalSalt } from "../../src/index.js";
import { notifySecurityEvent } from "../../src/server/accountChanges.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import { createIdentityService } from "../../src/server/service.js";
import type { SqlDriver } from "../../src/server/sql.js";
import type {
  IdentityServiceConfig,
  SecurityEventNotice,
  ServiceWalletMode,
} from "../../src/server/types.js";

/**
 * What the account-change methods refuse before they reach the database: the
 * opt-ins, the mode rule and the submitted keys. The driver fails the test on
 * any query, so "refused before any SQL" is checked, not assumed. The hook's
 * bound is checked here too, with fake timers. Everything that needs
 * PostgreSQL is in accountChanges.integration.test.ts.
 */

const noSql: SqlDriver = {
  kind: "no-sql",
  async query() {
    throw new Error("This call must be refused before any SQL runs.");
  },
};

function service(
  overrides: Partial<IdentityServiceConfig> = {},
  walletMode: ServiceWalletMode = "service-deterministic",
) {
  return createIdentityService(noSql, {
    serviceProfileId: "example-account-v1",
    profile: walletMode === "random-vault" ? kalvoraEd25519ExternalSalt : signInEd25519ExternalSalt,
    applicationId: "example-app",
    networkId: "kalvora-mainnet",
    walletMode,
    ...overrides,
  });
}

async function refusal(run: () => Promise<unknown>): Promise<IdentityError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    return error as IdentityError;
  }
  throw new Error("Expected the call to be refused.");
}

async function expectCode(run: () => Promise<unknown>, code: IdentityErrorCode): Promise<void> {
  expect((await refusal(run)).code).toBe(code);
}

const goodKey = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(3)));
const smallOrderKey = `01${"00".repeat(31)}`;
const nonCanonicalKey = `f0${"ff".repeat(30)}7f`;
const forgedSignature = `01${"00".repeat(63)}`;
const uuid = "6f0d4f7e-8f53-4a9b-9a8e-2f1b0c3d4e5f";

const rotation = (publicKeyHex: string) =>
  ({
    challengeId: uuid,
    newKey: { address: `S_${publicKeyHex}`, publicKey: `S_${publicKeyHex}` },
    authorizerSignature: forgedSignature,
    subjectSignature: forgedSignature,
  }) as const;
const enrollment = (recoveryPublicKey: string) =>
  ({ challengeId: uuid, recoveryPublicKey, authorizerSignature: forgedSignature, subjectSignature: forgedSignature }) as const;
const begin = (recoveryPublicKey: string) =>
  ({ username: "ada@example.org", challengeId: uuid, recoveryPublicKey, signature: forgedSignature }) as const;

describe("the account-security opt-ins", () => {
  it("refuses rotation, enrollment and recovery with both opt-ins off (the default)", async () => {
    const off = service();
    expect(off.config.accountSecurity).toEqual({
      signInKeyRotation: false,
      recoveryKeys: false,
      emailReset: false,
      signedInReset: false,
    });
    await expectCode(() => off.rotateSignInKey("token", rotation(goodKey)), "invalid-request");
    await expectCode(() => off.enrollRecoveryKey("token", enrollment(goodKey)), "invalid-request");
    await expectCode(() => off.beginRecovery(begin(goodKey)), "invalid-request");
    await expectCode(() => off.authenticateRecovery("token"), "invalid-request");
    await expectCode(() => off.completeRecovery("token", rotation(goodKey)), "invalid-request");
  });

  it("gates rotation and recovery keys separately", async () => {
    const rotationOnly = service({ accountSecurity: { signInKeyRotation: true } });
    await expectCode(() => rotationOnly.enrollRecoveryKey("token", enrollment(goodKey)), "invalid-request");
    await expectCode(() => rotationOnly.beginRecovery(begin(goodKey)), "invalid-request");
    const recoveryOnly = service({ accountSecurity: { recoveryKeys: true } });
    await expectCode(() => recoveryOnly.rotateSignInKey("token", rotation(goodKey)), "invalid-request");
  });
});

describe("the mode rule", () => {
  it("refuses rotation, enrollment and both recovery steps in random-vault mode, opt-ins on", async () => {
    const vault = service(
      { accountSecurity: { signInKeyRotation: true, recoveryKeys: true } },
      "random-vault",
    );
    for (const run of [
      () => vault.rotateSignInKey("token", rotation(goodKey)),
      () => vault.enrollRecoveryKey("token", enrollment(goodKey)),
      () => vault.beginRecovery(begin(goodKey)),
      () => vault.authenticateRecovery("token"),
      () => vault.completeRecovery("token", rotation(goodKey)),
    ]) {
      const error = await refusal(run);
      expect(error.code).toBe("invalid-request");
      expect(error.message).toMatch(/random-vault/u);
    }
  });
});

describe("submitted keys are checked before any lookup", () => {
  const on = service({ accountSecurity: { signInKeyRotation: true, recoveryKeys: true } });

  it("refuses a small-order or non-canonical newKey with invalid-public-key", async () => {
    for (const key of [smallOrderKey, nonCanonicalKey, `ecff${"ff".repeat(29)}7f`]) {
      await expectCode(() => on.rotateSignInKey("token", rotation(key)), "invalid-public-key");
      await expectCode(() => on.completeRecovery("token", rotation(key)), "invalid-public-key");
    }
    // A key the codec refuses is the codec's invalid-public-key, also first.
    await expectCode(() => on.rotateSignInKey("token", rotation(goodKey.toUpperCase())), "invalid-public-key");
  });

  it("refuses a small-order, non-canonical or malformed recovery key with invalid-public-key", async () => {
    for (const key of [smallOrderKey, nonCanonicalKey, goodKey.toUpperCase(), `${goodKey}00`, ""]) {
      await expectCode(() => on.enrollRecoveryKey("token", enrollment(key)), "invalid-public-key");
      await expectCode(() => on.beginRecovery(begin(key)), "invalid-public-key");
    }
  });

  it("refuses an invalid email with invalid-email", async () => {
    await expectCode(
      () => on.changeEmail("token", { challengeId: uuid, email: "not an address", authorizerSignature: forgedSignature }),
      "invalid-email",
    );
  });
});

describe("notifySecurityEvent", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  const event: SecurityEventNotice = Object.freeze({
    action: "account.key-rotate",
    accountId: uuid,
    occurredAt: new Date("2026-10-18T12:00:00.000Z"),
    clientLabel: "Firefox on macOS",
    revokedSessions: 2,
  });

  it("awaits the hook with the event", async () => {
    const seen: SecurityEventNotice[] = [];
    let finished = false;
    await notifySecurityEvent(async (received) => {
      await Promise.resolve();
      seen.push(received);
      finished = true;
    }, event);
    expect(finished).toBe(true);
    expect(seen).toEqual([event]);
  });

  it("returns at the bound when the hook never settles", async () => {
    vi.useFakeTimers();
    let settled = false;
    const pending = notifySecurityEvent(() => new Promise<void>(() => undefined), event, 3_000).then(() => {
      settled = true;
    });
    await vi.advanceTimersByTimeAsync(2_999);
    expect(settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await pending;
    expect(settled).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("swallows a hook that throws or rejects, and clears its timer", async () => {
    vi.useFakeTimers();
    await notifySecurityEvent(() => {
      throw new Error("sync failure");
    }, event);
    await notifySecurityEvent(async () => {
      throw new Error("async failure");
    }, event);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("does nothing without a hook", async () => {
    await expect(notifySecurityEvent(null, event)).resolves.toBeUndefined();
  });
});
