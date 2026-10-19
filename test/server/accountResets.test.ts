import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { kalvoraEd25519ExternalSalt } from "../../src/chains/kalvora.js";
import { signInEd25519ExternalSalt } from "../../src/index.js";
import { IdentityError, enumerationSensitiveCodes, identityErrorStatus, type IdentityErrorCode } from "../../src/server/errors.js";
import { createIdentityService } from "../../src/server/service.js";
import type { SqlDriver } from "../../src/server/sql.js";
import type { AccountSecurityOptions, ServiceWalletMode } from "../../src/server/types.js";

/**
 * What the reset methods refuse before they reach the database: the opt-ins,
 * the mode rule and their inputs. The driver fails the test on any query, so
 * "refused before any SQL" is checked, not assumed. Everything that needs
 * PostgreSQL is in accountResets.integration.test.ts.
 */

const noSql: SqlDriver = {
  kind: "no-sql",
  async query() {
    throw new Error("This call must be refused before any SQL runs.");
  },
};

function service(accountSecurity: AccountSecurityOptions = {}, walletMode: ServiceWalletMode = "service-deterministic") {
  return createIdentityService(noSql, {
    serviceProfileId: "example-account-v1",
    profile: walletMode === "random-vault" ? kalvoraEd25519ExternalSalt : signInEd25519ExternalSalt,
    applicationId: "example-app",
    networkId: "kalvora-mainnet",
    walletMode,
    accountSecurity,
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

async function expectCode(run: () => Promise<unknown>, code: IdentityErrorCode): Promise<IdentityError> {
  const error = await refusal(run);
  expect(error.code).toBe(code);
  return error;
}

/** The call got past every check that needs no database: it reached the driver. */
async function reachesSql(run: () => Promise<unknown>): Promise<void> {
  await expect(run()).rejects.toThrow("This call must be refused before any SQL runs.");
}

const goodKey = `S_${bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(3)))}`;
const smallOrderKey = `S_01${"00".repeat(31)}`;
const signature = `01${"00".repeat(63)}`;
const uuid = "6f0d4f7e-8f53-4a9b-9a8e-2f1b0c3d4e5f";
const key = (identifier: string) => ({ address: identifier, publicKey: identifier });

const all = { signInKeyRotation: true, recoveryKeys: true, emailReset: true, signedInReset: true } as const;

describe("the reset opt-ins", () => {
  it("refuses the resets with every opt-in off (the default), before any SQL", async () => {
    const off = service();
    await expectCode(() => off.startAccountReset({ username: "ada@example.org" }), "invalid-request");
    await expectCode(
      () => off.completeAccountReset({ username: "ada@example.org", resetId: uuid, code: "ABCD2345", challengeId: uuid, newKey: key(goodKey), subjectSignature: signature }),
      "invalid-request",
    );
    await expectCode(() => off.startSignedInReset("token"), "invalid-request");
    await expectCode(
      () => off.completeSignedInReset("token", { challengeId: uuid, resetId: uuid, newKey: key(goodKey), subjectSignature: signature }),
      "invalid-request",
    );
    for (const setting of ["email-reset", "signed-in-reset"] as const) {
      await expectCode(
        () => off.setAccountResetSetting("token", { challengeId: uuid, setting, enabled: true, authorizerSignature: signature }),
        "invalid-request",
      );
      // Turning a setting off needs no opt-in.
      await reachesSql(() => off.setAccountResetSetting("token", { challengeId: uuid, setting, enabled: false, authorizerSignature: signature }));
    }
    // Neither do the abort, the status and reauthentication.
    await reachesSql(() => off.abortSignedInReset("token"));
    await reachesSql(() => off.accountResetStatus("token"));
    await reachesSql(() => off.verifyReauthentication("token", { challengeId: uuid, label: "example-label", authorizerSignature: signature }));
  });

  it("gates account recovery by email and the signed-in reset separately", async () => {
    const emailOnly = service({ emailReset: true });
    await expectCode(() => emailOnly.startSignedInReset("token"), "invalid-request");
    await reachesSql(() => emailOnly.startAccountReset({ username: "ada@example.org" }));
    const signedInOnly = service({ signedInReset: true });
    await expectCode(() => signedInOnly.startAccountReset({ username: "ada@example.org" }), "invalid-request");
    await reachesSql(() => signedInOnly.startSignedInReset("token"));
  });
});

describe("the mode rule", () => {
  it("refuses the resets and the settings in random-vault mode, opt-ins on", async () => {
    const vault = service(all, "random-vault");
    for (const run of [
      () => vault.startAccountReset({ username: "ada@example.org" }),
      () => vault.completeAccountReset({ username: "ada@example.org", resetId: uuid, code: "ABCD2345", challengeId: uuid, newKey: key(goodKey), subjectSignature: signature }),
      () => vault.startSignedInReset("token"),
      () => vault.completeSignedInReset("token", { challengeId: uuid, resetId: uuid, newKey: key(goodKey), subjectSignature: signature }),
      () => vault.setAccountResetSetting("token", { challengeId: uuid, setting: "email-reset", enabled: true, authorizerSignature: signature }),
      () => vault.setAccountResetSetting("token", { challengeId: uuid, setting: "signed-in-reset", enabled: false, authorizerSignature: signature }),
    ]) {
      const error = await refusal(run);
      expect(error.code).toBe("invalid-request");
      expect(error.message).toMatch(/random-vault/u);
    }
    // Reauthentication changes no key, so it works in every mode.
    await reachesSql(() => vault.verifyReauthentication("token", { challengeId: uuid, label: "example-label", authorizerSignature: signature }));
  });
});

describe("inputs are checked before any lookup", () => {
  const on = service(all);

  it("refuses a malformed setting, value, label, reset id, code or key", async () => {
    for (const setting of ["email", "Email-reset", "recovery-key", ""]) {
      await expectCode(
        () => on.setAccountResetSetting("token", { challengeId: uuid, setting: setting as "email-reset", enabled: true, authorizerSignature: signature }),
        "invalid-request",
      );
    }
    for (const enabled of ["true", 1, null]) {
      await expectCode(
        () => on.setAccountResetSetting("token", { challengeId: uuid, setting: "email-reset", enabled: enabled as unknown as boolean, authorizerSignature: signature }),
        "invalid-request",
      );
    }
    for (const label of ["ab", "Example-label", "-label", "a".repeat(81), "with space", 42]) {
      await expectCode(
        () => on.verifyReauthentication("token", { challengeId: uuid, label: label as string, authorizerSignature: signature }),
        "invalid-request",
      );
    }
    for (const resetId of ["not-a-uuid", "", `${uuid}0`]) {
      await expectCode(
        () => on.completeSignedInReset("token", { challengeId: uuid, resetId, newKey: key(goodKey), subjectSignature: signature }),
        "invalid-request",
      );
    }
    await expectCode(
      () => on.completeSignedInReset("token", { challengeId: uuid, resetId: uuid, newKey: key(goodKey), subjectSignature: signature, code: 12345678 as unknown as string }),
      "invalid-request",
    );
    await expectCode(
      () => on.completeSignedInReset("token", { challengeId: uuid, resetId: uuid, newKey: key(smallOrderKey), subjectSignature: signature }),
      "invalid-public-key",
    );
    await expectCode(
      () => on.completeAccountReset({ username: "ada@example.org", resetId: uuid, code: "ABCD2345", challengeId: uuid, newKey: key(smallOrderKey), subjectSignature: signature }),
      "invalid-public-key",
    );
    await expectCode(() => on.startAccountReset({ username: "x" }), "invalid-username");
    await expectCode(() => on.startAccountReset(null as unknown as { username: string }), "invalid-request");
  });
});

describe("the reset error codes", () => {
  it("are 409s that need a session, and none is enumeration-sensitive", () => {
    for (const code of ["reset-pending", "reset-setting-refused", "reset-unavailable"] as const) {
      expect(identityErrorStatus(code)).toBe(409);
      expect(enumerationSensitiveCodes.has(code)).toBe(false);
    }
    expect([...enumerationSensitiveCodes].sort()).toEqual(["account-not-found", "invalid-signature", "wallet-mismatch"]);
  });
});
