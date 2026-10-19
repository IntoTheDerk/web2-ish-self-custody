import { describe, expect, it } from "vitest";
import {
  ACCOUNT_CHANGE_DOMAIN,
  DerivationError,
  accountChangeActions,
  buildAccountChangeMessage,
  normalizeEmail,
  type AccountChangeAction,
  type AccountChangeMessageInput,
  type DerivationErrorCode,
} from "../src/index.js";
import vector from "../vectors/account-change-v1.json" with { type: "json" };

/**
 * The account-change message from the core entry, against the committed
 * vector (reproduced independently by scripts/verify_account_change_vector.py)
 * and against every refusal the builder owes a signer: a client builds these
 * bytes from typed fields, so the builder is what keeps it from signing
 * anything else.
 */

const context = vector.context;
const expiresAt = new Date(context.expiresAt);

function input(overrides: Partial<Record<keyof AccountChangeMessageInput, unknown>> = {}): AccountChangeMessageInput {
  return {
    serviceProfileId: context.serviceProfileId,
    applicationId: context.applicationId,
    networkId: context.networkId,
    action: "sign-in-key-rotation",
    usernameNormalized: context.usernameNormalized,
    nonceHex: context.nonceHex,
    expiresAt,
    authorizer: vector.keys.current.principal,
    subject: vector.keys.next.principal,
    ...overrides,
  } as AccountChangeMessageInput;
}

function expectCode(run: () => unknown, code: DerivationErrorCode): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(DerivationError);
    expect((error as DerivationError).code).toBe(code);
    return;
  }
  throw new Error(`Expected a DerivationError "${code}", but nothing was thrown.`);
}

describe("buildAccountChangeMessage", () => {
  it("reproduces every committed message byte for byte", () => {
    expect(vector.format).toBe(ACCOUNT_CHANGE_DOMAIN);
    expect(vector.cases.map((entry) => entry.action).sort()).toEqual([...accountChangeActions].sort());
    for (const entry of vector.cases) {
      const built = buildAccountChangeMessage(
        input({ action: entry.action, authorizer: entry.authorizer, subject: entry.subject }),
      );
      expect(built).toBe(entry.messageUtf8);
      expect(new TextEncoder().encode(built)).toEqual(new TextEncoder().encode(entry.messageUtf8));
    }
  });

  it("is ten lines with no trailing newline, and never the 8-line login challenge", () => {
    const built = buildAccountChangeMessage(input());
    const lines = built.split("\n");
    expect(lines).toHaveLength(10);
    expect(lines[0]).toBe("web2-ish-self-custody account change v1");
    expect(lines[0]).not.toBe("web2-ish-self-custody auth challenge v1");
    expect(lines[7]).toBe("2026-10-18T12:05:00.000Z");
    expect(built.endsWith("\n")).toBe(false);
  });

  it("defines exactly this release's six actions", () => {
    expect(accountChangeActions).toEqual([
      "sign-in-key-rotation",
      "email-change",
      "recovery-key-enrollment",
      "recovery-key-removal",
      "recovery-begin",
      "recovery-reset",
    ]);
    expect(Object.isFrozen(accountChangeActions)).toBe(true);
  });

  it("refuses a line break in any field", () => {
    const breaks = ["\n", "\r", "\u000b", "\u000c", "\u0085", " ", " "];
    const fields = [
      "serviceProfileId",
      "applicationId",
      "networkId",
      "usernameNormalized",
      "nonceHex",
      "authorizer",
      "subject",
    ] as const;
    for (const field of fields) {
      for (const lineBreak of breaks) {
        const value = `${String(input()[field])}${lineBreak}x`;
        expectCode(() => buildAccountChangeMessage(input({ [field]: value })), "invalid-message");
      }
    }
    expectCode(() => buildAccountChangeMessage(input({ action: "sign-in-key-rotation\nemail-change" })), "invalid-message");
  });

  it("refuses an unknown action, including the next release's", () => {
    for (const action of [
      "wallet-rotation",
      "reauthentication",
      "email-reset-setting",
      "signed-in-reset-setting",
      "email-reset",
      "signed-in-reset",
      "recovery-secret-read",
      "toString",
      "__proto__",
      "",
    ]) {
      expectCode(
        () => buildAccountChangeMessage(input({ action: action as AccountChangeAction })),
        "invalid-message",
      );
    }
  });

  it("refuses an authorizer or subject in any form but the action's row", () => {
    const key = vector.keys.current.principal;
    const recovery = vector.keys.recovery.principal;
    const wrong: readonly Readonly<{ action: AccountChangeAction; authorizer: string; subject: string }>[] = [
      { action: "sign-in-key-rotation", authorizer: recovery, subject: key },
      { action: "sign-in-key-rotation", authorizer: key, subject: "none" },
      { action: "sign-in-key-rotation", authorizer: `wallet:${key.slice(4)}`, subject: key },
      { action: "email-change", authorizer: key, subject: "email:New@Example.com" },
      { action: "email-change", authorizer: key, subject: "email: new@example.com" },
      { action: "email-change", authorizer: key, subject: "email:not-an-address" },
      { action: "email-change", authorizer: key, subject: key },
      { action: "recovery-key-enrollment", authorizer: key, subject: recovery.toUpperCase() },
      { action: "recovery-key-enrollment", authorizer: key, subject: `recovery-key:${"ab".repeat(31)}` },
      { action: "recovery-key-enrollment", authorizer: key, subject: key },
      { action: "recovery-key-removal", authorizer: key, subject: "" },
      { action: "recovery-key-removal", authorizer: key, subject: "None" },
      { action: "recovery-begin", authorizer: key, subject: "none" },
      { action: "recovery-begin", authorizer: recovery, subject: key },
      { action: "recovery-reset", authorizer: key, subject: key },
      { action: "recovery-reset", authorizer: recovery, subject: recovery },
      // `host:` arrives with `reauthentication` in the next release.
      { action: "recovery-key-removal", authorizer: key, subject: "host:example-label" },
      { action: "sign-in-key-rotation", authorizer: "key:", subject: key },
      { action: "sign-in-key-rotation", authorizer: "key:has space", subject: key },
      { action: "sign-in-key-rotation", authorizer: `key:${"x".repeat(161)}`, subject: key },
    ];
    for (const fields of wrong) {
      expectCode(() => buildAccountChangeMessage(input(fields)), "invalid-message");
    }
  });

  it("refuses a username that is not normalized, a malformed nonce, context or expiry", () => {
    for (const overrides of [
      { usernameNormalized: "Jesse@example.com" },
      { usernameNormalized: " jesse@example.com" },
      { usernameNormalized: "jo" },
      { nonceHex: context.nonceHex.toUpperCase() },
      { nonceHex: context.nonceHex.slice(2) },
      { serviceProfileId: "Example-Account" },
      { applicationId: "" },
      { networkId: "kalvora mainnet" },
      { expiresAt: new Date("not a date") },
      { expiresAt: context.expiresAt },
      { authorizer: 42 },
    ] as const) {
      expectCode(() => buildAccountChangeMessage(input(overrides)), "invalid-message");
    }
    expectCode(() => buildAccountChangeMessage(null as unknown as AccountChangeMessageInput), "invalid-message");
  });

  it("binds every field: changing any one changes the bytes", () => {
    const reference = buildAccountChangeMessage(input());
    const variants = [
      input({ serviceProfileId: "example-account-v2" }),
      input({ applicationId: "other-app" }),
      input({ networkId: "kalvora-testnet" }),
      input({ usernameNormalized: "other@example.com" }),
      input({ nonceHex: "00".repeat(32) }),
      input({ expiresAt: new Date(expiresAt.getTime() + 1) }),
      input({ subject: vector.keys.current.principal }),
    ];
    for (const variant of variants) {
      expect(buildAccountChangeMessage(variant)).not.toBe(reference);
    }
  });
});

describe("normalizeEmail", () => {
  it("normalizes the vector's email input to its subject", () => {
    const entry = vector.cases.find((candidate) => candidate.action === "email-change");
    expect(entry).toBeDefined();
    expect(`email:${normalizeEmail(entry!.emailInput!)}`).toBe(entry!.subject);
  });

  it("trims and lowercases, and refuses anything that is not a plain address", () => {
    expect(normalizeEmail("  Ada@Example.ORG\t")).toBe("ada@example.org");
    for (const value of [
      "",
      "ada",
      "ada@",
      "@example.org",
      "ada@example",
      "a da@example.org",
      "ada@exa_mple.org",
      "ada@-example.org",
      `${"a".repeat(65)}@example.org`,
      `ada@${"a".repeat(250)}.org`,
      "ada@example.org\nbcc@example.org",
      42 as unknown as string,
    ]) {
      expectCode(() => normalizeEmail(value), "invalid-email");
    }
  });

  it("refuses C0 and C1 controls and DEL in the local part", () => {
    for (const code of [0x00, 0x01, 0x1f, 0x7f, 0x80, 0x85, 0x9f]) {
      const value = `a${String.fromCharCode(code)}b@example.com`;
      expectCode(() => normalizeEmail(value), "invalid-email");
    }
  });

  it("returns only addresses the builder accepts as an email: subject", () => {
    // Every code point the local part could hold that is not plain ASCII
    // printable: whatever normalizeEmail accepts, the builder must too.
    for (let code = 0; code <= 0x3000; code += 1) {
      if (code >= 0xd800 && code <= 0xdfff) {
        continue;
      }
      let address: string;
      try {
        address = normalizeEmail(`a${String.fromCodePoint(code)}b@example.com`);
      } catch {
        continue;
      }
      expect(() =>
        buildAccountChangeMessage(
          input({ action: "email-change", subject: `email:${address}` }),
        ),
      ).not.toThrow();
    }
  });
});
