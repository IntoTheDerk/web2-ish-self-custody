import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAccountChangeMessage,
  signInEd25519ExternalSalt,
  type AccountChangeAction,
} from "../../src/index.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import {
  createIdentityRouter,
  createIdentityService,
  pgDriver,
  type IdentityChallenge,
  type IdentityService,
  type IdentityServiceConfig,
  type IssuedSession,
  type RequestContext,
  type SecondFactorContext,
  type SecondFactorIdentityServiceConfig,
  type SecondFactorVerdict,
  type SqlDriver,
  type SqlRow,
} from "../../src/server/index.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * The `secondFactor` option over real PostgreSQL (migration 12): login,
 * account recovery by email and recovery-key completion answer with a ticket
 * instead of a session when the host's `required` says so, and
 * `completeSecondFactor` issues the session. A second service on the same
 * tables, without the option, shows that nothing changes for it. Gated on
 * W2SC_TEST_DATABASE_URL like the other server suites.
 */
const url = process.env["W2SC_TEST_DATABASE_URL"];

type Client = {
  connect(): Promise<void>;
  end(): Promise<void>;
  query(text: string, parameters?: readonly unknown[]): Promise<{ rows: SqlRow[] }>;
};

const encoder = new TextEncoder();
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
const prefix = `wsf_${suffix}`;
const serviceProfileId = `w2sc-second-factor-${suffix}`;
const tables = [
  "second_factor_tickets", "account_resets", "account_recoveries", "account_recovery_keys", "wallet_setups",
  "wallet_policy", "audit_events", "rate_limits", "email_verifications", "sessions", "auth_challenges",
  "account_wallets", "accounts", "service_profile_bootstrap", "service_profiles", "schema_migrations",
];

const base: IdentityServiceConfig = {
  serviceProfileId,
  profile: signInEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-testnet",
  tablePrefix: prefix,
  sessionTtlSeconds: 30 * 86_400,
  accountSecurity: { signInKeyRotation: true, recoveryKeys: true, emailReset: true, signedInReset: true },
};

/** The host's factor, faked: which accounts need it, their code, and a lockout. */
type FakeFactor = { required: boolean | "throw" | "undefined"; code: string; locked: boolean; verifyThrows: boolean };
const factors = new Map<string, FakeFactor>();
const requiredCalls: Array<Readonly<{ accountId: string; context: SecondFactorContext }>> = [];
const verifyCalls: Array<Readonly<{ accountId: string; ticketId: string; code: string }>> = [];

const gatedConfig: SecondFactorIdentityServiceConfig = {
  ...base,
  secondFactor: {
    async required(accountId, context) {
      requiredCalls.push({ accountId, context });
      const factor = factors.get(accountId);
      if (factor?.required === "throw") throw new Error("verifier store down");
      if (factor?.required === "undefined") return undefined as unknown as boolean;
      return factor?.required ?? false;
    },
    async verify(accountId, ticketId, code): Promise<SecondFactorVerdict> {
      verifyCalls.push({ accountId, ticketId, code });
      const factor = factors.get(accountId);
      if (factor === undefined) return "invalid";
      if (factor.verifyThrows) throw new Error("verifier down");
      if (factor.locked) return "locked";
      return code === factor.code ? "ok" : "invalid";
    },
  },
};

type Key = Readonly<{ secret: Uint8Array; publicKeyHex: string; identifier: string }>;

function newKey(): Key {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const publicKeyHex = bytesToHex(ed25519.getPublicKey(secret));
  return Object.freeze({ secret, publicKeyHex, identifier: `S_${publicKeyHex}` });
}

function sign(key: Key, message: string): string {
  return bytesToHex(ed25519.sign(encoder.encode(message), key.secret));
}

const keyPrincipal = (key: Key): string => `key:${key.identifier}`;
const enrolled = (key: Key) => ({ address: key.identifier, publicKey: key.identifier });

let ipCounter = 0;
function ctx(extra: Omit<RequestContext, "ipHash"> = {}): RequestContext {
  ipCounter += 1;
  return { ipHash: `ip-${suffix}-${String(ipCounter)}`, ...extra };
}

function username(label: string): string {
  return `${label}-${crypto.randomUUID().slice(0, 8)}@example.com`;
}

function messageFor(challenge: IdentityChallenge, action: AccountChangeAction, authorizer: string, subject: string): string {
  return buildAccountChangeMessage({
    serviceProfileId,
    applicationId: "example-app",
    networkId: "kalvora-testnet",
    action,
    usernameNormalized: challenge.usernameNormalized,
    nonceHex: challenge.message.split("\n")[6]!,
    expiresAt: challenge.expiresAt,
    authorizer,
    subject,
  });
}

let first: Client;
let plain: IdentityService;
let gated: IdentityService<true>;
const statements: string[] = [];

/** Records every statement text the plain service sends. */
function recordingDriver(inner: SqlDriver): SqlDriver {
  return {
    kind: inner.kind,
    query(text, parameters) {
      statements.push(text);
      return inner.query(text, parameters);
    },
  };
}

type Registered = Readonly<{ name: string; key: Key; accountId: string; session: IssuedSession }>;

async function register(label: string, factor?: Partial<FakeFactor>, email?: string): Promise<Registered> {
  const name = username(label);
  const key = newKey();
  if (email !== undefined) {
    const started = await gated.startEmailVerification({ username: name, email }, ctx());
    await gated.confirmEmailVerification(started.verificationId, started.code, ctx());
  }
  const challenge = await gated.createChallenge(name, "registration", ctx());
  const registered = await gated.register(
    {
      username: name,
      address: key.identifier,
      publicKey: key.identifier,
      challengeId: challenge.id,
      signature: sign(key, challenge.message),
      ...(email === undefined ? {} : { email }),
    },
    ctx(),
  );
  if (factor !== undefined) {
    factors.set(registered.account.id, { required: true, code: "123456", locked: false, verifyThrows: false, ...factor });
  }
  return { name, key, accountId: registered.account.id, session: registered.session };
}

async function login(account: Readonly<{ name: string }>, key: Key, via: IdentityService<boolean> = gated, context = ctx()) {
  const challenge = await via.createChallenge(account.name, "login", ctx());
  return via.login({ username: account.name, challengeId: challenge.id, signature: sign(key, challenge.message) }, context);
}

async function ticketFor(account: Registered, key: Key = account.key): Promise<string> {
  const result = await login(account, key);
  expect(result.session).toBeUndefined();
  expect(result.secondFactor).toBe("totp");
  return result.ticket!;
}

async function rejection(run: () => Promise<unknown>): Promise<IdentityError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    return error as IdentityError;
  }
  throw new Error("Expected the call to reject with an IdentityError.");
}

async function expectCode(run: () => Promise<unknown>, code: IdentityErrorCode): Promise<IdentityError> {
  const error = await rejection(run);
  expect(error.code).toBe(code);
  return error;
}

async function audit(accountId: string, action: string): Promise<readonly SqlRow[]> {
  return (
    await first.query(
      `SELECT metadata FROM ${prefix}_audit_events WHERE account_id = $1::uuid AND action = $2 ORDER BY created_at, id`,
      [accountId, action],
    )
  ).rows;
}

async function sessionCount(accountId: string): Promise<number> {
  return Number(
    (await first.query(`SELECT count(*)::int AS n FROM ${prefix}_sessions WHERE account_id = $1::uuid`, [accountId]))
      .rows[0]?.["n"],
  );
}

async function ticketRows(accountId: string): Promise<readonly SqlRow[]> {
  return (
    await first.query(`SELECT * FROM ${prefix}_second_factor_tickets WHERE account_id = $1::uuid ORDER BY created_at`, [accountId])
  ).rows;
}

/** The account's `login-account` count, as `[count]`, or `[]` without a row. */
async function accountGuessesOf(accountId: string): Promise<number[]> {
  const bucket = bytesToHex(
    sha256(encoder.encode(["web2-ish-self-custody rate limit bucket v1", serviceProfileId, "login-account", accountId].join("\n"))),
  );
  const rows = (await first.query(`SELECT count FROM ${prefix}_rate_limits WHERE bucket = $1::text`, [bucket])).rows;
  return rows.map((row) => Number(row["count"]));
}

async function authenticates(token: string): Promise<boolean> {
  try {
    await gated.authenticate(token);
    return true;
  } catch {
    return false;
  }
}

describe.skipIf(!url)("the second sign-in factor on PostgreSQL", () => {
  beforeAll(async () => {
    const moduleName: string = "pg";
    const pg = (await import(moduleName)) as { Client: new (options: { connectionString: string }) => Client };
    first = new pg.Client({ connectionString: url! });
    await first.connect();
    gated = createIdentityService(pgDriver(first), gatedConfig);
    plain = createIdentityService(recordingDriver(pgDriver(first)), base);
    expect(await gated.migrate()).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
  }, 60_000);

  afterAll(async () => {
    if (!first) return;
    await first.query(`DROP TABLE IF EXISTS ${tables.map((t) => `${prefix}_${t}`).join(", ")} CASCADE`);
    await first.query(`DROP FUNCTION IF EXISTS ${prefix}_reject_immutable_mutation() CASCADE`);
    await first.end();
  }, 60_000);

  describe("migration 12", () => {
    it("stores tickets only as 64-hex digests, at most five attempts, one per challenge", async () => {
      const row = (
        await first.query(
          `SELECT
             (SELECT count(*)::int FROM pg_constraint WHERE conrelid = to_regclass($1) AND contype = 'c') AS checks,
             (SELECT count(*)::int FROM pg_constraint WHERE conrelid = to_regclass($1) AND contype = 'u') AS uniques`,
          [`${prefix}_second_factor_tickets`],
        )
      ).rows[0]!;
      expect(row["checks"]).toBe(5);
      expect(row["uniques"]).toBe(2);
    });
  });

  describe("without the option", () => {
    it("issues the session at login exactly as before and never reads the ticket table", async () => {
      const account = await register("plain");
      factors.set(account.accountId, { required: true, code: "123456", locked: false, verifyThrows: false });
      statements.length = 0;
      const before = requiredCalls.length;
      const result = await login(account, account.key, plain);
      expect(result.session).toBeDefined();
      expect(Object.keys(result).sort()).toEqual(["account", "session"]);
      expect(requiredCalls.length).toBe(before);
      expect(statements.some((text) => text.includes("second_factor"))).toBe(false);
      expect(await ticketRows(account.accountId)).toEqual([]);
    });

    it("refuses completeSecondFactor and mounts no second-factor route", async () => {
      await expectCode(() => plain.completeSecondFactor({ ticket: "a".repeat(43), code: "1" }), "invalid-request");
      const router = createIdentityRouter(plain, { useCookies: false });
      const response = await router(
        new Request("https://id.example/identity/sessions/second-factor", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ ticket: "x", code: "1" }),
        }),
      );
      expect(response.status).toBe(404);
    });
  });

  describe("login", () => {
    it("asks required only after the signature verified, with the purpose and the request context", async () => {
      const account = await register("ask", { required: false });
      const before = requiredCalls.length;
      const challenge = await gated.createChallenge(account.name, "login", ctx());
      await expectCode(
        () => gated.login({ username: account.name, challengeId: challenge.id, signature: sign(newKey(), challenge.message) }, ctx()),
        "invalid-signature",
      );
      expect(requiredCalls.length).toBe(before);
      const context = ctx({ clientLabel: "Firefox on macOS" });
      const result = await login(account, account.key, gated, context);
      expect(result.session).toBeDefined();
      expect(requiredCalls.at(-1)).toEqual({ accountId: account.accountId, context: { ...context, purpose: "login" } });
      expect(await ticketRows(account.accountId)).toEqual([]);
    });

    it("issues a hashed ticket bound to the account, the challenge and the signing key, and no session", async () => {
      const account = await register("ticket", {});
      const sessionsBefore = await sessionCount(account.accountId);
      const challenge = await gated.createChallenge(account.name, "login", ctx());
      const result = await gated.login(
        { username: account.name, challengeId: challenge.id, signature: sign(account.key, challenge.message) },
        ctx({ clientLabel: "Safari on iOS" }),
      );
      expect(result.session).toBeUndefined();
      expect(result.secondFactor).toBe("totp");
      expect(result.ticket).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(result.expiresAt!.getTime() - Date.now()).toBeGreaterThan(290_000);
      expect(result.expiresAt!.getTime() - Date.now()).toBeLessThanOrEqual(300_000);
      expect(await sessionCount(account.accountId)).toBe(sessionsBefore);
      expect(await audit(account.accountId, "account.login")).toHaveLength(0);
      const [row] = await ticketRows(account.accountId);
      expect(row!["ticket_hash"]).toMatch(/^[0-9a-f]{64}$/u);
      expect(row!["ticket_hash"]).not.toBe(bytesToHex(sha256(encoder.encode(result.ticket!))));
      expect(JSON.stringify(row)).not.toContain(result.ticket!);
      expect(row!["challenge_id"]).toBe(challenge.id);
      expect(row!["public_key"]).toBe(account.key.identifier);
      expect(row!["purpose"]).toBe("login");
      expect(row!["attempts"]).toBe(0);
      expect(row!["client_label"]).toBe("Safari on iOS");
    });

    it("fails closed: a non-boolean answer gates, a throw refuses the sign-in", async () => {
      const unsure = await register("unsure", { required: "undefined" });
      expect((await login(unsure, unsure.key)).secondFactor).toBe("totp");
      const broken = await register("broken", { required: "throw" });
      const sessionsBefore = await sessionCount(broken.accountId);
      await expect(login(broken, broken.key)).rejects.toThrow("verifier store down");
      expect(await sessionCount(broken.accountId)).toBe(sessionsBefore);
      expect(await ticketRows(broken.accountId)).toEqual([]);
    });
  });

  describe("completeSecondFactor", () => {
    it("issues the session on ok in the statement that consumes the ticket, and audits it", async () => {
      const account = await register("ok", {});
      const ticket = await ticketFor(account);
      const [row] = await ticketRows(account.accountId);
      const completed = await gated.completeSecondFactor({ ticket, code: "123456" }, ctx());
      expect(completed.purpose).toBe("login");
      expect(completed.account.id).toBe(account.accountId);
      expect(await authenticates(completed.session.token)).toBe(true);
      expect(verifyCalls.at(-1)).toEqual({ accountId: account.accountId, ticketId: row!["id"], code: "123456" });
      const consumed = (await ticketRows(account.accountId))[0]!;
      expect(consumed["consumed_at"]).not.toBeNull();
      expect(consumed["attempts"]).toBe(1);
      const ok = await audit(account.accountId, "session.second-factor-ok");
      expect(ok.map((r) => r["metadata"])).toEqual([{ purpose: "login", sessionId: completed.session.session.id }]);
      const logins = await audit(account.accountId, "account.login");
      expect(logins.at(-1)!["metadata"]).toMatchObject({ secondFactor: true, sessionId: completed.session.session.id });
      // The label the login request carried.
      const label = (await first.query(`SELECT client_label FROM ${prefix}_sessions WHERE id = $1::uuid`, [completed.session.session.id])).rows[0];
      expect(label!["client_label"]).toBe(consumed["client_label"]);
    });

    it("refuses a replayed ticket without calling the verifier again", async () => {
      const account = await register("replay", {});
      const ticket = await ticketFor(account);
      await gated.completeSecondFactor({ ticket, code: "123456" }, ctx());
      const calls = verifyCalls.length;
      await expectCode(() => gated.completeSecondFactor({ ticket, code: "123456" }, ctx()), "second-factor-ticket-invalid");
      expect(verifyCalls.length).toBe(calls);
      expect(await sessionCount(account.accountId)).toBe(2);
    });

    it("issues one session when two completions of one ticket race", async () => {
      const account = await register("race", {});
      const ticket = await ticketFor(account);
      const results = await Promise.allSettled([
        gated.completeSecondFactor({ ticket, code: "123456" }, ctx()),
        gated.completeSecondFactor({ ticket, code: "123456" }, ctx()),
      ]);
      expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
      const failed = results.find((r) => r.status === "rejected") as PromiseRejectedResult;
      expect((failed.reason as IdentityError).code).toBe("second-factor-ticket-invalid");
      expect(await sessionCount(account.accountId)).toBe(2);
    });

    it("counts a wrong code as an attempt and still accepts the right one afterwards", async () => {
      const account = await register("wrong", {});
      const ticket = await ticketFor(account);
      const error = await expectCode(() => gated.completeSecondFactor({ ticket, code: "000000" }, ctx()), "second-factor-invalid");
      expect(error.status).toBe(401);
      expect(error.details).toEqual({ attemptsRemaining: 4 });
      const failed = await audit(account.accountId, "session.second-factor-failed");
      expect(failed.map((r) => r["metadata"])).toEqual([{ purpose: "login", reason: "invalid", attempts: 1, exhausted: false }]);
      const completed = await gated.completeSecondFactor({ ticket, code: "123456" }, ctx());
      expect(await authenticates(completed.session.token)).toBe(true);
      // The wrong code stays counted against the account; the right one gave its unit back.
      expect(await accountGuessesOf(account.accountId)).toEqual([1]);
    });

    it("bounds wrong codes per account across abandoned tickets, outstanding tickets and addresses", async () => {
      const account = await register("abandon", {});
      // Issued before the bucket fills: still bound by it afterwards.
      const outstanding = await ticketFor(account);
      for (let ticketNumber = 1; ticketNumber <= 6; ticketNumber += 1) {
        const ticket = await ticketFor(account);
        // Four wrong codes, then abandoned: the ticket never dies.
        for (let attempt = 1; attempt <= 4; attempt += 1) {
          await expectCode(() => gated.completeSecondFactor({ ticket, code: "999999" }, ctx()), "second-factor-invalid");
        }
      }
      const last = await ticketFor(account);
      // The 25th wrong code is still tested ...
      await expectCode(() => gated.completeSecondFactor({ ticket: last, code: "999999" }, ctx()), "second-factor-invalid");
      expect((await audit(account.accountId, "session.second-factor-failed")).every(
        (r) => (r["metadata"] as Record<string, unknown>)["exhausted"] === false,
      )).toBe(true);
      // ... the 26th is refused unseen by the verifier, as is the right code on
      // a ticket issued before the bucket filled, whatever the address.
      const calls = verifyCalls.length;
      const limited = await expectCode(() => gated.completeSecondFactor({ ticket: last, code: "999999" }, ctx()), "rate-limited");
      expect(limited.details?.["rule"]).toBe("login-account");
      await expectCode(() => gated.completeSecondFactor({ ticket: outstanding, code: "123456" }, ctx()), "rate-limited");
      expect(verifyCalls.length).toBe(calls);
      await expectCode(() => login(account, account.key), "rate-limited");
      expect(await sessionCount(account.accountId)).toBe(1);
      // An hour later the outstanding ticket has expired, and a fresh sign-in works.
      const later = ctx({ now: new Date(Date.now() + 3_601_000) });
      const challenge = await gated.createChallenge(account.name, "login", later);
      const result = await gated.login(
        { username: account.name, challengeId: challenge.id, signature: sign(account.key, challenge.message) },
        later,
      );
      const completed = await gated.completeSecondFactor({ ticket: result.ticket!, code: "123456" }, later);
      expect(await authenticates(completed.session.token)).toBe(true);
    });

    it("does not count right codes or a locked verdict against the account", async () => {
      const account = await register("right-codes", {});
      for (let signIn = 1; signIn <= 30; signIn += 1) {
        const ticket = await ticketFor(account);
        await gated.completeSecondFactor({ ticket, code: "123456" }, ctx());
      }
      factors.set(account.accountId, { required: true, code: "123456", locked: true, verifyThrows: false });
      const ticket = await ticketFor(account);
      await expectCode(() => gated.completeSecondFactor({ ticket, code: "123456" }, ctx()), "second-factor-locked");
      expect(await accountGuessesOf(account.accountId)).toEqual([0]);
    });

    it("kills the ticket at the fifth wrong code; 25 wrong codes fill the account's login limit", async () => {
      const account = await register("exhaust", {});
      for (let ticketNumber = 1; ticketNumber <= 5; ticketNumber += 1) {
        const ticket = await ticketFor(account);
        for (let attempt = 1; attempt <= 4; attempt += 1) {
          const error = await expectCode(() => gated.completeSecondFactor({ ticket, code: "999999" }, ctx()), "second-factor-invalid");
          expect(error.details).toEqual({ attemptsRemaining: 5 - attempt });
        }
        await expectCode(() => gated.completeSecondFactor({ ticket, code: "999999" }, ctx()), "second-factor-ticket-invalid");
        const calls = verifyCalls.length;
        // Dead: even the right code is refused, unseen by the verifier.
        await expectCode(() => gated.completeSecondFactor({ ticket, code: "123456" }, ctx()), "second-factor-ticket-invalid");
        expect(verifyCalls.length).toBe(calls);
      }
      const exhausted = (await audit(account.accountId, "session.second-factor-failed")).filter(
        (r) => (r["metadata"] as Record<string, unknown>)["exhausted"] === true,
      );
      expect(exhausted).toHaveLength(5);
      // 25 wrong codes in the hour: the password alone no longer gets a ticket.
      const limited = await expectCode(() => login(account, account.key), "rate-limited");
      expect(limited.details?.["rule"]).toBe("login-account");
      // An hour later it does.
      const later = ctx({ now: new Date(Date.now() + 3_601_000) });
      const challenge = await gated.createChallenge(account.name, "login", later);
      const result = await gated.login(
        { username: account.name, challengeId: challenge.id, signature: sign(account.key, challenge.message) },
        later,
      );
      expect(result.secondFactor).toBe("totp");
    });

    it("refuses an expired ticket", async () => {
      const account = await register("expired", {});
      const ticket = await ticketFor(account);
      const calls = verifyCalls.length;
      await expectCode(
        () => gated.completeSecondFactor({ ticket, code: "123456" }, ctx({ now: new Date(Date.now() + 301_000) })),
        "second-factor-ticket-invalid",
      );
      expect(verifyCalls.length).toBe(calls);
    });

    it("refuses a ticket whose bound key was replaced after it was issued", async () => {
      const account = await register("rebound", {});
      const ticket = await ticketFor(account);
      const next = newKey();
      const challenge = await gated.createChallenge(account.name, "rotation", ctx());
      const message = messageFor(challenge, "sign-in-key-rotation", keyPrincipal(account.key), keyPrincipal(next));
      await gated.rotateSignInKey(
        account.session.token,
        { challengeId: challenge.id, newKey: enrolled(next), authorizerSignature: sign(account.key, message), subjectSignature: sign(next, message) },
        ctx(),
      );
      const sessionsBefore = await sessionCount(account.accountId);
      await expectCode(() => gated.completeSecondFactor({ ticket, code: "123456" }, ctx()), "second-factor-ticket-invalid");
      expect(await sessionCount(account.accountId)).toBe(sessionsBefore);
      // The new key's own ticket works.
      const fresh = await ticketFor(account, next);
      expect(await authenticates((await gated.completeSecondFactor({ ticket: fresh, code: "123456" }, ctx())).session.token)).toBe(true);
    });

    it("refuses a ticket of a suspended account and an unknown or malformed ticket", async () => {
      const account = await register("suspended", {});
      const ticket = await ticketFor(account);
      await first.query(`UPDATE ${prefix}_accounts SET status = 'suspended' WHERE id = $1::uuid`, [account.accountId]);
      await expectCode(() => gated.completeSecondFactor({ ticket, code: "123456" }, ctx()), "second-factor-ticket-invalid");
      const calls = verifyCalls.length;
      await expectCode(() => gated.completeSecondFactor({ ticket: "A".repeat(43), code: "123456" }, ctx()), "second-factor-ticket-invalid");
      await expectCode(() => gated.completeSecondFactor({ ticket: "short", code: "123456" }, ctx()), "second-factor-ticket-invalid");
      await expectCode(() => gated.completeSecondFactor({ ticket, code: "" }, ctx()), "invalid-request");
      await expectCode(() => gated.completeSecondFactor({ ticket, code: "1".repeat(65) }, ctx()), "invalid-request");
      expect(verifyCalls.length).toBe(calls);
    });

    it("refuses with second-factor-locked when the verifier is locked, and propagates a verifier failure", async () => {
      const account = await register("locked", { locked: true });
      const ticket = await ticketFor(account);
      const error = await expectCode(() => gated.completeSecondFactor({ ticket, code: "123456" }, ctx()), "second-factor-locked");
      expect(error.status).toBe(423);
      expect((await audit(account.accountId, "session.second-factor-failed")).at(-1)!["metadata"]).toMatchObject({ reason: "locked" });
      factors.set(account.accountId, { required: true, code: "123456", locked: false, verifyThrows: true });
      await expect(gated.completeSecondFactor({ ticket, code: "123456" }, ctx())).rejects.toThrow("verifier down");
      expect((await ticketRows(account.accountId))[0]!["attempts"]).toBe(2);
      factors.set(account.accountId, { required: true, code: "123456", locked: false, verifyThrows: false });
      expect(await authenticates((await gated.completeSecondFactor({ ticket, code: "123456" }, ctx())).session.token)).toBe(true);
    });
  });

  describe("resets and recovery never bypass the factor", () => {
    async function enableEmailReset(account: Registered): Promise<void> {
      const challenge = await gated.createChallenge(account.name, "rotation", ctx());
      const message = messageFor(challenge, "email-reset-setting", keyPrincipal(account.key), "setting:on");
      await gated.setAccountResetSetting(
        account.session.token,
        { challengeId: challenge.id, setting: "email-reset", enabled: true, authorizerSignature: sign(account.key, message) },
        ctx(),
      );
    }

    async function emailReset(via: IdentityService<boolean>, account: Registered, to: Key) {
      const started = await via.startAccountReset({ username: account.name }, ctx());
      const challenge = await via.createChallenge(account.name, "rotation", ctx());
      const message = messageFor(challenge, "email-reset", `email:${started.delivery!.resetId}`, keyPrincipal(to));
      return {
        challenge,
        result: await via.completeAccountReset(
          {
            username: account.name,
            resetId: started.delivery!.resetId,
            code: started.delivery!.code,
            challengeId: challenge.id,
            newKey: enrolled(to),
            subjectSignature: sign(to, message),
          },
          ctx(),
        ),
      };
    }

    it("account recovery by email replaces the key but answers a ticket bound to the new key", async () => {
      const account = await register("email", {}, `email-${suffix}-${crypto.randomUUID().slice(0, 6)}@example.org`);
      await enableEmailReset(account);
      const to = newKey();
      const { challenge, result } = await emailReset(gated, account, to);
      expect(result.session).toBeUndefined();
      expect(result.secondFactor).toBe("totp");
      expect(result.wallets[0]!.publicKey).toBe(to.identifier);
      expect(result.revokedSessionIds.length).toBeGreaterThan(0);
      expect(await authenticates(account.session.token)).toBe(false);
      expect(requiredCalls.at(-1)).toMatchObject({ accountId: account.accountId, context: { purpose: "email-reset" } });
      // No live session exists before the factor passes.
      const live = await first.query(
        `SELECT count(*)::int AS n FROM ${prefix}_sessions WHERE account_id = $1::uuid AND revoked_at IS NULL`,
        [account.accountId],
      );
      expect(live.rows[0]!["n"]).toBe(0);
      const [row] = (await ticketRows(account.accountId)).filter((r) => r["purpose"] === "email-reset");
      expect(row!["public_key"]).toBe(to.identifier);
      expect(row!["challenge_id"]).toBe(challenge.id);
      const reset = await audit(account.accountId, "account.email-reset");
      expect(reset.at(-1)!["metadata"]).toMatchObject({ secondFactorTicketId: row!["id"] });
      await expectCode(() => gated.completeSecondFactor({ ticket: result.ticket!, code: "000000" }, ctx()), "second-factor-invalid");
      const completed = await gated.completeSecondFactor({ ticket: result.ticket!, code: "123456" }, ctx());
      expect(completed.purpose).toBe("email-reset");
      expect(await authenticates(completed.session.token)).toBe(true);
      expect((await audit(account.accountId, "session.second-factor-ok")).at(-1)!["metadata"]).toMatchObject({ purpose: "email-reset" });
    });

    it("consults required only for a caller who names a live email reset of the username", async () => {
      const account = await register("email-oracle", {}, `oracle-${suffix}-${crypto.randomUUID().slice(0, 6)}@example.org`);
      await enableEmailReset(account);
      // A live reset exists, but the caller names another id (as the anonymous
      // starter's decoy would be): refused without asking the host anything.
      const started = await gated.startAccountReset({ username: account.name }, ctx());
      expect(started.delivery).toBeDefined();
      const to = newKey();
      const calls = requiredCalls.length;
      for (const resetId of [crypto.randomUUID(), crypto.randomUUID()]) {
        const challenge = await gated.createChallenge(account.name, "rotation", ctx());
        const message = messageFor(challenge, "email-reset", `email:${resetId}`, keyPrincipal(to));
        await rejection(() =>
          gated.completeAccountReset(
            {
              username: account.name,
              resetId,
              code: "000000",
              challengeId: challenge.id,
              newKey: enrolled(to),
              subjectSignature: sign(to, message),
            },
            ctx(),
          ),
        );
      }
      expect(requiredCalls.length).toBe(calls);
    });

    it("account recovery by email still issues the session at once for an account that needs no factor", async () => {
      const account = await register("email-free", { required: false }, `free-${suffix}-${crypto.randomUUID().slice(0, 6)}@example.org`);
      await enableEmailReset(account);
      const { result } = await emailReset(gated, account, newKey());
      expect(result.secondFactor).toBeUndefined();
      expect(await authenticates(result.session!.token)).toBe(true);
    });

    it("a recovery-key completion answers a ticket bound to the new key", async () => {
      const account = await register("recovery", {});
      const recovery = newKey();
      const enrollChallenge = await gated.createChallenge(account.name, "rotation", ctx());
      const enrollMessage = messageFor(enrollChallenge, "recovery-key-enrollment", keyPrincipal(account.key), `recovery-key:${recovery.publicKeyHex}`);
      await gated.enrollRecoveryKey(
        account.session.token,
        { challengeId: enrollChallenge.id, recoveryPublicKey: recovery.publicKeyHex, authorizerSignature: sign(account.key, enrollMessage), subjectSignature: sign(recovery, enrollMessage) },
        ctx(),
      );
      const beginChallenge = await gated.createChallenge(account.name, "rotation", ctx());
      const begun = await gated.beginRecovery(
        {
          username: account.name,
          challengeId: beginChallenge.id,
          recoveryPublicKey: recovery.publicKeyHex,
          signature: sign(recovery, messageFor(beginChallenge, "recovery-begin", `recovery-key:${recovery.publicKeyHex}`, "none")),
        },
        ctx(),
      );
      const to = newKey();
      const challenge = await gated.createChallenge(account.name, "rotation", ctx());
      const message = messageFor(challenge, "recovery-reset", `recovery-key:${recovery.publicKeyHex}`, keyPrincipal(to));
      const result = await gated.completeRecovery(
        begun.recoveryToken,
        { challengeId: challenge.id, newKey: enrolled(to), authorizerSignature: sign(recovery, message), subjectSignature: sign(to, message) },
        ctx(),
      );
      expect(result.session).toBeUndefined();
      expect(result.secondFactor).toBe("totp");
      expect(await authenticates(account.session.token)).toBe(false);
      expect(requiredCalls.at(-1)).toMatchObject({ accountId: account.accountId, context: { purpose: "recovery" } });
      const [row] = (await ticketRows(account.accountId)).filter((r) => r["purpose"] === "recovery");
      expect(row!["public_key"]).toBe(to.identifier);
      expect((await audit(account.accountId, "account.recover")).at(-1)!["metadata"]).toMatchObject({ secondFactorTicketId: row!["id"] });
      const completed = await gated.completeSecondFactor({ ticket: result.ticket!, code: "123456" }, ctx());
      expect(completed.purpose).toBe("recovery");
      expect(await authenticates(completed.session.token)).toBe(true);
    });

    it("a signed-in reset completion issues no session, and the next login with the new key needs the factor", async () => {
      const account = await register("signed-in", {});
      const started = await gated.startSignedInReset(account.session.token, ctx());
      await first.query(
        `UPDATE ${prefix}_account_resets SET created_at = created_at - interval '73 hours', available_at = available_at - interval '73 hours' WHERE id = $1::uuid`,
        [started.reset.id],
      );
      const to = newKey();
      const challenge = await gated.createChallenge(account.name, "rotation", ctx());
      const message = messageFor(challenge, "signed-in-reset", `session-reset:${started.reset.id}`, keyPrincipal(to));
      const sessionsBefore = await sessionCount(account.accountId);
      const completed = await gated.completeSignedInReset(
        account.session.token,
        { challengeId: challenge.id, resetId: started.reset.id, newKey: enrolled(to), subjectSignature: sign(to, message) },
        ctx(),
      );
      expect(Object.keys(completed).sort()).toEqual(["revokedSessionIds", "wallets"]);
      expect(await sessionCount(account.accountId)).toBe(sessionsBefore);
      const result = await login(account, to);
      expect(result.session).toBeUndefined();
      expect(result.secondFactor).toBe("totp");
    });
  });

  describe("the router", () => {
    it("answers a pending login with the ticket and no cookie, and sets the cookie after the factor", async () => {
      const account = await register("router", {});
      const router = createIdentityRouter(gated, { trustedOrigins: ["https://app.example"] });
      const challenge = await gated.createChallenge(account.name, "login", ctx());
      const post = (path: string, body: unknown) =>
        router(
          new Request(`https://id.example/identity${path}`, {
            method: "POST",
            headers: { "content-type": "application/json", origin: "https://app.example" },
            body: JSON.stringify(body),
          }),
        );
      const pending = await post("/sessions", {
        username: account.name,
        challengeId: challenge.id,
        signature: sign(account.key, challenge.message),
      });
      expect(pending.status).toBe(200);
      expect(pending.headers.get("set-cookie")).toBeNull();
      const body = (await pending.json()) as Record<string, unknown>;
      expect(Object.keys(body).sort()).toEqual(["expiresAt", "secondFactor", "ticket"]);
      expect(body["secondFactor"]).toBe("totp");

      const wrong = await post("/sessions/second-factor", { ticket: body["ticket"], code: "000000" });
      expect(wrong.status).toBe(401);
      expect(((await wrong.json()) as { error: { code: string } }).error.code).toBe("second-factor-invalid");
      const unknownField = await post("/sessions/second-factor", { ticket: body["ticket"], code: "1", extra: 1 });
      expect(unknownField.status).toBe(400);

      const done = await post("/sessions/second-factor", { ticket: body["ticket"], code: "123456" });
      expect(done.status).toBe(200);
      expect(done.headers.get("set-cookie")).toMatch(/^__Host-w2sc_session=/u);
      const doneBody = (await done.json()) as Record<string, unknown>;
      expect(Object.keys(doneBody).sort()).toEqual(["account", "session"]);
    });

    it("keeps a login that needs no factor byte for byte the plain router's", async () => {
      const account = await register("router-free", { required: false });
      const router = createIdentityRouter(gated, { useCookies: false });
      const challenge = await gated.createChallenge(account.name, "login", ctx());
      const response = await router(
        new Request("https://id.example/identity/sessions", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ username: account.name, challengeId: challenge.id, signature: sign(account.key, challenge.message) }),
        }),
      );
      expect(response.status).toBe(200);
      expect(Object.keys((await response.json()) as object).sort()).toEqual(["account", "session", "token"]);
    });
  });

  describe("pruneExpired", () => {
    it("deletes a ticket a day after it expires", async () => {
      const account = await register("prune", {});
      await ticketFor(account);
      await first.query(
        `UPDATE ${prefix}_second_factor_tickets SET created_at = created_at - interval '2 days', expires_at = expires_at - interval '2 days' WHERE account_id = $1::uuid`,
        [account.accountId],
      );
      const pruned = await gated.pruneExpired();
      expect(pruned.secondFactorTickets).toBeGreaterThanOrEqual(1);
      expect(await ticketRows(account.accountId)).toEqual([]);
    });
  });
});
