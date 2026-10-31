import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAccountChangeMessage,
  signInEd25519ExternalSalt,
  type AccountChangeAction,
} from "../../src/index.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import {
  createIdentityService,
  pgDriver,
  type IdentityChallenge,
  type IdentityService,
  type IdentityServiceConfig,
  type IssuedSession,
  type RequestContext,
  type SecondFactorIdentityServiceConfig,
  type SqlRow,
} from "../../src/server/index.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * `deleteAccount` over real PostgreSQL (migration 13): one statement that
 * deletes everything the service stores for an account, keeps (or prunes)
 * its audit rows, records `account.deleted`, refuses an account with live
 * sessions unless asked to revoke them, and resolves for a missing account.
 * Gated on W2SC_TEST_DATABASE_URL like the other server suites.
 */
const url = process.env["W2SC_TEST_DATABASE_URL"];

type Client = {
  connect(): Promise<void>;
  end(): Promise<void>;
  query(text: string, parameters?: readonly unknown[]): Promise<{ rows: SqlRow[] }>;
};

const encoder = new TextEncoder();
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
const prefix = `wad_${suffix}`;
const serviceProfileId = `w2sc-deletion-${suffix}`;
const tables = [
  "second_factor_tickets", "account_resets", "account_recoveries", "account_recovery_keys", "wallet_setups",
  "wallet_policy", "audit_events", "rate_limits", "email_verifications", "sessions", "auth_challenges",
  "account_wallets", "accounts", "service_profile_bootstrap", "service_profiles", "schema_migrations",
];

const config = (overrides: Partial<IdentityServiceConfig> = {}): IdentityServiceConfig => ({
  serviceProfileId,
  profile: signInEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-testnet",
  tablePrefix: prefix,
  sessionTtlSeconds: 30 * 86_400,
  accountSecurity: { signInKeyRotation: true, recoveryKeys: true, emailReset: true, signedInReset: true },
  ...overrides,
});

type Key = Readonly<{ secret: Uint8Array; publicKeyHex: string; identifier: string }>;

function newKey(): Key {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const publicKeyHex = bytesToHex(ed25519.getPublicKey(secret));
  return Object.freeze({ secret, publicKeyHex, identifier: `S_${publicKeyHex}` });
}

function sign(key: Key, message: string): string {
  return bytesToHex(ed25519.sign(encoder.encode(message), key.secret));
}

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

let PgClient: new (options: { connectionString: string }) => Client;
let first: Client;
let service: IdentityService;

type Registered = Readonly<{ name: string; key: Key; accountId: string; session: IssuedSession; email: string }>;

/** An account with a row in every table the deletion covers. */
async function fullAccount(label: string): Promise<Registered> {
  const name = username(label);
  const email = `${label}-${suffix}-${crypto.randomUUID().slice(0, 6)}@example.org`;
  const key = newKey();
  const started = await service.startEmailVerification({ username: name, email }, ctx());
  await service.confirmEmailVerification(started.verificationId, started.code, ctx());
  const challenge = await service.createChallenge(name, "registration", ctx());
  const registered = await service.register(
    { username: name, address: key.identifier, publicKey: key.identifier, challengeId: challenge.id, signature: sign(key, challenge.message), email },
    ctx(),
  );
  const account = { name, key, accountId: registered.account.id, session: registered.session, email };
  // A recovery key and a live recovery token.
  const recovery = newKey();
  const enrollChallenge = await service.createChallenge(name, "rotation", ctx());
  const enrollMessage = messageFor(enrollChallenge, "recovery-key-enrollment", `key:${key.identifier}`, `recovery-key:${recovery.publicKeyHex}`);
  await service.enrollRecoveryKey(
    registered.session.token,
    { challengeId: enrollChallenge.id, recoveryPublicKey: recovery.publicKeyHex, authorizerSignature: sign(key, enrollMessage), subjectSignature: sign(recovery, enrollMessage) },
    ctx(),
  );
  const beginChallenge = await service.createChallenge(name, "rotation", ctx());
  await service.beginRecovery(
    {
      username: name,
      challengeId: beginChallenge.id,
      recoveryPublicKey: recovery.publicKeyHex,
      signature: sign(recovery, messageFor(beginChallenge, "recovery-begin", `recovery-key:${recovery.publicKeyHex}`, "none")),
    },
    ctx(),
  );
  // A pending signed-in reset, an unconsumed challenge and a second session.
  await service.startSignedInReset(registered.session.token, ctx());
  await service.createChallenge(name, "login", ctx());
  const loginChallenge = await service.createChallenge(name, "login", ctx());
  await service.login({ username: name, challengeId: loginChallenge.id, signature: sign(key, loginChallenge.message) }, ctx());
  return account;
}

async function count(table: string, where: string, parameter: string): Promise<number> {
  return Number(
    (await first.query(`SELECT count(*)::int AS n FROM ${prefix}_${table} WHERE ${where}`, [parameter])).rows[0]?.["n"],
  );
}

async function footprint(account: Registered): Promise<Record<string, number>> {
  const byAccount = "account_id = $1::uuid";
  const byName = `service_profile_id = '${serviceProfileId}' AND username_normalized = $1::text`;
  return {
    accounts: await count("accounts", "id = $1::uuid", account.accountId),
    wallets: await count("account_wallets", byAccount, account.accountId),
    sessions: await count("sessions", byAccount, account.accountId),
    recoveryKeys: await count("account_recovery_keys", byAccount, account.accountId),
    recoveries: await count("account_recoveries", byAccount, account.accountId),
    resets: await count("account_resets", byAccount, account.accountId),
    tickets: await count("second_factor_tickets", byAccount, account.accountId),
    challenges: await count("auth_challenges", byName, account.name),
    verifications: await count("email_verifications", byName, account.name),
    auditAttached: await count("audit_events", byAccount, account.accountId),
  };
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

async function waitUntilBlocked(pid: number): Promise<void> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const row = (await first.query(`SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1::integer`, [pid])).rows[0];
    if (row?.["wait_event_type"] === "Lock") return;
    if (Date.now() > deadline) throw new Error(`Backend ${String(pid)} never waited for a lock.`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

describe.skipIf(!url)("account deletion on PostgreSQL", () => {
  beforeAll(async () => {
    const moduleName: string = "pg";
    const pg = (await import(moduleName)) as { Client: new (options: { connectionString: string }) => Client };
    PgClient = pg.Client;
    first = new PgClient({ connectionString: url! });
    await first.connect();
    service = createIdentityService(pgDriver(first), config());
    expect(await service.migrate()).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
  }, 60_000);

  afterAll(async () => {
    if (!first) return;
    await first.query(`DROP TABLE IF EXISTS ${tables.map((t) => `${prefix}_${t}`).join(", ")} CASCADE`);
    await first.query(`DROP FUNCTION IF EXISTS ${prefix}_reject_immutable_mutation() CASCADE`);
    await first.end();
  }, 60_000);

  it("resolves for a missing account and refuses a malformed id", async () => {
    expect(await service.deleteAccount(crypto.randomUUID())).toEqual({ deleted: false, revokedSessions: 0 });
    await expectCode(() => service.deleteAccount("not-a-uuid"), "invalid-request");
    await expectCode(() => service.deleteAccount(crypto.randomUUID(), { revokeLiveSessions: "yes" as unknown as boolean }), "invalid-request");
  });

  it("refuses an account with live sessions and deletes nothing", async () => {
    const account = await fullAccount("live");
    const before = await footprint(account);
    const error = await expectCode(() => service.deleteAccount(account.accountId), "account-has-sessions");
    expect(error.status).toBe(409);
    expect(error.details).toEqual({ liveSessions: 2 });
    expect(await footprint(account)).toEqual(before);
    expect(await service.authenticate(account.session.token)).toBeDefined();
  });

  it("deletes everything in one statement with revokeLiveSessions and keeps the audit rows detached", async () => {
    const account = await fullAccount("full");
    // A second-factor ticket too.
    await first.query(
      `INSERT INTO ${prefix}_second_factor_tickets (account_id, ticket_hash, challenge_id, public_key, purpose, created_at, expires_at)
       VALUES ($1::uuid, repeat('a', 64), gen_random_uuid(), $2, 'login', now(), now() + interval '5 minutes')`,
      [account.accountId, account.key.identifier],
    );
    const before = await footprint(account);
    for (const [table, rows] of Object.entries(before)) {
      expect(rows, table).toBeGreaterThan(0);
    }
    const auditBefore = before["auditAttached"]!;
    const result = await service.deleteAccount(account.accountId, { revokeLiveSessions: true }, ctx());
    expect(result).toEqual({ deleted: true, revokedSessions: 2 });
    expect(await footprint(account)).toEqual({
      accounts: 0, wallets: 0, sessions: 0, recoveryKeys: 0, recoveries: 0, resets: 0, tickets: 0,
      challenges: 0, verifications: 0, auditAttached: 0,
    });
    await expectCode(() => service.authenticate(account.session.token), "session-not-found");

    const kept = (
      await first.query(
        `SELECT action, account_id, deleted_service_profile_id, metadata FROM ${prefix}_audit_events
          WHERE deleted_account_id = $1::uuid ORDER BY created_at, id`,
        [account.accountId],
      )
    ).rows;
    expect(kept).toHaveLength(auditBefore + 1);
    for (const row of kept) {
      expect(row["account_id"]).toBeNull();
      expect(row["deleted_service_profile_id"]).toBe(serviceProfileId);
    }
    const deleted = kept.filter((row) => row["action"] === "account.deleted");
    expect(deleted).toHaveLength(1);
    expect(deleted[0]!["metadata"]).toEqual({ revokedSessions: 2, keptAuditEvents: auditBefore, prunedAuditEvents: 0 });
    const text = JSON.stringify(deleted[0]);
    expect(text).not.toContain(account.email);
    expect(text).not.toContain(account.name);
    expect(text).not.toContain(account.key.publicKeyHex);

    // Idempotent: a second call finds nothing and records nothing.
    expect(await service.deleteAccount(account.accountId, { revokeLiveSessions: true })).toEqual({ deleted: false, revokedSessions: 0 });
    expect(
      await count("audit_events", "deleted_account_id = $1::uuid AND action = 'account.deleted'", account.accountId),
    ).toBe(1);
  });

  it("deletes an account whose sessions are all revoked without the option", async () => {
    const account = await fullAccount("signed-out");
    await service.revokeAllSessions(account.accountId);
    expect(await service.deleteAccount(account.accountId)).toEqual({ deleted: true, revokedSessions: 0 });
    expect((await footprint(account))["accounts"]).toBe(0);
  });

  it("frees the username: it registers again as a new account with nothing of the old one", async () => {
    const account = await fullAccount("reuse");
    await service.deleteAccount(account.accountId, { revokeLiveSessions: true });
    const key = newKey();
    const challenge = await service.createChallenge(account.name, "registration", ctx());
    const again = await service.register(
      { username: account.name, address: key.identifier, publicKey: key.identifier, challengeId: challenge.id, signature: sign(key, challenge.message) },
      ctx(),
    );
    expect(again.account.id).not.toBe(account.accountId);
    expect(again.account.email).toBeNull();
    const events = await service.listSecurityEvents(again.session.token);
    expect(events.map((event) => event.action)).toEqual(["account.register"]);
  });

  it("deletes the account's login-account rate-limit row and its pending second-factor tickets", async () => {
    const factorService = createIdentityService(pgDriver(first), {
      ...config(),
      secondFactor: { required: async () => true, verify: async () => "invalid" },
    } satisfies SecondFactorIdentityServiceConfig);
    const name = username("ticket");
    const key = newKey();
    const challenge = await factorService.createChallenge(name, "registration", ctx());
    const registered = await factorService.register(
      { username: name, address: key.identifier, publicKey: key.identifier, challengeId: challenge.id, signature: sign(key, challenge.message) },
      ctx(),
    );
    const loginChallenge = await factorService.createChallenge(name, "login", ctx());
    const pending = await factorService.login({ username: name, challengeId: loginChallenge.id, signature: sign(key, loginChallenge.message) }, ctx());
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await rejection(() => factorService.completeSecondFactor({ ticket: pending.ticket!, code: "1" }, ctx()));
    }
    const limitRows = async () =>
      Number((await first.query(`SELECT count(*)::int AS n FROM ${prefix}_rate_limits WHERE rule_id = 'login-account'`)).rows[0]?.["n"]);
    const limitsBefore = await limitRows();
    expect(limitsBefore).toBeGreaterThan(0);
    const second = await factorService.createChallenge(name, "login", ctx());
    const live = await factorService.login({ username: name, challengeId: second.id, signature: sign(key, second.message) }, ctx());
    expect(await factorService.deleteAccount(registered.account.id, { revokeLiveSessions: true })).toEqual({ deleted: true, revokedSessions: 1 });
    expect(await limitRows()).toBe(limitsBefore - 1);
    expect(await count("second_factor_tickets", "account_id = $1::uuid", registered.account.id)).toBe(0);
    await expectCode(() => factorService.completeSecondFactor({ ticket: live.ticket!, code: "1" }, ctx()), "second-factor-ticket-invalid");
  });

  it("applies auditRetentionDays at once, and pruneExpired keeps applying it to the kept rows", async () => {
    const retained = createIdentityService(pgDriver(first), config({ auditRetentionDays: 30 }));
    const account = await fullAccount("retention");
    // An email.* row of the account (a verification started once it exists).
    await service.startEmailVerification({ username: account.name, email: account.email }, ctx());
    await first.query(
      `UPDATE ${prefix}_audit_events SET created_at = now() - interval '40 days'
        WHERE account_id = $1::uuid AND action IN ('account.register', 'email.verification-start')`,
      [account.accountId],
    );
    const attached = await count("audit_events", "account_id = $1::uuid", account.accountId);
    const result = await retained.deleteAccount(account.accountId, { revokeLiveSessions: true });
    expect(result.deleted).toBe(true);
    const rows = (
      await first.query(`SELECT action, metadata FROM ${prefix}_audit_events WHERE deleted_account_id = $1::uuid`, [account.accountId])
    ).rows;
    const actions = rows.map((row) => row["action"]);
    // account.register was older than 30 days: pruned. email.* is outside the rule: kept.
    expect(actions).not.toContain("account.register");
    expect(actions).toContain("email.verification-start");
    const deleted = rows.find((row) => row["action"] === "account.deleted")!;
    expect(deleted["metadata"]).toMatchObject({ prunedAuditEvents: 1, keptAuditEvents: attached - 1 });

    // 31 days on, pruneExpired removes the kept account.* and session.* rows too.
    const later = new Date(Date.now() + 31 * 86_400_000);
    await retained.pruneExpired({ now: later });
    const left = (
      await first.query(`SELECT action FROM ${prefix}_audit_events WHERE deleted_account_id = $1::uuid`, [account.accountId])
    ).rows.map((row) => row["action"]);
    expect(left.every((action) => typeof action === "string" && action.startsWith("email."))).toBe(true);
    expect(left.length).toBeGreaterThan(0);
  });

  it("waits for a session lock held by a revocation in flight, then deletes, without deadlock", async () => {
    const account = await fullAccount("locked");
    const other = new PgClient({ connectionString: url! });
    const deleter = new PgClient({ connectionString: url! });
    await Promise.all([other.connect(), deleter.connect()]);
    try {
      const pid = Number((await deleter.query("SELECT pg_backend_pid() AS pid")).rows[0]?.["pid"]);
      await other.query("BEGIN");
      // As revoke-others locks a session, then (its audit insert) the account FOR KEY SHARE.
      await other.query(
        `SELECT id FROM ${prefix}_sessions WHERE account_id = $1::uuid ORDER BY id LIMIT 1 FOR NO KEY UPDATE`,
        [account.accountId],
      );
      const deleting = createIdentityService(pgDriver(deleter), config()).deleteAccount(account.accountId, { revokeLiveSessions: true });
      await waitUntilBlocked(pid);
      await other.query(
        `INSERT INTO ${prefix}_audit_events (account_id, action, metadata) VALUES ($1::uuid, 'session.revoke', '{}'::jsonb)`,
        [account.accountId],
      );
      await other.query("COMMIT");
      expect(await deleting).toEqual({ deleted: true, revokedSessions: 2 });
      // The row the other transaction wrote while the deletion waited is kept
      // too: the deletion's audit statement runs in a snapshot taken after the
      // locks, so it detaches that row like the others, with the service's id.
      const late = (
        await first.query(
          `SELECT deleted_service_profile_id FROM ${prefix}_audit_events WHERE deleted_account_id = $1::uuid AND action = 'session.revoke'`,
          [account.accountId],
        )
      ).rows;
      expect(late).toEqual([{ deleted_service_profile_id: serviceProfileId }]);
      await createIdentityService(pgDriver(first), config({ auditRetentionDays: 1 })).pruneExpired({
        now: new Date(Date.now() + 2 * 86_400_000),
      });
      expect(await count("audit_events", "deleted_account_id = $1::uuid AND action LIKE 'session.%'", account.accountId)).toBe(0);
    } finally {
      await Promise.all([other.end(), deleter.end()]);
    }
  });

  it("serializes with a login on the account lock: a login queued behind the deletion issues nothing", async () => {
    const account = await fullAccount("race-login");
    const holder = new PgClient({ connectionString: url! });
    const deleter = new PgClient({ connectionString: url! });
    const loginClient = new PgClient({ connectionString: url! });
    await Promise.all([holder.connect(), deleter.connect(), loginClient.connect()]);
    try {
      const pidOf = async (client: Client) => Number((await client.query("SELECT pg_backend_pid() AS pid")).rows[0]?.["pid"]);
      const [deleterPid, loginPid] = [await pidOf(deleter), await pidOf(loginClient)];
      const challenge = await service.createChallenge(account.name, "login", ctx());
      await holder.query("BEGIN");
      await holder.query(`SELECT id FROM ${prefix}_accounts WHERE id = $1::uuid FOR NO KEY UPDATE`, [account.accountId]);
      const deleting = createIdentityService(pgDriver(deleter), config()).deleteAccount(account.accountId, { revokeLiveSessions: true });
      await waitUntilBlocked(deleterPid);
      const loggingIn = rejection(() =>
        createIdentityService(pgDriver(loginClient), config()).login(
          { username: account.name, challengeId: challenge.id, signature: sign(account.key, challenge.message) },
          ctx(),
        ),
      );
      await waitUntilBlocked(loginPid);
      await holder.query("ROLLBACK");
      expect(await deleting).toEqual({ deleted: true, revokedSessions: 2 });
      expect((await loggingIn).code).toBe("invalid-signature");
      expect(await count("sessions", "account_id = $1::uuid", account.accountId)).toBe(0);
    } finally {
      await Promise.all([holder.end(), deleter.end(), loginClient.end()]);
    }
  });

  describe("a session committed while the deletion waits for the account lock", () => {
    /**
     * As a login or completeSecondFactor does: lock the account FOR NO KEY
     * UPDATE and insert a live session in one transaction, start the deletion
     * behind it, then commit; answers the deletion's outcome and the session.
     */
    async function deleteBehindLateSession(accountId: string, revokeLiveSessions: boolean) {
      const holder = new PgClient({ connectionString: url! });
      const deleter = new PgClient({ connectionString: url! });
      await Promise.all([holder.connect(), deleter.connect()]);
      try {
        const pid = Number((await deleter.query("SELECT pg_backend_pid() AS pid")).rows[0]?.["pid"]);
        await holder.query("BEGIN");
        await holder.query(`SELECT id FROM ${prefix}_accounts WHERE id = $1::uuid FOR NO KEY UPDATE`, [accountId]);
        const inserted = await holder.query(
          `INSERT INTO ${prefix}_sessions (account_id, token_hash, expires_at)
           VALUES ($1::uuid, $2::text, now() + interval '1 day') RETURNING id`,
          [accountId, bytesToHex(crypto.getRandomValues(new Uint8Array(32)))],
        );
        const deleting = createIdentityService(pgDriver(deleter), config())
          .deleteAccount(accountId, { revokeLiveSessions })
          .then(
            (value) => ({ value, error: null }),
            (error: unknown) => ({ value: null, error }),
          );
        await waitUntilBlocked(pid);
        await holder.query("COMMIT");
        return { sessionId: String(inserted.rows[0]!["id"]), ...(await deleting) };
      } finally {
        await Promise.all([holder.end(), deleter.end()]);
      }
    }

    it("refuses with account-has-sessions and leaves the account and the session in place", async () => {
      const account = await fullAccount("late-refuse");
      await service.revokeAllSessions(account.accountId);
      expect(await count("sessions", "account_id = $1::uuid AND revoked_at IS NULL", account.accountId)).toBe(0);
      const { sessionId, value, error } = await deleteBehindLateSession(account.accountId, false);
      expect(value).toBeNull();
      expect(error).toBeInstanceOf(IdentityError);
      expect((error as IdentityError).code).toBe("account-has-sessions");
      expect((error as IdentityError).details).toEqual({ liveSessions: 1 });
      expect(await count("accounts", "id = $1::uuid", account.accountId)).toBe(1);
      expect(await count("sessions", "id = $1::uuid", sessionId)).toBe(1);
    });

    it("counts the late session in revokedSessions when asked to revoke", async () => {
      const account = await fullAccount("late-revoke");
      const liveBefore = await count("sessions", "account_id = $1::uuid AND revoked_at IS NULL", account.accountId);
      const { value, error } = await deleteBehindLateSession(account.accountId, true);
      expect(error).toBeNull();
      expect(value).toEqual({ deleted: true, revokedSessions: liveBefore + 1 });
      expect(await count("sessions", "account_id = $1::uuid", account.accountId)).toBe(0);
      const logged = (
        await first.query(
          `SELECT metadata FROM ${prefix}_audit_events WHERE deleted_account_id = $1::uuid AND action = 'account.deleted'`,
          [account.accountId],
        )
      ).rows;
      expect(logged[0]!["metadata"]).toMatchObject({ revokedSessions: liveBefore + 1 });
    });
  });
});
