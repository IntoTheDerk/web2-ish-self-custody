import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAccountChangeMessage,
  signInEd25519ExternalSalt,
  type AccountChangeAction,
} from "../../src/index.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import { applyMigrationStatement, identityMigrations } from "../../src/server/migrations.js";
import {
  createIdentityRouter,
  createIdentityService,
  pgDriver,
  type AccountResetSettingName,
  type IdentityChallenge,
  type IdentityService,
  type IdentityServiceConfig,
  type IssuedAccountReset,
  type IssuedSession,
  type RequestContext,
  type SecurityEventNotice,
  type SqlDriver,
  type SqlParameter,
  type SqlRow,
} from "../../src/server/index.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * Account resets (migration 8, the two settings, account recovery by email
 * with its uniform start, the signed-in reset with its wait, abort, login
 * abort and emailed code, reauthentication, the lock order) over real
 * PostgreSQL. Gated on W2SC_TEST_DATABASE_URL like the other server suites.
 *
 * Keys are plain Ed25519 keys under the sign-in profile's codec, so no test
 * pays for scrypt. Every change is signed over buildAccountChangeMessage from
 * the core entry, as a browser would sign it.
 */
const url = process.env["W2SC_TEST_DATABASE_URL"];

type Client = {
  connect(): Promise<void>;
  end(): Promise<void>;
  query(text: string, parameters?: readonly unknown[]): Promise<{ rows: SqlRow[] }>;
};

const encoder = new TextEncoder();
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
const prefix = `wrs_${suffix}`;
const concurrencyPrefix = `wrc_${suffix}`;
const serviceProfileId = `w2sc-resets-${suffix}`;
const tables = [
  "account_resets", "account_recoveries", "account_recovery_keys", "wallet_setups", "wallet_policy",
  "audit_events", "rate_limits", "email_verifications", "sessions", "auth_challenges", "account_wallets",
  "accounts", "service_profile_bootstrap", "service_profiles", "schema_migrations",
];

const events: SecurityEventNotice[] = [];
const HOUR = 3_600_000;
const WAIT_MS = 72 * HOUR;

const config = (tablePrefix: string, overrides: Partial<IdentityServiceConfig> = {}): IdentityServiceConfig => ({
  serviceProfileId,
  profile: signInEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-testnet",
  tablePrefix,
  // Long enough that a session outlives the 72-hour wait on a moved clock.
  sessionTtlSeconds: 30 * 86_400,
  accountSecurity: { signInKeyRotation: true, recoveryKeys: true, emailReset: true, signedInReset: true },
  onSecurityEvent: (event) => {
    events.push(event);
  },
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

const keyPrincipal = (key: Key): string => `key:${key.identifier}`;
const enrolled = (key: Key) => ({ address: key.identifier, publicKey: key.identifier });

/** A fresh hashed IP per call, so rate-limit buckets never carry across tests. */
let ipCounter = 0;
function ctx(extra: Omit<RequestContext, "ipHash"> = {}): RequestContext {
  ipCounter += 1;
  return { ipHash: `ip-${suffix}-${String(ipCounter)}`, ...extra };
}

function username(label: string): string {
  return `${label}-${crypto.randomUUID().slice(0, 8)}@example.com`;
}

function messageFor(
  challenge: IdentityChallenge,
  action: AccountChangeAction,
  authorizer: string,
  subject: string,
): string {
  const nonceHex = challenge.message.split("\n")[6]!;
  return buildAccountChangeMessage({
    serviceProfileId,
    applicationId: "example-app",
    networkId: "kalvora-testnet",
    action,
    usernameNormalized: challenge.usernameNormalized,
    nonceHex,
    expiresAt: challenge.expiresAt,
    authorizer,
    subject,
  });
}

let PgClient: new (options: { connectionString: string }) => Client;
let first: Client;
let second: Client;
let service: IdentityService;
let otherService: IdentityService;
let secondPid: number;

type Connection = Readonly<{ client: Client; service: IdentityService; pid: number }>;

async function openConnections(count: number): Promise<readonly Connection[]> {
  const connections: Connection[] = [];
  try {
    for (let index = 0; index < count; index += 1) {
      const client = new PgClient({ connectionString: url! });
      await client.connect();
      const pid = Number((await client.query("SELECT pg_backend_pid() AS pid")).rows[0]?.["pid"]);
      connections.push({ client, service: createIdentityService(pgDriver(client), config(prefix)), pid });
    }
  } catch (error) {
    await closeConnections(connections);
    throw error;
  }
  return connections;
}

async function closeConnections(connections: readonly Connection[]): Promise<void> {
  await Promise.all(connections.map((connection) => connection.client.end()));
}

async function waitUntilBlocked(pid: number): Promise<void> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const row = (
      await first.query(`SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1::integer`, [pid])
    ).rows[0];
    if (row?.["wait_event_type"] === "Lock") return;
    if (Date.now() > deadline) throw new Error(`Backend ${String(pid)} never waited for a lock.`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

type Registered = Readonly<{ name: string; key: Key; accountId: string; session: IssuedSession; email: string | null }>;

async function register(
  name: string,
  options: Readonly<{ email?: string; verify?: boolean; via?: IdentityService; context?: RequestContext }> = {},
): Promise<Registered> {
  const via = options.via ?? service;
  const key = newKey();
  if (options.email !== undefined && options.verify === true) {
    const started = await via.startEmailVerification({ username: name, email: options.email }, ctx());
    await via.confirmEmailVerification(started.verificationId, started.code, ctx());
  }
  const challenge = await via.createChallenge(name, "registration", ctx());
  const registered = await via.register(
    {
      username: name,
      address: key.identifier,
      publicKey: key.identifier,
      challengeId: challenge.id,
      signature: sign(key, challenge.message),
      ...(options.email !== undefined ? { email: options.email } : {}),
    },
    options.context ?? ctx(),
  );
  if (options.verify === true) {
    expect(registered.account.emailVerifiedAt).not.toBeNull();
  }
  return { name, key, accountId: registered.account.id, session: registered.session, email: options.email ?? null };
}

async function verifiedAccount(label: string): Promise<Registered> {
  return register(username(label), { email: `${label}-${crypto.randomUUID().slice(0, 6)}@example.org`, verify: true });
}

async function login(name: string, key: Key, via: IdentityService = service, context: RequestContext = ctx()): Promise<IssuedSession> {
  const challenge = await via.createChallenge(name, "login", ctx());
  return (
    await via.login({ username: name, challengeId: challenge.id, signature: sign(key, challenge.message) }, context)
  ).session;
}

async function setSetting(
  account: Readonly<{ name: string; key: Key }>,
  token: string,
  setting: AccountResetSettingName,
  enabled: boolean,
  options: Readonly<{ via?: IdentityService; signed?: boolean; signer?: Key }> = {},
) {
  const via = options.via ?? service;
  const challenge = await via.createChallenge(account.name, "rotation", ctx());
  const action = setting === "email-reset" ? "email-reset-setting" : "signed-in-reset-setting";
  const signedValue = options.signed ?? enabled;
  const message = messageFor(challenge, action, keyPrincipal(account.key), signedValue ? "setting:on" : "setting:off");
  return via.setAccountResetSetting(
    token,
    { challengeId: challenge.id, setting, enabled, authorizerSignature: sign(options.signer ?? account.key, message) },
    ctx(),
  );
}

async function enableEmailReset(account: Registered): Promise<void> {
  const result = await setSetting(account, account.session.token, "email-reset", true);
  expect(result.settings.emailReset).toBe(true);
}

async function startEmail(name: string, via: IdentityService = service, context: RequestContext = ctx()): Promise<IssuedAccountReset> {
  return via.startAccountReset({ username: name }, context);
}

async function completeEmail(
  name: string,
  resetId: string,
  code: string,
  to: Key,
  options: Readonly<{ via?: IdentityService; context?: RequestContext; signer?: Key }> = {},
) {
  const via = options.via ?? service;
  const challenge = await via.createChallenge(name, "rotation", ctx());
  const message = messageFor(challenge, "email-reset", `email:${resetId}`, keyPrincipal(to));
  return via.completeAccountReset(
    {
      username: name,
      resetId,
      code,
      challengeId: challenge.id,
      newKey: enrolled(to),
      subjectSignature: sign(options.signer ?? to, message),
    },
    options.context ?? ctx(),
  );
}

async function completeSignedIn(
  name: string,
  token: string,
  resetId: string,
  to: Key,
  options: Readonly<{ via?: IdentityService; context?: RequestContext; code?: string }> = {},
) {
  const via = options.via ?? service;
  const now = options.context?.now;
  const challenge = await via.createChallenge(name, "rotation", ctx(now === undefined ? {} : { now }));
  const message = messageFor(challenge, "signed-in-reset", `session-reset:${resetId}`, keyPrincipal(to));
  return via.completeSignedInReset(
    token,
    {
      challengeId: challenge.id,
      resetId,
      newKey: enrolled(to),
      subjectSignature: sign(to, message),
      ...(options.code !== undefined ? { code: options.code } : {}),
    },
    options.context ?? ctx(),
  );
}

async function reauth(account: Readonly<{ name: string; key: Key }>, token: string, label: string, signedLabel = label) {
  const challenge = await service.createChallenge(account.name, "rotation", ctx());
  const message = messageFor(challenge, "reauthentication", keyPrincipal(account.key), `host:${signedLabel}`);
  return service.verifyReauthentication(
    token,
    { challengeId: challenge.id, label, authorizerSignature: sign(account.key, message) },
    ctx(),
  );
}

async function rotate(
  account: Readonly<{ name: string; key: Key }>,
  token: string,
  to: Key,
  options: Readonly<{ via?: IdentityService; context?: RequestContext; signer?: Key }> = {},
) {
  const via = options.via ?? service;
  const challenge = await via.createChallenge(account.name, "rotation", ctx());
  const message = messageFor(challenge, "sign-in-key-rotation", keyPrincipal(account.key), keyPrincipal(to));
  return via.rotateSignInKey(
    token,
    {
      challengeId: challenge.id,
      newKey: enrolled(to),
      authorizerSignature: sign(options.signer ?? account.key, message),
      subjectSignature: sign(to, message),
    },
    options.context ?? ctx(),
  );
}

/** Moves a reset's clock back, so it is available now (and its code expired). */
async function age(resetId: string, milliseconds = WAIT_MS + 1_000): Promise<void> {
  await first.query(
    `UPDATE ${prefix}_account_resets
        SET created_at = created_at - ($2::double precision * interval '1 millisecond'),
            available_at = available_at - ($2::double precision * interval '1 millisecond'),
            expires_at = expires_at - ($2::double precision * interval '1 millisecond')
      WHERE id = $1::uuid`,
    [resetId, milliseconds],
  );
}

async function resetRow(resetId: string): Promise<SqlRow | undefined> {
  return (await first.query(`SELECT * FROM ${prefix}_account_resets WHERE id = $1::uuid`, [resetId])).rows[0];
}

async function resetRows(accountId: string): Promise<readonly SqlRow[]> {
  return (
    await first.query(`SELECT * FROM ${prefix}_account_resets WHERE account_id = $1::uuid ORDER BY created_at, id`, [accountId])
  ).rows;
}

async function auditRows(accountId: string, action: string): Promise<readonly SqlRow[]> {
  return (
    await first.query(
      `SELECT metadata, created_at FROM ${prefix}_audit_events WHERE account_id = $1::uuid AND action = $2 ORDER BY created_at, id`,
      [accountId, action],
    )
  ).rows;
}

async function authenticates(token: string): Promise<boolean> {
  try {
    await service.authenticate(token);
    return true;
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe("session-not-found");
    return false;
  }
}

async function loginFails(name: string, key: Key): Promise<boolean> {
  try {
    await login(name, key);
    return false;
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe("invalid-signature");
    return true;
  }
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

async function suspend(accountId: string): Promise<void> {
  await first.query(`UPDATE ${prefix}_accounts SET status = 'suspended' WHERE id = $1::uuid`, [accountId]);
}

function eventsFor(accountId: string, action?: string): readonly SecurityEventNotice[] {
  return events.filter((event) => event.accountId === accountId && (action === undefined || event.action === action));
}

/** Counts the statements a service sends, so "the same work" is checked, not assumed. */
function countingDriver(inner: SqlDriver): SqlDriver & { count: number } {
  const driver = {
    kind: inner.kind,
    count: 0,
    async query<T extends SqlRow = SqlRow>(text: string, params?: readonly SqlParameter[]): Promise<T[]> {
      driver.count += 1;
      return inner.query<T>(text, params);
    },
  };
  return driver;
}

const uuidShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

describe.skipIf(!url)("account resets on PostgreSQL", () => {
  beforeAll(async () => {
    const moduleName: string = "pg";
    const pg = (await import(moduleName)) as { Client: new (options: { connectionString: string }) => Client };
    PgClient = pg.Client;
    first = new PgClient({ connectionString: url! });
    second = new PgClient({ connectionString: url! });
    await Promise.all([first.connect(), second.connect()]);
    service = createIdentityService(pgDriver(first), config(prefix));
    otherService = createIdentityService(pgDriver(second), config(prefix));
    secondPid = Number((await second.query("SELECT pg_backend_pid() AS pid")).rows[0]?.["pid"]);
    expect(await service.migrate()).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
  }, 60_000);

  afterAll(async () => {
    if (!first) return;
    for (const tablePrefix of [prefix, concurrencyPrefix]) {
      await first.query(`DROP TABLE IF EXISTS ${tables.map((t) => `${tablePrefix}_${t}`).join(", ")} CASCADE`);
      await first.query(`DROP FUNCTION IF EXISTS ${tablePrefix}_reject_immutable_mutation() CASCADE`);
    }
    await Promise.all([first.end(), second.end()]);
  }, 60_000);

  describe("migration 8", () => {
    /** The columns, the table, its indexes and constraints, found by relation, not by name. */
    async function resetObjects(): Promise<readonly string[]> {
      const rows = await first.query(
        `WITH t AS (SELECT oid FROM pg_class WHERE oid = to_regclass($1))
         SELECT c.relname || ':r' AS object FROM pg_class c WHERE c.oid IN (SELECT oid FROM t)
          UNION ALL
         SELECT i.indexrelid::regclass::text || ':i' FROM pg_index i WHERE i.indrelid IN (SELECT oid FROM t)
          UNION ALL
         SELECT con.conname::text || ':' || con.contype::text FROM pg_constraint con WHERE con.conrelid IN (SELECT oid FROM t)
          UNION ALL
         SELECT column_name || ':' || data_type || ':' || is_nullable || ':' || column_default
           FROM information_schema.columns
          WHERE table_name = $2 AND column_name IN ('email_reset_enabled', 'signed_in_reset_enabled')
          ORDER BY 1`,
        [`${concurrencyPrefix}_account_resets`, `${concurrencyPrefix}_accounts`],
      );
      return rows.rows.map((row) => String(row["object"]));
    }

    it("adds two defaulted columns and one table, the same from one, two or two concurrent runners", async () => {
      const one = createIdentityService(pgDriver(first), config(concurrencyPrefix));
      const two = createIdentityService(pgDriver(second), config(concurrencyPrefix));
      await one.migrate();
      const expected = await resetObjects();
      expect(expected).toContain("email_reset_enabled:boolean:NO:false");
      expect(expected).toContain("signed_in_reset_enabled:boolean:NO:true");
      // One table; four indexes (the primary key, the live unique index, the
      // account and the expiry index); one primary key, one foreign key and
      // six named checks.
      expect(expected.filter((object) => object.endsWith(":r"))).toHaveLength(1);
      expect(expected.filter((object) => object.endsWith(":i"))).toHaveLength(4);
      expect(expected.filter((object) => object.endsWith(":p"))).toHaveLength(1);
      expect(expected.filter((object) => object.endsWith(":f"))).toHaveLength(1);
      expect(expected.filter((object) => object.endsWith(":c"))).toHaveLength(6);

      const statements = identityMigrations(one.config).find((migration) => migration.version === 8)!.statements;
      for (const statement of statements) {
        await applyMigrationStatement(pgDriver(first), statement);
        await applyMigrationStatement(pgDriver(first), statement);
      }
      expect(await resetObjects()).toEqual(expected);

      const drop = async (): Promise<void> => {
        await first.query(`DROP TABLE ${concurrencyPrefix}_account_resets`);
        await first.query(
          `ALTER TABLE ${concurrencyPrefix}_accounts DROP COLUMN email_reset_enabled, DROP COLUMN signed_in_reset_enabled`,
        );
      };
      for (let round = 0; round < 5; round += 1) {
        await drop();
        await Promise.all(
          [first, second].map(async (client) => {
            for (const statement of statements) {
              await applyMigrationStatement(pgDriver(client), statement);
            }
          }),
        );
        expect(await resetObjects()).toEqual(expected);
      }

      // The whole runner, twice at once, with version 8 not yet recorded.
      await drop();
      await first.query(`DELETE FROM ${concurrencyPrefix}_schema_migrations WHERE version = 8`);
      const [ranOne, ranTwo] = await Promise.all([one.migrate(), two.migrate()]);
      expect([...ranOne, ...ranTwo]).toContain(8);
      expect(await resetObjects()).toEqual(expected);
      expect(
        (await first.query(`SELECT name FROM ${concurrencyPrefix}_schema_migrations WHERE version = 8`)).rows,
      ).toEqual([{ name: "account-resets" }]);
      expect(await one.migrate()).toEqual([]);
    }, 60_000);

    it("gives every account the defaults: email recovery off, the signed-in reset on", async () => {
      const account = await register(username("defaults"));
      const row = (
        await first.query(
          `SELECT email_reset_enabled, signed_in_reset_enabled FROM ${prefix}_accounts WHERE id = $1::uuid`,
          [account.accountId],
        )
      ).rows[0];
      expect(row).toEqual({ email_reset_enabled: false, signed_in_reset_enabled: true });
      const status = await service.accountResetStatus(account.session.token);
      expect(status).toEqual({
        settings: { emailReset: false, signedInReset: true },
        emailVerified: false,
        pendingSignedInReset: null,
      });
    });

    it("refuses rows its checks forbid, and a second live signed-in reset of one account", async () => {
      const account = await register(username("checks"));
      const insert = (fields: Readonly<Record<string, string | number | null>>) => {
        const row = {
          account_id: account.accountId,
          kind: "signed-in",
          code_hash: null,
          session_id: account.session.session.id,
          created_at: "2026-10-19T00:00:00.000Z",
          available_at: "2026-10-22T00:00:00.000Z",
          expires_at: "2026-10-29T00:00:00.000Z",
          ...fields,
        };
        const names = Object.keys(row);
        return first.query(
          `INSERT INTO ${prefix}_account_resets (${names.join(", ")}) VALUES (${names.map((_, index) => `$${String(index + 1)}`).join(", ")})`,
          Object.values(row),
        );
      };
      const hash = "ab".repeat(32);
      await expect(insert({ kind: "phone" })).rejects.toMatchObject({ code: "23514" });
      await expect(insert({ code_hash: "AB".repeat(32) })).rejects.toMatchObject({ code: "23514" });
      await expect(insert({ session_id: null })).rejects.toMatchObject({ code: "23514" });
      await expect(insert({ kind: "email", code_hash: null, session_id: null })).rejects.toMatchObject({ code: "23514" });
      await expect(
        insert({ kind: "email", code_hash: hash, session_id: account.session.session.id }),
      ).rejects.toMatchObject({ code: "23514" });
      // An emailed code is available when it is issued.
      await expect(
        insert({ kind: "email", code_hash: hash, session_id: null, available_at: "2026-10-19T00:00:01.000Z" }),
      ).rejects.toMatchObject({ code: "23514" });
      await expect(insert({ available_at: "2026-10-18T00:00:00.000Z" })).rejects.toMatchObject({ code: "23514" });
      await expect(insert({ expires_at: "2026-10-22T00:00:00.000Z" })).rejects.toMatchObject({ code: "23514" });
      await expect(insert({ attempts: -1 })).rejects.toMatchObject({ code: "23514" });
      await expect(
        insert({ completed_at: "2026-10-23T00:00:00.000Z", aborted_at: "2026-10-23T00:00:00.000Z" }),
      ).rejects.toMatchObject({ code: "23514" });
      await insert({});
      await expect(insert({})).rejects.toMatchObject({ code: "23505" });
      // A closed one does not count; several emailed codes may be live.
      await insert({ aborted_at: "2026-10-20T00:00:00.000Z" });
      await insert({ kind: "email", code_hash: hash, session_id: null, available_at: "2026-10-19T00:00:00.000Z" });
      await insert({ kind: "email", code_hash: hash, session_id: null, available_at: "2026-10-19T00:00:00.000Z" });
      await first.query(`DELETE FROM ${prefix}_account_resets WHERE account_id = $1::uuid`, [account.accountId]);
    });

    it("serves its lookups from indexes, not a scan", async () => {
      const plan = async (text: string): Promise<string> => {
        await first.query("BEGIN");
        try {
          await first.query("SET LOCAL enable_seqscan = off");
          const rows = await first.query(`EXPLAIN ${text}`, [crypto.randomUUID()]);
          return rows.rows.map((row) => String(row["QUERY PLAN"])).join("\n");
        } finally {
          await first.query("ROLLBACK");
        }
      };
      const live = await plan(
        `SELECT id FROM ${prefix}_account_resets WHERE account_id = $1::uuid AND kind = 'signed-in'
            AND completed_at IS NULL AND aborted_at IS NULL`,
      );
      expect(live).toContain(`${prefix}_account_resets_signed_in_live_idx`);
      const history = await plan(
        `SELECT id FROM ${prefix}_account_resets WHERE account_id = $1::uuid AND kind = 'email' AND completed_at IS NULL`,
      );
      expect(history).toContain(`${prefix}_account_resets_account_idx`);
      const expired = await plan(
        `SELECT id FROM ${prefix}_account_resets WHERE expires_at <= now() - interval '1 day' AND id <> $1::uuid`,
      );
      expect(expired).toContain(`${prefix}_account_resets_expires_idx`);
      for (const text of [live, history, expired]) {
        expect(text).not.toMatch(/Seq Scan/u);
      }
    });
  });

  describe("setAccountResetSetting", () => {
    it("turns account recovery by email on only with a verified email, signed over setting:on", async () => {
      const unverified = await register(username("unverified"), { email: `unverified-${suffix}@example.org` });
      const refused = await expectCode(
        () => setSetting(unverified, unverified.session.token, "email-reset", true),
        "reset-setting-refused",
      );
      expect(refused.status).toBe(409);
      expect(refused.details?.["reason"]).toBe("email-unverified");
      const noEmail = await register(username("no-email"));
      await expectCode(() => setSetting(noEmail, noEmail.session.token, "email-reset", true), "reset-setting-refused");

      const account = await verifiedAccount("enable-email");
      const on = await setSetting(account, account.session.token, "email-reset", true);
      expect(on).toEqual({ settings: { emailReset: true, signedInReset: true }, changed: true });
      const again = await setSetting(account, account.session.token, "email-reset", true);
      expect(again.changed).toBe(false);
      expect((await service.accountResetStatus(account.session.token)).settings.emailReset).toBe(true);
      expect((await service.accountResetStatus(account.session.token)).emailVerified).toBe(true);

      const audit = await auditRows(account.accountId, "account.reset-setting");
      expect(audit.map((row) => row["metadata"])).toEqual([
        { setting: "email-reset", enabled: true, closedResets: 0, sessionId: account.session.session.id },
      ]);
      expect(eventsFor(account.accountId, "account.reset-setting")).toEqual([
        expect.objectContaining({ setting: "email-reset", enabled: true }),
      ]);
      const off = await setSetting(account, account.session.token, "email-reset", false);
      expect(off).toEqual({ settings: { emailReset: false, signedInReset: true }, changed: true });
    });

    it("binds the value: a signature over setting:off does not turn a setting on, nor another key's", async () => {
      const account = await verifiedAccount("binds");
      await expectCode(
        () => setSetting(account, account.session.token, "email-reset", true, { signed: false }),
        "invalid-signature",
      );
      await expectCode(
        () => setSetting(account, account.session.token, "email-reset", true, { signer: newKey() }),
        "invalid-signature",
      );
      // A signature for the other setting's action does not verify either.
      const challenge = await service.createChallenge(account.name, "rotation", ctx());
      const message = messageFor(challenge, "signed-in-reset-setting", keyPrincipal(account.key), "setting:on");
      await expectCode(
        () =>
          service.setAccountResetSetting(
            account.session.token,
            { challengeId: challenge.id, setting: "email-reset", enabled: true, authorizerSignature: sign(account.key, message) },
            ctx(),
          ),
        "invalid-signature",
      );
      expect((await service.accountResetStatus(account.session.token)).settings.emailReset).toBe(false);
    });

    it("turns the signed-in reset off only while a recovery key or account recovery by email is set", async () => {
      const account = await verifiedAccount("signed-in-off");
      const refused = await expectCode(
        () => setSetting(account, account.session.token, "signed-in-reset", false),
        "reset-setting-refused",
      );
      expect(refused.details?.["reason"]).toBe("no-other-reset-method");

      // With a recovery key.
      const recovery = newKey();
      const challenge = await service.createChallenge(account.name, "rotation", ctx());
      const enrollment = messageFor(challenge, "recovery-key-enrollment", keyPrincipal(account.key), `recovery-key:${recovery.publicKeyHex}`);
      await service.enrollRecoveryKey(
        account.session.token,
        {
          challengeId: challenge.id,
          recoveryPublicKey: recovery.publicKeyHex,
          authorizerSignature: sign(account.key, enrollment),
          subjectSignature: sign(recovery, enrollment),
        },
        ctx(),
      );
      expect((await setSetting(account, account.session.token, "signed-in-reset", false)).settings.signedInReset).toBe(false);
      expect((await setSetting(account, account.session.token, "signed-in-reset", true)).settings.signedInReset).toBe(true);

      // A deployment without recovery keys does not count one.
      const noRecoveryKeys = createIdentityService(
        pgDriver(first),
        config(prefix, { accountSecurity: { signInKeyRotation: true, emailReset: true, signedInReset: true } }),
      );
      await expectCode(
        () => setSetting(account, account.session.token, "signed-in-reset", false, { via: noRecoveryKeys }),
        "reset-setting-refused",
      );

      // With account recovery by email instead.
      const other = await verifiedAccount("signed-in-off-email");
      await enableEmailReset(other);
      expect((await setSetting(other, other.session.token, "signed-in-reset", false)).settings).toEqual({
        emailReset: true,
        signedInReset: false,
      });
    });

    it("needs the opt-in to turn a setting on, and none to turn one off", async () => {
      const off = createIdentityService(pgDriver(first), config(prefix, { accountSecurity: {} }));
      const account = await verifiedAccount("opt-in");
      await expectCode(() => setSetting(account, account.session.token, "email-reset", true, { via: off }), "invalid-request");
      await expectCode(() => setSetting(account, account.session.token, "signed-in-reset", true, { via: off }), "invalid-request");
      await enableEmailReset(account);
      const withdrawn = await setSetting(account, account.session.token, "email-reset", false, { via: off });
      expect(withdrawn.settings.emailReset).toBe(false);
    });
  });

  describe("the email-change interlock", () => {
    for (const via of ["changeEmail", "updateAccount"] as const) {
      it(`turns account recovery by email off and closes its live codes on ${via}`, async () => {
        const account = await verifiedAccount(`interlock-${via}`);
        await enableEmailReset(account);
        const issued = await startEmail(account.name);
        expect(issued.delivery).not.toBeNull();
        if (via === "changeEmail") {
          const challenge = await service.createChallenge(account.name, "rotation", ctx());
          const message = messageFor(challenge, "email-change", keyPrincipal(account.key), "email:moved@example.org");
          await service.changeEmail(
            account.session.token,
            { challengeId: challenge.id, email: "moved@example.org", authorizerSignature: sign(account.key, message) },
            ctx(),
          );
          const audit = await auditRows(account.accountId, "account.email-change");
          expect(audit.at(-1)?.["metadata"]).toMatchObject({ emailResetDisabled: true, closedResets: 1 });
        } else {
          await service.updateAccount(account.accountId, { email: "moved@example.org" }, ctx());
          const audit = await auditRows(account.accountId, "account.update");
          expect(audit.at(-1)?.["metadata"]).toMatchObject({ emailChanged: true, emailResetDisabled: true, closedResets: 1 });
        }
        const status = await service.accountResetStatus(account.session.token);
        expect(status.settings.emailReset).toBe(false);
        expect(status.emailVerified).toBe(false);
        expect((await resetRow(issued.resetId))?.["aborted_at"]).not.toBeNull();
        // The code sent to the old address completes nothing.
        await expectCode(() => completeEmail(account.name, issued.resetId, issued.delivery!.code, newKey()), "invalid-signature");
        // Back on only once the new address is verified.
        await expectCode(() => setSetting(account, account.session.token, "email-reset", true), "reset-setting-refused");
        const started = await service.startEmailVerification({ username: account.name, email: "moved@example.org" }, ctx());
        await service.confirmEmailVerification(started.verificationId, started.code, ctx());
        await enableEmailReset(account);
        // A display-name edit changes neither.
        await service.updateAccount(account.accountId, { displayName: "Still on" }, ctx());
        expect((await service.accountResetStatus(account.session.token)).settings.emailReset).toBe(true);
      });
    }

    it("keeps the setting when the address is unchanged", async () => {
      const account = await verifiedAccount("interlock-same");
      await enableEmailReset(account);
      await service.updateAccount(account.accountId, { email: account.email!.toUpperCase() }, ctx());
      expect((await service.accountResetStatus(account.session.token)).settings.emailReset).toBe(true);
    });
  });

  describe("startAccountReset", () => {
    it("answers every username alike and issues a code only to an eligible account", async () => {
      const counting = countingDriver(pgDriver(first));
      const counted = createIdentityService(counting, config(prefix));
      const now = new Date(Date.now() + 1_000);
      const eligible = await verifiedAccount("eligible");
      await enableEmailReset(eligible);
      const settingOff = await verifiedAccount("setting-off");
      const unverified = await register(username("unverified-start"), { email: `unverified-start-${suffix}@example.org` });
      const noEmail = await register(username("no-email-start"));
      const suspended = await verifiedAccount("suspended-start");
      await enableEmailReset(suspended);
      await suspend(suspended.accountId);

      const cases = [
        { label: "unknown", name: username("nobody") },
        { label: "no email", name: noEmail.name },
        { label: "unverified", name: unverified.name },
        { label: "setting off", name: settingOff.name },
        { label: "suspended", name: suspended.name },
        { label: "eligible", name: eligible.name },
      ];
      const answers: { label: string; statements: number; issued: IssuedAccountReset }[] = [];
      for (const entry of cases) {
        counting.count = 0;
        const issued = await counted.startAccountReset({ username: entry.name }, ctx({ now }));
        answers.push({ label: entry.label, statements: counting.count, issued });
      }
      const statements = new Set(answers.map((answer) => answer.statements));
      expect(statements.size).toBe(1);
      for (const answer of answers) {
        expect(Object.keys(answer.issued).sort()).toEqual(["delivery", "expiresAt", "resetId"]);
        expect(answer.issued.resetId).toMatch(uuidShape);
        expect(answer.issued.expiresAt.toISOString()).toBe(new Date(now.getTime() + 900_000).toISOString());
        expect(answer.issued.delivery === null).toBe(answer.label !== "eligible");
      }
      expect(new Set(answers.map((answer) => answer.issued.resetId)).size).toBe(answers.length);
      const delivered = answers.at(-1)!.issued.delivery!;
      expect(delivered.email).toBe(eligible.email);
      // 16 symbols of 5 bits: a digest that leaks cannot be searched within the code's life.
      expect(delivered.code).toMatch(/^[A-HJ-NP-Z2-9]{16}$/u);

      // A row (its code hashed) only for the eligible account, and audit only there.
      for (const account of [settingOff, unverified, noEmail, suspended]) {
        expect(await resetRows(account.accountId)).toHaveLength(0);
        expect(await auditRows(account.accountId, "account.email-reset.start")).toHaveLength(0);
      }
      const [row] = await resetRows(eligible.accountId);
      expect(row?.["kind"]).toBe("email");
      expect(row?.["code_hash"]).toMatch(/^[0-9a-f]{64}$/u);
      expect(String(row?.["code_hash"])).not.toContain(delivered.code);
      expect(row?.["attempts"]).toBe(0);
      expect(await auditRows(eligible.accountId, "account.email-reset.start")).toHaveLength(1);
      // No hook for a start: it would make an issued code slower to answer.
      expect(eventsFor(eligible.accountId).map((event) => event.action)).not.toContain("account.email-reset.start");
    });

    it("rate-limits per username whoever asks, by hour and by day, alike for known and unknown usernames", async () => {
      const known = await verifiedAccount("rate-known");
      await enableEmailReset(known);
      const base = Date.now() + 10 * 86_400_000;
      for (const name of [known.name, username("rate-unknown")]) {
        for (let attempt = 0; attempt < 3; attempt += 1) {
          await startEmail(name, service, ctx({ now: new Date(base + attempt) }));
        }
        const hourly = await expectCode(() => startEmail(name, service, ctx({ now: new Date(base + 10) })), "rate-limited");
        expect(hourly.details?.["rule"]).toBe("account-reset-start");
        // Seven more over the next hours, then the daily cap.
        for (let hour = 1; hour <= 7; hour += 1) {
          await startEmail(name, service, ctx({ now: new Date(base + hour * HOUR + 1_000) }));
        }
        // The hour window has rolled, so the eleventh of the day is the daily one.
        const daily = await expectCode(
          () => startEmail(name, service, ctx({ now: new Date(base + 9 * HOUR) })),
          "rate-limited",
        );
        expect(daily.details?.["rule"]).toBe("account-reset-start-day");
      }
      // Per caller: 20 an hour across usernames.
      const caller = { ipHash: `reset-spray-${suffix}` };
      for (let attempt = 0; attempt < 20; attempt += 1) {
        await service.startAccountReset({ username: username(`spray-${String(attempt)}`) }, caller);
      }
      const sprayed = await expectCode(() => service.startAccountReset({ username: username("spray-last") }, caller), "rate-limited");
      expect(sprayed.details?.["rule"]).toBe("account-reset-start-ip");
    });

    it("counts a per-recipient cap of its own inside its statement, which nothing else reads, and never says so", async () => {
      const account = await verifiedAccount("recipient");
      await enableEmailReset(account);
      const bucketOf = (rule: string): string =>
        bytesToHex(
          sha256(encoder.encode(["web2-ish-self-custody rate limit bucket v1", serviceProfileId, rule, account.email!].join("\n"))),
        );
      const resetBucket = bucketOf("account-reset-recipient");
      const verificationBucket = bucketOf("email-verification-recipient");
      const count = async (bucket: string): Promise<number> =>
        Number((await first.query(`SELECT count FROM ${prefix}_rate_limits WHERE bucket = $1`, [bucket])).rows[0]?.["count"] ?? 0);
      // The account's verification counted one mail to the address.
      expect(await count(verificationBucket)).toBe(1);
      expect(await count(resetBucket)).toBe(0);
      expect((await startEmail(account.name)).delivery).not.toBeNull();
      expect(await count(resetBucket)).toBe(1);
      // The start leaves email verification's bucket alone, so its 429, which
      // anyone can draw for an address, cannot tell an eligible account's
      // start from any other username's: the address still takes exactly the
      // seven more verification mails it would have taken with no start.
      expect(await count(verificationBucket)).toBe(1);
      for (let index = 0; index < 7; index += 1) {
        await service.startEmailVerification({ username: username(`probe-${String(index)}`), email: account.email! }, ctx());
      }
      const probed = await expectCode(
        () => service.startEmailVerification({ username: username("probe-last"), email: account.email! }, ctx()),
        "rate-limited",
      );
      expect(probed.details?.["rule"]).toBe("email-verification-recipient");
      // And that verification traffic does not silence the reset codes.
      expect((await startEmail(account.name)).delivery).not.toBeNull();
      expect(await count(resetBucket)).toBe(2);
      // Over its own cap: no code, and the answer it always gives.
      await first.query(`UPDATE ${prefix}_rate_limits SET count = 8 WHERE bucket = $1`, [resetBucket]);
      const capped = await startEmail(account.name);
      expect(capped.delivery).toBeNull();
      expect(Object.keys(capped).sort()).toEqual(["delivery", "expiresAt", "resetId"]);
      expect(await resetRows(account.accountId)).toHaveLength(2);
    });

    it("refuses with invalid-request without the opt-in, and in random-vault mode before any SQL", async () => {
      const off = createIdentityService(pgDriver(first), config(prefix, { accountSecurity: { signedInReset: true } }));
      await expectCode(() => off.startAccountReset({ username: "anyone@example.com" }), "invalid-request");
      await expectCode(() => service.startAccountReset({ username: "x" }, ctx()), "invalid-username");
    });
  });

  describe("completeAccountReset", () => {
    async function emailAccount(label: string) {
      const account = await verifiedAccount(label);
      await enableEmailReset(account);
      return account;
    }

    it("replaces the key, revokes every session, issues one, and closes the account's other live resets", async () => {
      const account = await emailAccount("email-complete");
      const other = await login(account.name, account.key);
      const signedIn = await service.startSignedInReset(other.token, ctx());
      const earlier = await startEmail(account.name);
      const issued = await startEmail(account.name);
      const next = newKey();
      const done = await completeEmail(account.name, issued.resetId, issued.delivery!.code.toLowerCase(), next, {
        context: ctx({ clientLabel: "Firefox on macOS" }),
      });
      expect(done.wallets.map((wallet) => wallet.publicKey)).toEqual([next.identifier]);
      expect([...done.revokedSessionIds].sort()).toEqual([account.session.session.id, other.session.id].sort());
      expect(await authenticates(account.session.token)).toBe(false);
      expect(await authenticates(other.token)).toBe(false);
      expect(await authenticates(done.session.token)).toBe(true);
      expect(await loginFails(account.name, account.key)).toBe(true);
      await login(account.name, next);

      expect((await resetRow(issued.resetId))?.["completed_at"]).not.toBeNull();
      expect((await resetRow(earlier.resetId))?.["aborted_at"]).not.toBeNull();
      expect((await resetRow(signedIn.reset.id))?.["aborted_at"]).not.toBeNull();
      const [audit] = await auditRows(account.accountId, "account.email-reset");
      expect(audit?.["metadata"]).toEqual({
        method: "email",
        revokedSessions: 2,
        closedResets: 2,
        sessionId: done.session.session.id,
      });
      expect(eventsFor(account.accountId, "account.email-reset")).toEqual([
        expect.objectContaining({ revokedSessions: 2, clientLabel: "Firefox on macOS" }),
      ]);
    });

    it("is single use, bound to its reset id, and signed by the new key only", async () => {
      const account = await emailAccount("email-single");
      const a = await startEmail(account.name);
      const b = await startEmail(account.name);
      // A's code against B's id.
      await expectCode(() => completeEmail(account.name, b.resetId, a.delivery!.code, newKey()), "invalid-signature");
      // The current key signing for the new one: only the subject signs, and it must be the new key.
      await expectCode(
        () => completeEmail(account.name, a.resetId, a.delivery!.code, newKey(), { signer: account.key }),
        "invalid-signature",
      );
      const next = newKey();
      await completeEmail(account.name, a.resetId, a.delivery!.code, next);
      await expectCode(() => completeEmail(account.name, a.resetId, a.delivery!.code, newKey()), "invalid-signature");
      // The completion closed B.
      await expectCode(() => completeEmail(account.name, b.resetId, b.delivery!.code, newKey()), "invalid-signature");
      expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([next.identifier]);
    });

    it("allows five attempts, then refuses even the right code", async () => {
      const account = await emailAccount("email-attempts");
      const issued = await startEmail(account.name);
      for (let attempt = 0; attempt < 5; attempt += 1) {
        await expectCode(() => completeEmail(account.name, issued.resetId, "WRONGCOD", newKey()), "invalid-signature");
      }
      expect((await resetRow(issued.resetId))?.["attempts"]).toBe(5);
      await expectCode(() => completeEmail(account.name, issued.resetId, issued.delivery!.code, newKey()), "invalid-signature");
      expect((await resetRow(issued.resetId))?.["attempts"]).toBe(5);
    });

    it("counts parallel guesses one attempt each", async () => {
      const account = await emailAccount("email-parallel");
      const issued = await startEmail(account.name);
      // One connection per guess, so the guesses race in the database rather
      // than queue on one client.
      const lanes = await openConnections(8);
      try {
        const guesses = await Promise.allSettled(
          lanes.map((lane) =>
            completeEmail(account.name, issued.resetId, "WRONGCOD", newKey(), { via: lane.service }),
          ),
        );
        expect(guesses.every((guess) => guess.status === "rejected")).toBe(true);
        for (const guess of guesses) {
          expect(((guess as PromiseRejectedResult).reason as IdentityError).code).toBe("invalid-signature");
        }
      } finally {
        await closeConnections(lanes);
      }
      expect((await resetRow(issued.resetId))?.["attempts"]).toBe(5);
    });

    it("expires after 15 minutes", async () => {
      const account = await emailAccount("email-expiry");
      const issued = await startEmail(account.name);
      const later = new Date(issued.expiresAt.getTime() + 1);
      const challenge = await service.createChallenge(account.name, "rotation", ctx({ now: later }));
      const next = newKey();
      const message = messageFor(challenge, "email-reset", `email:${issued.resetId}`, keyPrincipal(next));
      await expectCode(
        () =>
          service.completeAccountReset(
            {
              username: account.name,
              resetId: issued.resetId,
              code: issued.delivery!.code,
              challengeId: challenge.id,
              newKey: enrolled(next),
              subjectSignature: sign(next, message),
            },
            ctx({ now: later }),
          ),
        "invalid-signature",
      );
    });

    it("answers one uniform invalid-signature for every failure an unauthenticated caller can cause", async () => {
      const account = await emailAccount("email-uniform");
      const issued = await startEmail(account.name);
      const code = issued.delivery!.code;
      const refusals: (() => Promise<unknown>)[] = [
        () => completeEmail(username("nobody"), issued.resetId, code, newKey()),
        () => completeEmail(account.name, crypto.randomUUID(), code, newKey()),
        async () => {
          // A malformed reset id (signed over a well-formed one: no builder signs this one).
          const challenge = await service.createChallenge(account.name, "rotation", ctx());
          const next = newKey();
          const message = messageFor(challenge, "email-reset", `email:${crypto.randomUUID()}`, keyPrincipal(next));
          return service.completeAccountReset(
            { username: account.name, resetId: "not-a-uuid", code, challengeId: challenge.id, newKey: enrolled(next), subjectSignature: sign(next, message) },
            ctx(),
          );
        },
        () => completeEmail(account.name, issued.resetId, "AAAAAAAA", newKey()),
        async () => {
          // A challenge of another username.
          const challenge = await service.createChallenge(username("someone"), "rotation", ctx());
          const next = newKey();
          const message = messageFor(challenge, "email-reset", `email:${issued.resetId}`, keyPrincipal(next));
          return service.completeAccountReset(
            { username: account.name, resetId: issued.resetId, code, challengeId: challenge.id, newKey: enrolled(next), subjectSignature: sign(next, message) },
            ctx(),
          );
        },
      ];
      for (const run of refusals) {
        const error = await expectCode(run, "invalid-signature");
        expect(error.status).toBe(401);
      }
      // The setting turned off, then on again: the old code is closed.
      const toggled = await emailAccount("email-uniform-toggled");
      const second = await startEmail(toggled.name);
      await setSetting(toggled, toggled.session.token, "email-reset", false);
      await enableEmailReset(toggled);
      await expectCode(() => completeEmail(toggled.name, second.resetId, second.delivery!.code, newKey()), "invalid-signature");
      // A suspended account.
      const suspended = await emailAccount("email-uniform-suspended");
      const third = await startEmail(suspended.name);
      await suspend(suspended.accountId);
      await expectCode(() => completeEmail(suspended.name, third.resetId, third.delivery!.code, newKey()), "invalid-signature");
      // The right code naming the current key is key-unchanged: only the code's holder gets this far.
      const fourth = await startEmail(account.name);
      await expectCode(() => completeEmail(account.name, fourth.resetId, fourth.delivery!.code, account.key), "key-unchanged");
      for (const each of [account, toggled, suspended]) {
        expect((await service.listWallets(each.accountId)).map((wallet) => wallet.publicKey)).toEqual([each.key.identifier]);
      }
    });
  });

  describe("the signed-in reset", () => {
    it("waits 72 hours, then the initiating session completes it; other sessions go, the caller's stays", async () => {
      const account = await register(username("signed-in"));
      const other = await login(account.name, account.key);
      const startedAt = new Date(Date.now() + 1_000);
      const started = await service.startSignedInReset(account.session.token, ctx({ now: startedAt }));
      expect(started.delivery).toBeNull();
      expect(started.reset).toMatchObject({ initiatedByCaller: true, codeUsable: false });
      expect(started.reset.availableAt.getTime() - started.reset.createdAt.getTime()).toBe(WAIT_MS);
      expect(started.reset.expiresAt.getTime() - started.reset.availableAt.getTime()).toBe(7 * 86_400_000);
      expect(eventsFor(account.accountId, "account.signed-in-reset.start")).toEqual([
        expect.objectContaining({ availableAt: started.reset.availableAt }),
      ]);

      // Every other session sees it, not as its own.
      const seen = await service.accountResetStatus(other.token, ctx({ now: startedAt }));
      expect(seen.pendingSignedInReset).toEqual({ ...started.reset, initiatedByCaller: false });
      expect((await service.accountResetStatus(account.session.token, ctx({ now: startedAt }))).pendingSignedInReset?.initiatedByCaller).toBe(true);

      // Before the wait: not available, with the time it will be.
      const early = await expectCode(
        () => completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { context: ctx({ now: new Date(started.reset.availableAt.getTime() - 1_000) }) }),
        "reset-unavailable",
      );
      expect(early.details?.["availableAt"]).toBe(started.reset.availableAt.toISOString());
      // Another session cannot complete it, even after the wait.
      const after = new Date(started.reset.availableAt.getTime() + 1_000);
      await expectCode(
        () => completeSignedIn(account.name, other.token, started.reset.id, newKey(), { context: ctx({ now: after }) }),
        "reset-unavailable",
      );

      const next = newKey();
      const done = await completeSignedIn(account.name, account.session.token, started.reset.id, next, { context: ctx({ now: after }) });
      expect(done.wallets.map((wallet) => wallet.publicKey)).toEqual([next.identifier]);
      expect(done.revokedSessionIds).toEqual([other.session.id]);
      expect(await authenticates(account.session.token)).toBe(true);
      expect(await authenticates(other.token)).toBe(false);
      expect(await loginFails(account.name, account.key)).toBe(true);
      await login(account.name, next);
      expect((await resetRow(started.reset.id))?.["completed_at"]).not.toBeNull();
      const [audit] = await auditRows(account.accountId, "account.signed-in-reset");
      expect(audit?.["metadata"]).toEqual({
        method: "wait",
        revokedSessions: 1,
        closedResets: 0,
        sessionId: account.session.session.id,
      });
      expect(eventsFor(account.accountId, "account.signed-in-reset")).toEqual([expect.objectContaining({ revokedSessions: 1 })]);
      // Single use.
      await expectCode(
        () => completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { context: ctx({ now: after }) }),
        "reset-unavailable",
      );
    });

    it("any session aborts it, the initiating one included", async () => {
      const account = await register(username("abort"));
      const other = await login(account.name, account.key);
      const started = await service.startSignedInReset(account.session.token, ctx());
      expect(await service.abortSignedInReset(other.token, ctx())).toEqual({ aborted: true });
      expect((await service.accountResetStatus(other.token)).pendingSignedInReset).toBeNull();
      expect(await service.abortSignedInReset(other.token, ctx())).toEqual({ aborted: false });
      await age(started.reset.id);
      await expectCode(() => completeSignedIn(account.name, account.session.token, started.reset.id, newKey()), "reset-unavailable");
      const [audit] = await auditRows(account.accountId, "account.signed-in-reset.abort");
      expect(audit?.["metadata"]).toEqual({ abortedBy: "session", sessionId: other.session.id });
      expect(eventsFor(account.accountId, "account.signed-in-reset.abort")).toEqual([
        expect.objectContaining({ abortedBy: "session" }),
      ]);

      const again = await service.startSignedInReset(account.session.token, ctx());
      expect(await service.abortSignedInReset(account.session.token, ctx())).toEqual({ aborted: true });
      expect((await resetRow(again.reset.id))?.["aborted_at"]).not.toBeNull();
    });

    it("is aborted by a sign-in with the password, in the login statement", async () => {
      const account = await register(username("login-abort"));
      const started = await service.startSignedInReset(account.session.token, ctx());
      const fresh = await login(account.name, account.key, service, ctx({ clientLabel: "Safari on iOS" }));
      expect((await resetRow(started.reset.id))?.["aborted_at"]).not.toBeNull();
      const [audit] = await auditRows(account.accountId, "account.signed-in-reset.abort");
      expect(audit?.["metadata"]).toEqual({ abortedBy: "login", sessionId: fresh.session.id });
      expect(eventsFor(account.accountId, "account.signed-in-reset.abort")).toEqual([
        expect.objectContaining({ abortedBy: "login", clientLabel: "Safari on iOS" }),
      ]);
      // In the same statement as the session: the audit rows carry one clock.
      const [login_] = (await auditRows(account.accountId, "account.login")).slice(-1);
      expect((login_?.["created_at"] as Date).getTime()).toBe((audit?.["created_at"] as Date).getTime());
      await age(started.reset.id);
      await expectCode(() => completeSignedIn(account.name, account.session.token, started.reset.id, newKey()), "reset-unavailable");
      // A failed sign-in aborts nothing.
      const next = await service.startSignedInReset(account.session.token, ctx());
      await loginFails(account.name, newKey());
      expect((await resetRow(next.reset.id))?.["aborted_at"]).toBeNull();
    });

    it("is aborted by a password change, even one made on the session that started it", async () => {
      // A stolen copy of the owner's session starts the reset; the owner
      // changes the password on that same session, which the rotation keeps.
      const account = await register(username("rotation-abort"));
      const other = await login(account.name, account.key);
      const started = await service.startSignedInReset(account.session.token, ctx());
      const next = newKey();
      const rotated = await rotate(account, account.session.token, next, { context: ctx({ clientLabel: "Firefox on macOS" }) });
      expect(rotated.revokedSessionIds).toEqual([other.session.id]);
      expect((await resetRow(started.reset.id))?.["aborted_at"]).not.toBeNull();
      const [audit] = await auditRows(account.accountId, "account.signed-in-reset.abort");
      expect(audit?.["metadata"]).toEqual({ abortedBy: "rotation", sessionId: account.session.session.id });
      // In the rotation's own statement: the audit rows carry one clock.
      const [rotation] = await auditRows(account.accountId, "account.key-rotate");
      expect((rotation?.["created_at"] as Date).getTime()).toBe((audit?.["created_at"] as Date).getTime());
      expect(eventsFor(account.accountId, "account.signed-in-reset.abort")).toEqual([
        expect.objectContaining({ abortedBy: "rotation", clientLabel: "Firefox on macOS" }),
      ]);
      expect((await service.accountResetStatus(account.session.token)).pendingSignedInReset).toBeNull();
      // 72 hours on, the session that started it cannot complete it, and the
      // new password still signs in.
      await age(started.reset.id);
      await expectCode(() => completeSignedIn(account.name, account.session.token, started.reset.id, newKey()), "reset-unavailable");
      expect(await loginFails(account.name, account.key)).toBe(true);
      await login(account.name, next);

      // A rotation with nothing pending aborts nothing, and a refused one leaves a pending reset alone.
      const owner = { name: account.name, key: next };
      const again = newKey();
      await rotate(owner, account.session.token, again);
      expect(await auditRows(account.accountId, "account.signed-in-reset.abort")).toHaveLength(1);
      const pending = await service.startSignedInReset(account.session.token, ctx());
      await expectCode(() => rotate({ name: account.name, key: again }, account.session.token, newKey(), { signer: next }), "invalid-signature");
      expect((await resetRow(pending.reset.id))?.["aborted_at"]).toBeNull();
      expect(eventsFor(account.accountId, "account.signed-in-reset.abort")).toHaveLength(1);
    });

    it("completes at once with the emailed code when account recovery by email is on", async () => {
      const account = await verifiedAccount("signed-in-code");
      await enableEmailReset(account);
      const other = await login(account.name, account.key);
      const started = await service.startSignedInReset(account.session.token, ctx());
      expect(started.delivery?.email).toBe(account.email);
      expect(started.reset.codeUsable).toBe(true);
      await expectCode(
        () => completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { code: "WRONGCOD" }),
        "email-verification-failed",
      );
      // Another session cannot use the code.
      await expectCode(
        () => completeSignedIn(account.name, other.token, started.reset.id, newKey(), { code: started.delivery!.code }),
        "email-verification-failed",
      );
      const next = newKey();
      const done = await completeSignedIn(account.name, account.session.token, started.reset.id, next, {
        code: `${started.delivery!.code.slice(0, 4)}-${started.delivery!.code.slice(4)}`,
      });
      expect(done.revokedSessionIds).toEqual([other.session.id]);
      const [audit] = await auditRows(account.accountId, "account.signed-in-reset");
      expect(audit?.["metadata"]).toMatchObject({ method: "email-code" });
    });

    it("keeps the wait when the code runs out, expires or email recovery goes off", async () => {
      const account = await verifiedAccount("signed-in-code-limits");
      await enableEmailReset(account);
      const started = await service.startSignedInReset(account.session.token, ctx());
      for (let attempt = 0; attempt < 5; attempt += 1) {
        await expectCode(
          () => completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { code: "WRONGCOD" }),
          "email-verification-failed",
        );
      }
      await expectCode(
        () => completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { code: started.delivery!.code }),
        "email-verification-failed",
      );
      expect((await service.accountResetStatus(account.session.token)).pendingSignedInReset?.codeUsable).toBe(false);
      await age(started.reset.id);
      await completeSignedIn(account.name, account.session.token, started.reset.id, newKey());

      // Email recovery turned off after the code was sent: the code no longer completes it.
      const second = await verifiedAccount("signed-in-code-off");
      await enableEmailReset(second);
      const pending = await service.startSignedInReset(second.session.token, ctx());
      await setSetting(second, second.session.token, "email-reset", false);
      await expectCode(
        () => completeSignedIn(second.name, second.session.token, pending.reset.id, newKey(), { code: pending.delivery!.code }),
        "email-verification-failed",
      );
    });

    it("keeps one pending reset per account; a lapsed one, or one whose session is gone, is replaced", async () => {
      const account = await register(username("one-pending"));
      const other = await login(account.name, account.key);
      const started = await service.startSignedInReset(account.session.token, ctx());
      const pending = await expectCode(() => service.startSignedInReset(other.token, ctx()), "reset-pending");
      expect(pending.status).toBe(409);
      await expectCode(() => service.startSignedInReset(account.session.token, ctx()), "reset-pending");

      // Its session revoked by another: the reset is gone with it.
      expect(await service.revokeSessionById(other.token, account.session.session.id, ctx())).toEqual({ revoked: true });
      expect((await service.accountResetStatus(other.token)).pendingSignedInReset).toBeNull();
      const replacement = await service.startSignedInReset(other.token, ctx());
      expect((await resetRow(started.reset.id))?.["aborted_at"]).not.toBeNull();
      // Lapsed: past its window.
      await age(replacement.reset.id, WAIT_MS + 8 * 86_400_000);
      const third = await service.startSignedInReset(other.token, ctx());
      expect((await resetRow(replacement.reset.id))?.["aborted_at"]).not.toBeNull();
      expect((await service.accountResetStatus(other.token)).pendingSignedInReset?.id).toBe(third.reset.id);
    });

    it("leaves one live reset when two sessions start at once", async () => {
      for (let round = 0; round < 5; round += 1) {
        const account = await register(username(`race-${String(round)}`));
        const other = await login(account.name, account.key);
        const results = await Promise.allSettled([
          service.startSignedInReset(account.session.token, ctx()),
          otherService.startSignedInReset(other.token, ctx()),
        ]);
        const fulfilled = results.filter((result) => result.status === "fulfilled");
        expect(fulfilled).toHaveLength(1);
        const rejected = results.find((result) => result.status === "rejected") as PromiseRejectedResult;
        expect((rejected.reason as IdentityError).code).toBe("reset-pending");
        const live = (await resetRows(account.accountId)).filter((row) => row["completed_at"] === null && row["aborted_at"] === null);
        expect(live).toHaveLength(1);
      }
    });

    it("keeps the initiating session from signing out the others while it is pending (reset-pending)", async () => {
      const account = await register(username("no-revoke"));
      const other = await login(account.name, account.key);
      const third = await login(account.name, account.key);
      await service.startSignedInReset(account.session.token, ctx());
      await expectCode(() => service.revokeOtherSessions(account.session.token, ctx()), "reset-pending");
      await expectCode(() => service.revokeSessionById(account.session.token, other.session.id, ctx()), "reset-pending");
      expect(await authenticates(other.token)).toBe(true);
      expect(await auditRows(account.accountId, "session.revoke-others")).toHaveLength(0);
      // Over HTTP, with the session routes on: 409.
      const router = createIdentityRouter(service, { useCookies: false, accountSecurityRoutes: true });
      const response = await router(
        new Request("https://example.test/identity/sessions", { method: "DELETE", headers: { Authorization: `Bearer ${account.session.token}` } }),
      );
      expect(response.status).toBe(409);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe("reset-pending");
      // Its own sign-out still works for the others, and they can sign it out.
      expect(await service.revokeSessionById(other.token, third.session.id, ctx())).toEqual({ revoked: true });
      // After an abort, the initiator may again.
      await service.abortSignedInReset(other.token, ctx());
      expect((await service.revokeOtherSessions(account.session.token, ctx())).revokedSessionIds).toEqual([other.session.id]);
    });

    it("is refused while the account's setting is off, and turning the setting off aborts a pending one", async () => {
      const account = await verifiedAccount("setting-gate");
      await enableEmailReset(account);
      const pending = await service.startSignedInReset(account.session.token, ctx());
      await setSetting(account, account.session.token, "signed-in-reset", false);
      expect((await resetRow(pending.reset.id))?.["aborted_at"]).not.toBeNull();
      const audit = await auditRows(account.accountId, "account.reset-setting");
      expect(audit.at(-1)?.["metadata"]).toMatchObject({ setting: "signed-in-reset", enabled: false, closedResets: 1 });
      const refused = await expectCode(() => service.startSignedInReset(account.session.token, ctx()), "reset-setting-refused");
      expect(refused.details?.["reason"]).toBe("signed-in-reset-off");
    });

    it("is refused, without a code, when the session would expire before the reset becomes available", async () => {
      // Sessions keep their expiry, and only the initiating one completes a
      // reset, so the start says so now rather than after 72 hours.
      const account = await register(username("ttl"));
      const expiresAt = account.session.session.expiresAt.getTime();
      const late = new Date(expiresAt - WAIT_MS + HOUR);
      const refused = await expectCode(() => service.startSignedInReset(account.session.token, ctx({ now: late })), "reset-unavailable");
      expect(refused.status).toBe(409);
      expect(refused.details).toEqual({
        reason: "session-expires-first",
        sessionExpiresAt: account.session.session.expiresAt.toISOString(),
      });
      expect(await resetRows(account.accountId)).toHaveLength(0);
      expect(await auditRows(account.accountId, "account.signed-in-reset.start")).toHaveLength(0);
      expect(eventsFor(account.accountId, "account.signed-in-reset.start")).toHaveLength(0);
      // Started early enough, the same session completes it before it expires.
      const early = new Date(expiresAt - WAIT_MS - HOUR);
      const started = await service.startSignedInReset(account.session.token, ctx({ now: early }));
      const next = newKey();
      await completeSignedIn(account.name, account.session.token, started.reset.id, next, {
        context: ctx({ now: new Date(started.reset.availableAt.getTime() + 1_000) }),
      });
      expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([next.identifier]);

      // With an emailed code the reset can complete at once, so it starts.
      const coded = await verifiedAccount("ttl-code");
      await enableEmailReset(coded);
      const codedLate = new Date(coded.session.session.expiresAt.getTime() - WAIT_MS + HOUR);
      const issued = await service.startSignedInReset(coded.session.token, ctx({ now: codedLate }));
      expect(issued.delivery).not.toBeNull();
      await completeSignedIn(coded.name, coded.session.token, issued.reset.id, newKey(), {
        code: issued.delivery!.code,
        context: ctx({ now: codedLate }),
      });
    });

    it("closes a reset that started while the setting was being turned off, when it is turned on again", async () => {
      // The turn-off's snapshot predates the start's row, so it cannot close
      // it; the reset must neither count as pending while the setting is off
      // nor come back when it is turned on.
      const account = await verifiedAccount("setting-race");
      await enableEmailReset(account);
      const other = await login(account.name, account.key);
      // Signed in before the start: a password sign-in would abort the reset.
      const third = await login(account.name, account.key);
      const [starter, setter] = await openConnections(2);
      let started: Awaited<ReturnType<IdentityService["startSignedInReset"]>>;
      try {
        await starter!.client.query("BEGIN");
        let turnOff: Promise<unknown> | undefined;
        try {
          started = await starter!.service.startSignedInReset(account.session.token, ctx());
          turnOff = setSetting(account, account.session.token, "signed-in-reset", false, { via: setter!.service });
          void turnOff.catch(() => undefined);
          await waitUntilBlocked(setter!.pid);
        } finally {
          await starter!.client.query("COMMIT");
        }
        expect(await turnOff).toMatchObject({ changed: true, settings: { signedInReset: false } });
      } finally {
        await closeConnections([starter!, setter!]);
      }
      // The turn-off could not see the start's row, so it is still open ...
      expect((await resetRow(started!.reset.id))?.["aborted_at"]).toBeNull();
      expect((await auditRows(account.accountId, "account.reset-setting")).at(-1)?.["metadata"]).toMatchObject({
        setting: "signed-in-reset",
        enabled: false,
        closedResets: 0,
      });
      // ... but while the setting is off it is not pending: no banner, and
      // its session may sign out the others.
      expect((await service.accountResetStatus(other.token)).pendingSignedInReset).toBeNull();
      expect(await service.revokeSessionById(account.session.token, third.session.id, ctx())).toEqual({ revoked: true });
      // Turning it on closes it, so the wait that already ran cannot complete it.
      expect((await setSetting(account, account.session.token, "signed-in-reset", true)).changed).toBe(true);
      expect((await resetRow(started!.reset.id))?.["aborted_at"]).not.toBeNull();
      const audit = await auditRows(account.accountId, "account.reset-setting");
      expect(audit.at(-1)?.["metadata"]).toMatchObject({ setting: "signed-in-reset", enabled: true, closedResets: 1 });
      await age(started!.reset.id);
      await expectCode(() => completeSignedIn(account.name, account.session.token, started!.reset.id, newKey()), "reset-unavailable");
      expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([account.key.identifier]);
      expect(await authenticates(other.token)).toBe(true);
    });

    it("fences a start invisible to a concurrent authorized abort, then permits a fresh reset", async () => {
      const account = await register(username("abort-start-fence"));
      const connections = await openConnections(2);
      const [starter, canceller] = [connections[0]!, connections[1]!];
      let started: Awaited<ReturnType<IdentityService["startSignedInReset"]>>;
      let abort: Promise<{ aborted: boolean }> | undefined;
      try {
        await starter.client.query("BEGIN");
        try {
          started = await starter.service.startSignedInReset(account.session.token, ctx());
          abort = canceller.service.abortSignedInReset(account.session.token, ctx());
          void abort.catch(() => undefined);
          await waitUntilBlocked(canceller.pid);
        } finally {
          await starter.client.query("COMMIT");
        }
        // The abort's statement snapshot cannot see the uncommitted insert.
        expect(await abort).toEqual({ aborted: false });
      } finally {
        await closeConnections(connections);
      }
      expect((await resetRow(started!.reset.id))?.["aborted_at"]).toBeNull();
      expect((await service.accountResetStatus(account.session.token)).pendingSignedInReset).toBeNull();
      await age(started!.reset.id);
      await expectCode(() => completeSignedIn(account.name, account.session.token, started!.reset.id, newKey()), "reset-unavailable");
      const fresh = await service.startSignedInReset(account.session.token, ctx());
      expect((await resetRow(started!.reset.id))?.["aborted_at"]).not.toBeNull();
      await age(fresh.reset.id);
      const next = newKey();
      await completeSignedIn(account.name, account.session.token, fresh.reset.id, next);
      expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([next.identifier]);
    });

    it("fences starts invisible to concurrent email and recovery-factor changes", async () => {
      for (const factor of ["email", "update-email", "recovery-enroll", "recovery-remove"] as const) {
        const account = await verifiedAccount(`factor-${factor}`);
        await enableEmailReset(account);
        const recovery = newKey();
        if (factor === "recovery-remove") {
          const challenge = await service.createChallenge(account.name, "rotation", ctx());
          const signed = messageFor(challenge, "recovery-key-enrollment", keyPrincipal(account.key), `recovery-key:${recovery.publicKeyHex}`);
          await service.enrollRecoveryKey(account.session.token, {
            challengeId: challenge.id,
            recoveryPublicKey: recovery.publicKeyHex,
            authorizerSignature: sign(account.key, signed),
            subjectSignature: sign(recovery, signed),
          }, ctx());
        }
        const challenge = factor === "update-email" ? null : await service.createChallenge(account.name, "rotation", ctx());
        const connections = await openConnections(2);
        const [starter, changer] = [connections[0]!, connections[1]!];
        let started: Awaited<ReturnType<IdentityService["startSignedInReset"]>>;
        let change: Promise<unknown> | undefined;
        try {
          await starter.client.query("BEGIN");
          try {
            started = await starter.service.startSignedInReset(account.session.token, ctx());
            change = (() => {
              if (factor === "email") {
                const signed = messageFor(challenge!, "email-change", keyPrincipal(account.key), "email:moved@example.org");
                return changer.service.changeEmail(account.session.token, {
                  challengeId: challenge!.id,
                  email: "moved@example.org",
                  authorizerSignature: sign(account.key, signed),
                }, ctx());
              }
              if (factor === "update-email") {
                return changer.service.updateAccount(account.accountId, { email: "moved@example.org" }, ctx());
              }
              if (factor === "recovery-enroll") {
                const signed = messageFor(challenge!, "recovery-key-enrollment", keyPrincipal(account.key), `recovery-key:${recovery.publicKeyHex}`);
                return changer.service.enrollRecoveryKey(account.session.token, {
                  challengeId: challenge!.id,
                  recoveryPublicKey: recovery.publicKeyHex,
                  authorizerSignature: sign(account.key, signed),
                  subjectSignature: sign(recovery, signed),
                }, ctx());
              }
              const signed = messageFor(challenge!, "recovery-key-removal", keyPrincipal(account.key), "none");
              return changer.service.removeRecoveryKey(account.session.token, {
                challengeId: challenge!.id,
                authorizerSignature: sign(account.key, signed),
              }, ctx());
            })();
            void change.catch(() => undefined);
            await waitUntilBlocked(changer.pid);
          } finally {
            await starter.client.query("COMMIT");
          }
          await change;
        } finally {
          await closeConnections(connections);
        }
        expect((await resetRow(started!.reset.id))?.["aborted_at"]).toBeNull();
        expect((await service.accountResetStatus(account.session.token)).pendingSignedInReset).toBeNull();
        await age(started!.reset.id);
        await expectCode(() => completeSignedIn(account.name, account.session.token, started!.reset.id, newKey()), "reset-unavailable");
        expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([account.key.identifier]);
        const fresh = await service.startSignedInReset(account.session.token, ctx());
        expect(fresh.reset.id).not.toBe(started!.reset.id);
      }
    }, 60_000);

    it("fences a reset start concurrent with password sign-in", async () => {
      const account = await register(username("login-start-fence"));
      const connections = await openConnections(2);
      const [starter, signer] = [connections[0]!, connections[1]!];
      let started: Awaited<ReturnType<IdentityService["startSignedInReset"]>>;
      let signedIn: Promise<IssuedSession> | undefined;
      try {
        await starter.client.query("BEGIN");
        try {
          started = await starter.service.startSignedInReset(account.session.token, ctx());
          signedIn = login(account.name, account.key, signer.service);
          void signedIn.catch(() => undefined);
          await waitUntilBlocked(signer.pid);
        } finally {
          await starter.client.query("COMMIT");
        }
        expect(await signedIn).toMatchObject({ token: expect.any(String) });
      } finally {
        await closeConnections(connections);
      }
      expect((await service.accountResetStatus(account.session.token)).pendingSignedInReset).toBeNull();
      await age(started!.reset.id);
      await expectCode(() => completeSignedIn(account.name, account.session.token, started!.reset.id, newKey()), "reset-unavailable");
    });

    it("serializes password login and reset completion in both orders, without a surviving old-key session", async () => {
      const connections = await openConnections(3);
      const [holder, signer, completer] = [connections[0]!, connections[1]!, connections[2]!];
      try {
        {
          const account = await register(username("login-before-completion"));
          const started = await service.startSignedInReset(account.session.token, ctx());
          await age(started.reset.id);
          const next = newKey();
          await signer.client.query("BEGIN");
          let pendingCompletion: Promise<unknown> | undefined;
          try {
            const issued = await login(account.name, account.key, signer.service);
            pendingCompletion = completeSignedIn(account.name, account.session.token, started.reset.id, next, { via: completer.service });
            void pendingCompletion.catch(() => undefined);
            await waitUntilBlocked(completer.pid);
            expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([account.key.identifier]);
            await signer.client.query("COMMIT");
            await expectCode(() => pendingCompletion!, "reset-unavailable");
            expect((await resetRow(started.reset.id))?.["aborted_at"]).not.toBeNull();
            expect(await authenticates(issued.token)).toBe(true);
          } finally {
            // Harmless if already committed; avoid leaving a transaction open on assertion failure.
            await signer.client.query("ROLLBACK");
          }
        }

        {
          const account = await register(username("completion-before-login"));
          const started = await service.startSignedInReset(account.session.token, ctx());
          await age(started.reset.id);
          const next = newKey();
          const signedChallenge = await signer.service.createChallenge(account.name, "login", ctx());
          await holder.client.query("BEGIN");
          let pendingLogin: Promise<unknown> | undefined;
          try {
            // FOR SHARE admits completion but blocks login's account lock.
            // Old login SQL inserted a session before this wait, which the
            // completion's snapshot could not see or revoke.
            await holder.client.query(`SELECT 1 FROM ${prefix}_accounts WHERE id = $1::uuid FOR SHARE`, [account.accountId]);
            pendingLogin = signer.service.login({
              username: account.name,
              challengeId: signedChallenge.id,
              signature: sign(account.key, signedChallenge.message),
            }, ctx());
            void pendingLogin.catch(() => undefined);
            await waitUntilBlocked(signer.pid);
            const done = await completeSignedIn(account.name, account.session.token, started.reset.id, next, { via: completer.service });
            expect(done.wallets.map((wallet) => wallet.publicKey)).toEqual([next.identifier]);
          } finally {
            await holder.client.query("COMMIT");
          }
          await expectCode(() => pendingLogin!, "invalid-signature");
          expect((await resetRow(started.reset.id))?.["completed_at"]).not.toBeNull();
          expect((await first.query(`SELECT count(*)::int AS count FROM ${prefix}_sessions WHERE account_id = $1::uuid AND revoked_at IS NULL`, [account.accountId])).rows[0]?.["count"]).toBe(1);
          await login(account.name, next);
        }
      } finally {
        await closeConnections(connections);
      }
    }, 60_000);

    it("answers stale-key when the enrolled key moves while the completion waits for it", async () => {
      const account = await register(username("signed-in-stale"));
      const started = await service.startSignedInReset(account.session.token, ctx());
      await age(started.reset.id);
      const [holder] = await openConnections(1);
      try {
        await holder!.client.query("BEGIN");
        const moved = newKey();
        await holder!.client.query(
          `UPDATE ${prefix}_account_wallets SET address = $2, address_normalized = lower($2), public_key = $2 WHERE account_id = $1::uuid`,
          [account.accountId, moved.identifier],
        );
        const completion = completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { via: otherService });
        void completion.catch(() => undefined);
        await waitUntilBlocked(secondPid);
        await holder!.client.query("COMMIT");
        await expectCode(() => completion, "stale-key");
        expect((await resetRow(started.reset.id))?.["completed_at"]).toBeNull();
      } finally {
        await closeConnections([holder!]);
      }
    });
  });

  describe("verifyReauthentication", () => {
    it("verifies the key over host:<label>, audits account.reauth and changes nothing else", async () => {
      const account = await verifiedAccount("reauth");
      const other = await login(account.name, account.key);
      const before = {
        wallets: await service.listWallets(account.accountId),
        sessions: await service.liveSessionIds(account.session.token),
        status: await service.accountResetStatus(account.session.token),
      };
      const verified = await reauth(account, account.session.token, "example.host-action:v1");
      expect(verified).toEqual({
        accountId: account.accountId,
        sessionId: account.session.session.id,
        label: "example.host-action:v1",
        verifiedAt: expect.any(Date),
      });
      const [audit] = await auditRows(account.accountId, "account.reauth");
      expect(audit?.["metadata"]).toEqual({ label: "example.host-action:v1", sessionId: account.session.session.id });
      expect((audit?.["created_at"] as Date).getTime()).toBe(verified.verifiedAt.getTime());
      expect(await service.listWallets(account.accountId)).toEqual(before.wallets);
      expect(await service.liveSessionIds(account.session.token)).toEqual(before.sessions);
      expect(await service.accountResetStatus(account.session.token)).toEqual(before.status);
      expect(await authenticates(other.token)).toBe(true);
      expect(eventsFor(account.accountId).map((event) => event.action)).not.toContain("account.reauth");
    });

    it("refuses another label's signature, another action's, a spent challenge and a malformed label", async () => {
      const account = await register(username("reauth-refusals"));
      await expectCode(() => reauth(account, account.session.token, "example-label-one", "example-label-two"), "invalid-signature");
      const challenge = await service.createChallenge(account.name, "rotation", ctx());
      const otherAction = messageFor(challenge, "recovery-key-removal", keyPrincipal(account.key), "none");
      await expectCode(
        () =>
          service.verifyReauthentication(
            account.session.token,
            { challengeId: challenge.id, label: "example-label", authorizerSignature: sign(account.key, otherAction) },
            ctx(),
          ),
        "invalid-signature",
      );
      // That challenge is spent now.
      const message = messageFor(challenge, "reauthentication", keyPrincipal(account.key), "host:example-label");
      await expectCode(
        () =>
          service.verifyReauthentication(
            account.session.token,
            { challengeId: challenge.id, label: "example-label", authorizerSignature: sign(account.key, message) },
            ctx(),
          ),
        "challenge-consumed",
      );
      // A malformed label is refused before the challenge is spent.
      const fresh = await service.createChallenge(account.name, "rotation", ctx());
      for (const label of ["ab", "Example", "-label", "a".repeat(81), "label with space", "label\n"]) {
        await expectCode(
          () => service.verifyReauthentication(account.session.token, { challengeId: fresh.id, label, authorizerSignature: "00" }, ctx()),
          "invalid-request",
        );
      }
      const good = messageFor(fresh, "reauthentication", keyPrincipal(account.key), "host:example-label");
      await service.verifyReauthentication(
        account.session.token,
        { challengeId: fresh.id, label: "example-label", authorizerSignature: sign(account.key, good) },
        ctx(),
      );
      // Works without any reset opt-in.
      const plain = createIdentityService(pgDriver(first), config(prefix, { accountSecurity: {} }));
      const third = await plain.createChallenge(account.name, "rotation", ctx());
      const thirdMessage = messageFor(third, "reauthentication", keyPrincipal(account.key), "host:example-label");
      await plain.verifyReauthentication(
        account.session.token,
        { challengeId: third.id, label: "example-label", authorizerSignature: sign(account.key, thirdMessage) },
        ctx(),
      );
    });

    it("counts under the account-change rate limit", async () => {
      const account = await register(username("reauth-rate"));
      const caller = { ipHash: `reauth-rate-${suffix}` };
      for (let attempt = 0; attempt < 10; attempt += 1) {
        await expectCode(
          () => service.verifyReauthentication(account.session.token, { challengeId: crypto.randomUUID(), label: "example-label", authorizerSignature: "00" }, caller),
          "challenge-not-found",
        );
      }
      const limited = await expectCode(
        () => service.verifyReauthentication(account.session.token, { challengeId: crypto.randomUUID(), label: "example-label", authorizerSignature: "00" }, caller),
        "rate-limited",
      );
      expect(limited.details?.["rule"]).toBe("account-change");
    });
  });

  describe("the status rule", () => {
    it("refuses every reset operation of a suspended account, while a start still answers uniformly", async () => {
      const account = await verifiedAccount("suspended");
      await enableEmailReset(account);
      const other = await login(account.name, account.key);
      const pending = await service.startSignedInReset(account.session.token, ctx());
      const emailed = await startEmail(account.name);
      await age(pending.reset.id);
      await suspend(account.accountId);
      const refusals = [
        () => setSetting(account, account.session.token, "email-reset", false),
        () => service.accountResetStatus(account.session.token),
        () => service.startSignedInReset(other.token, ctx()),
        () => service.abortSignedInReset(other.token, ctx()),
        () => completeSignedIn(account.name, account.session.token, pending.reset.id, newKey()),
        () => completeEmail(account.name, emailed.resetId, emailed.delivery!.code, newKey()),
        () => reauth(account, account.session.token, "example-label"),
      ];
      for (const run of refusals) {
        const error = await expectCode(run, "invalid-signature");
        expect(error.status).toBe(401);
      }
      const start = await startEmail(account.name);
      expect(start.delivery).toBeNull();
      expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([account.key.identifier]);
    });
  });

  describe("pruneExpired", () => {
    it("deletes reset rows a day after they expire", async () => {
      const account = await verifiedAccount("prune");
      await enableEmailReset(account);
      const issued = await startEmail(account.name);
      await service.pruneExpired({ now: new Date(issued.expiresAt.getTime() + 60_000) });
      expect(await resetRow(issued.resetId)).toBeDefined();
      const dayAfter = await service.pruneExpired({ now: new Date(issued.expiresAt.getTime() + 86_400_000 + 1) });
      expect(dayAfter.accountResets).toBeGreaterThanOrEqual(1);
      expect(await resetRow(issued.resetId)).toBeUndefined();
    });
  });

  describe("lock order", () => {
    type Variant = "signed-in" | "email";

    /** An account with a reset ready to complete, and `others` more sessions. */
    async function prepared(variant: Variant, label: string, others: number) {
      const account = await verifiedAccount(label);
      await enableEmailReset(account);
      const sessions: IssuedSession[] = [];
      for (let index = 0; index < others; index += 1) sessions.push(await login(account.name, account.key));
      let complete: (via: IdentityService) => Promise<readonly string[]>;
      if (variant === "signed-in") {
        const started = await service.startSignedInReset(account.session.token, ctx());
        await age(started.reset.id);
        complete = (via) =>
          completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { via }).then((result) => result.revokedSessionIds);
      } else {
        const issued = await startEmail(account.name);
        complete = (via) =>
          completeEmail(account.name, issued.resetId, issued.delivery!.code, newKey(), { via }).then((result) => result.revokedSessionIds);
      }
      return { account, sessions, complete };
    }

    it("completions hold the account FOR SHARE, lock the key and the reset first, then sessions in id order, never the caller's", async () => {
      const pair = await openConnections(2);
      const [holder, actor] = [pair[0]!, pair[1]!];
      try {
        for (const variant of ["signed-in", "email"] as const) {
          const { account, sessions, complete } = await prepared(variant, `lock-${variant}`, 15);
          const targets = (variant === "signed-in" ? sessions : [account.session, ...sessions]).map((s) => s.session.id).sort();
          const middle = Math.floor(targets.length / 2);
          const blocker = targets[middle]!;
          await holder.client.query("BEGIN");
          let change: Promise<readonly string[]> | undefined;
          try {
            await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [blocker]);
            change = complete(actor.service);
            void change.catch(() => undefined);
            await waitUntilBlocked(actor.pid);

            const unlocked = await first.query(
              `SELECT id FROM ${prefix}_sessions WHERE account_id = $1::uuid FOR SHARE SKIP LOCKED`,
              [account.accountId],
            );
            const unlockedIds = new Set(unlocked.rows.map((row) => String(row["id"])));
            const all = [account.session, ...sessions].map((s) => s.session.id);
            const held = all.filter((id) => id !== blocker && !unlockedIds.has(id)).sort();
            expect(held).toEqual(targets.slice(0, middle));
            if (variant === "signed-in") expect(unlockedIds.has(account.session.session.id)).toBe(true);
            await first.query(`SELECT 1 FROM ${prefix}_accounts WHERE id = $1::uuid FOR KEY SHARE NOWAIT`, [account.accountId]);
            await expect(
              first.query(`SELECT 1 FROM ${prefix}_accounts WHERE id = $1::uuid FOR NO KEY UPDATE NOWAIT`, [account.accountId]),
            ).rejects.toMatchObject({ code: "55P03" });
            await expect(
              first.query(`SELECT 1 FROM ${prefix}_account_wallets WHERE account_id = $1::uuid FOR KEY SHARE NOWAIT`, [account.accountId]),
            ).rejects.toMatchObject({ code: "55P03" });
            // The reset being completed is locked before any session.
            const lockedResets = await first.query(
              `SELECT id FROM ${prefix}_account_resets WHERE account_id = $1::uuid
                  AND completed_at IS NULL AND aborted_at IS NULL FOR KEY SHARE SKIP LOCKED`,
              [account.accountId],
            );
            expect(lockedResets.rows).toHaveLength(0);
          } finally {
            await holder.client.query("COMMIT");
          }
          expect([...(await change!)].sort()).toEqual(targets);
        }
      } finally {
        await closeConnections(pair);
      }
    }, 60_000);

    it("completes alongside a revoke-others that holds sessions it needs (the cycle FOR UPDATE would close)", async () => {
      // As accountChanges.integration.test.ts drives it for a rotation: a
      // holder locks session X; revoke-others (another session, B) locks the
      // sessions below X and waits on X; the completion takes the account,
      // the key and the reset, then waits on a session revoke-others holds;
      // the holder commits and revoke-others' audit insert takes FOR KEY
      // SHARE on the account, which the completion's FOR SHARE admits.
      const trio = await openConnections(3);
      const [holder, revoker, actor] = [trio[0]!, trio[1]!, trio[2]!];
      try {
        for (const variant of ["signed-in", "email"] as const) {
          const { sessions, complete } = await prepared(variant, `cycle-${variant}`, 12);
          const sorted = [...sessions].sort((x, y) => (x.session.id < y.session.id ? -1 : 1));
          const b = sorted[0]!;
          const blocker = sorted[Math.floor(sorted.length / 2)]!.session.id;
          await holder.client.query("BEGIN");
          let revocation: Promise<readonly string[]> | undefined;
          let change: Promise<readonly string[]> | undefined;
          try {
            await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [blocker]);
            revocation = revoker.service.revokeOtherSessions(b.token).then((result) => result.revokedSessionIds);
            void revocation.catch(() => undefined);
            await waitUntilBlocked(revoker.pid);
            change = complete(actor.service);
            void change.catch(() => undefined);
            await waitUntilBlocked(actor.pid);
          } finally {
            await holder.client.query("COMMIT");
          }
          const [revoked, changed] = await Promise.all([revocation!, change!]);
          expect(new Set([...revoked, ...changed]).size).toBe(revoked.length + changed.length);
          expect(changed).toContain(b.session.id);
          expect(await authenticates(b.token)).toBe(false);
        }
      } finally {
        await closeConnections(trio);
      }
    }, 60_000);

    it("serializes a rotation and a completion of one account on the enrolled key, in either order, without deadlock", async () => {
      const trio = await openConnections(3);
      const [holder, rotator, actor] = [trio[0]!, trio[1]!, trio[2]!];
      try {
        for (const first_ of ["rotation", "completion"] as const) {
          const account = await register(username(`rotate-vs-${first_}`));
          const rotating = await login(account.name, account.key);
          const others: IssuedSession[] = [];
          for (let index = 0; index < 6; index += 1) others.push(await login(account.name, account.key));
          const started = await service.startSignedInReset(account.session.token, ctx());
          await age(started.reset.id);
          const blocker = [...others].map((s) => s.session.id).sort()[3]!;
          const rotate = async (): Promise<unknown> => {
            const challenge = await rotator.service.createChallenge(account.name, "rotation", ctx());
            const next = newKey();
            const message = messageFor(challenge, "sign-in-key-rotation", keyPrincipal(account.key), keyPrincipal(next));
            return rotator.service.rotateSignInKey(
              rotating.token,
              { challengeId: challenge.id, newKey: enrolled(next), authorizerSignature: sign(account.key, message), subjectSignature: sign(next, message) },
              ctx(),
            );
          };
          const completion = (): Promise<unknown> =>
            completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { via: actor.service });

          await holder.client.query("BEGIN");
          const outcomes: Promise<PromiseSettledResult<unknown>>[] = [];
          try {
            await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [blocker]);
            const leader = first_ === "rotation" ? rotate : completion;
            const follower = first_ === "rotation" ? completion : rotate;
            const leaderPid = first_ === "rotation" ? rotator.pid : actor.pid;
            const followerPid = first_ === "rotation" ? actor.pid : rotator.pid;
            outcomes.push(leader().then((value) => ({ status: "fulfilled", value }) as const, (reason: unknown) => ({ status: "rejected", reason }) as const));
            await waitUntilBlocked(leaderPid);
            outcomes.push(follower().then((value) => ({ status: "fulfilled", value }) as const, (reason: unknown) => ({ status: "rejected", reason }) as const));
            await waitUntilBlocked(followerPid);
          } finally {
            await holder.client.query("COMMIT");
          }
          const [leading, following] = await Promise.all(outcomes);
          // The leader holds the key first and commits; the follower, which
          // waited on the key, finds it moved (or its session revoked).
          expect(leading!.status).toBe("fulfilled");
          expect(following!.status).toBe("rejected");
          const reason = (following as PromiseRejectedResult).reason as IdentityError;
          expect(reason).toBeInstanceOf(IdentityError);
          expect(["stale-key", "session-not-found"]).toContain(reason.code);
          expect(reason.code).not.toBe("internal-error");
        }
      } finally {
        await closeConnections(trio);
      }
    }, 60_000);

    it("lets an abort that waits on a completing reset find it completed, and a completion that waits on an abort find it gone", async () => {
      const trio = await openConnections(3);
      const [holder, aborter, actor] = [trio[0]!, trio[1]!, trio[2]!];
      try {
        // The completion first: it holds the reset row while it waits on a session.
        {
          const account = await register(username("abort-vs-complete"));
          const others: IssuedSession[] = [];
          for (let index = 0; index < 5; index += 1) others.push(await login(account.name, account.key));
          const started = await service.startSignedInReset(account.session.token, ctx());
          await age(started.reset.id);
          const sorted = others.map((s) => s.session.id).sort();
          await holder.client.query("BEGIN");
          let change: Promise<unknown> | undefined;
          let abort: Promise<{ aborted: boolean }> | undefined;
          try {
            await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [sorted[2]!]);
            change = completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { via: actor.service });
            void change.catch(() => undefined);
            await waitUntilBlocked(actor.pid);
            const aborting = others.find((s) => s.session.id === sorted[4])!;
            abort = aborter.service.abortSignedInReset(aborting.token, ctx());
            void abort.catch(() => undefined);
            await waitUntilBlocked(aborter.pid);
          } finally {
            await holder.client.query("COMMIT");
          }
          await change;
          // The abort waited on the reset row (behind the completion), then
          // its session was revoked or the reset was completed: either way it
          // aborts nothing.
          const outcome = await abort!.then((value) => value, (error: unknown) => error);
          if (outcome instanceof IdentityError) {
            expect(outcome.code).toBe("session-not-found");
          } else {
            expect(outcome).toEqual({ aborted: false });
          }
          expect((await resetRow(started.reset.id))?.["completed_at"]).not.toBeNull();
        }
        // The abort first, held open: the completion waits on the reset row and then finds it aborted.
        {
          const account = await register(username("complete-vs-abort"));
          const started = await service.startSignedInReset(account.session.token, ctx());
          await age(started.reset.id);
          await holder.client.query("BEGIN");
          let change: Promise<unknown> | undefined;
          try {
            await holder.client.query(`UPDATE ${prefix}_account_resets SET aborted_at = now() WHERE id = $1::uuid`, [started.reset.id]);
            change = completeSignedIn(account.name, account.session.token, started.reset.id, newKey(), { via: actor.service });
            void change.catch(() => undefined);
            await waitUntilBlocked(actor.pid);
          } finally {
            await holder.client.query("COMMIT");
          }
          await expectCode(() => change!, "reset-unavailable");
          expect((await service.listWallets(account.accountId)).map((wallet) => wallet.publicKey)).toEqual([account.key.identifier]);
        }
      } finally {
        await closeConnections(trio);
      }
    }, 60_000);

    it("lets a rotation lock the pending reset after the key and before the sessions, and abort it", async () => {
      const pair = await openConnections(2);
      const [holder, actor] = [pair[0]!, pair[1]!];
      try {
        const account = await register(username("lock-rotation"));
        const others: IssuedSession[] = [];
        for (let index = 0; index < 8; index += 1) others.push(await login(account.name, account.key));
        const started = await service.startSignedInReset(account.session.token, ctx());
        const targets = others.map((s) => s.session.id).sort();
        const middle = Math.floor(targets.length / 2);
        const next = newKey();
        await holder.client.query("BEGIN");
        let change: Promise<Awaited<ReturnType<IdentityService["rotateSignInKey"]>>> | undefined;
        try {
          await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [targets[middle]]);
          change = rotate(account, account.session.token, next, { via: actor.service });
          void change.catch(() => undefined);
          await waitUntilBlocked(actor.pid);
          // The key and the reset are held while the rotation waits on a session.
          await expect(
            first.query(`SELECT 1 FROM ${prefix}_account_wallets WHERE account_id = $1::uuid FOR KEY SHARE NOWAIT`, [account.accountId]),
          ).rejects.toMatchObject({ code: "55P03" });
          await expect(
            first.query(`SELECT 1 FROM ${prefix}_account_resets WHERE id = $1::uuid FOR SHARE NOWAIT`, [started.reset.id]),
          ).rejects.toMatchObject({ code: "55P03" });
          await first.query(`SELECT 1 FROM ${prefix}_accounts WHERE id = $1::uuid FOR KEY SHARE NOWAIT`, [account.accountId]);
        } finally {
          await holder.client.query("COMMIT");
        }
        expect([...(await change!).revokedSessionIds].sort()).toEqual(targets);
        expect((await resetRow(started.reset.id))?.["aborted_at"]).not.toBeNull();
      } finally {
        await closeConnections(pair);
      }
    }, 60_000);

    it("leaves a lapsed reset as a completion or an abort that held it left it, when a new start waits on it", async () => {
      for (const outcome of ["completed", "aborted"] as const) {
        const account = await register(username(`lapsed-${outcome}`));
        const other = await login(account.name, account.key);
        const third = await login(account.name, account.key);
        const first_ = await service.startSignedInReset(account.session.token, ctx());
        // Its session revoked: the next start sees it lapsed and closes it.
        expect(await service.revokeSessionById(other.token, account.session.session.id, ctx())).toEqual({ revoked: true });
        const [holder] = await openConnections(1);
        let closedAt: unknown;
        try {
          await holder!.client.query("BEGIN");
          let start: Promise<Awaited<ReturnType<IdentityService["startSignedInReset"]>>> | undefined;
          try {
            // A completion (or an abort) in flight holds the row and closes it.
            const closed = await holder!.client.query(
              `UPDATE ${prefix}_account_resets
                  SET ${outcome === "completed" ? "completed_at" : "aborted_at"} = now() - interval '1 hour'
                WHERE id = $1::uuid
                RETURNING ${outcome === "completed" ? "completed_at" : "aborted_at"} AS closed_at`,
              [first_.reset.id],
            );
            closedAt = closed.rows[0]?.["closed_at"];
            start = otherService.startSignedInReset(third.token, ctx());
            void start.catch(() => undefined);
            await waitUntilBlocked(secondPid);
          } finally {
            await holder!.client.query("COMMIT");
          }
          const next = await start!;
          expect(next.reset.initiatedByCaller).toBe(true);
        } finally {
          await closeConnections([holder!]);
        }
        const row = await resetRow(first_.reset.id);
        if (outcome === "completed") {
          expect((row?.["completed_at"] as Date).getTime()).toBe((closedAt as Date).getTime());
          expect(row?.["aborted_at"]).toBeNull();
        } else {
          expect((row?.["aborted_at"] as Date).getTime()).toBe((closedAt as Date).getTime());
        }
        // The new start closed nothing: the holder had already closed it.
        expect((await auditRows(account.accountId, "account.signed-in-reset.start")).at(-1)?.["metadata"]).toMatchObject({
          closedResets: 0,
        });
      }
    }, 60_000);

    it("never deadlocks with revoke-others, revoke-all, authenticate, login, abort and rotation traffic", async () => {
      const lanes = 9;
      const connections = await openConnections(lanes);
      const legal: ReadonlySet<string> = new Set([
        "session-not-found",
        "stale-key",
        "invalid-signature",
        "reset-unavailable",
        "reset-pending",
        "email-verification-failed",
      ]);
      const unexpected: unknown[] = [];
      const settle = async (work: Promise<unknown>): Promise<void> => {
        try {
          await work;
        } catch (error) {
          if (!(error instanceof IdentityError && legal.has(error.code))) unexpected.push(error);
        }
      };
      try {
        for (let round = 0; round < 16; round += 1) {
          const viaEmail = round % 2 === 1;
          const account = await verifiedAccount(`stress-${String(round)}`);
          await enableEmailReset(account);
          const sessions: IssuedSession[] = [account.session];
          while (sessions.length < 16) {
            sessions.push(...(await Promise.all(connections.map((connection) => login(account.name, account.key, connection.service)))));
          }
          const next = newKey();
          let change: Promise<unknown>;
          if (viaEmail) {
            const issued = await startEmail(account.name);
            change = completeEmail(account.name, issued.resetId, issued.delivery!.code, next, { via: connections[0]!.service });
          } else {
            const started = await service.startSignedInReset(account.session.token, ctx());
            await age(started.reset.id);
            change = completeSignedIn(account.name, account.session.token, started.reset.id, next, { via: connections[0]!.service });
          }
          const work: Promise<unknown>[] = [change];
          for (let index = 1; index <= 3; index += 1) {
            work.push(connections[index]!.service.revokeOtherSessions(sessions[index]!.token));
          }
          work.push(connections[4]!.service.revokeAllSessions(account.accountId));
          for (const lane of [5, 6]) {
            work.push(
              (async () => {
                for (let index = 4 + lane - 5; index < sessions.length; index += 2) {
                  await settle(connections[lane]!.service.authenticate(sessions[index]!.token));
                }
              })(),
            );
          }
          work.push(login(account.name, account.key, connections[7]!.service));
          work.push(connections[8]!.service.abortSignedInReset(sessions[8]!.token, ctx()));
          work.push(
            (async () => {
              const challenge = await connections[8]!.service.createChallenge(account.name, "rotation", ctx());
              const rotated = newKey();
              const message = messageFor(challenge, "sign-in-key-rotation", keyPrincipal(account.key), keyPrincipal(rotated));
              return connections[8]!.service.rotateSignInKey(
                sessions[9]!.token,
                { challengeId: challenge.id, newKey: enrolled(rotated), authorizerSignature: sign(account.key, message), subjectSignature: sign(rotated, message) },
                ctx(),
              );
            })(),
          );
          await Promise.all(work.map(settle));
          expect(unexpected).toEqual([]);
          expect(await service.listWallets(account.accountId)).toHaveLength(1);
        }
      } finally {
        await closeConnections(connections);
      }
    }, 240_000);
  });
});
