import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { normalizeUsername, signInEd25519ExternalSalt } from "../../src/index.js";
import { IdentityError } from "../../src/server/errors.js";
import { applyMigrationStatement, identityMigrations } from "../../src/server/migrations.js";
import {
  createIdentityRouter,
  createIdentityService,
  pgDriver,
  type IdentityService,
  type IdentityServiceConfig,
  type IssuedSession,
  type RequestContext,
  type SqlDriver,
  type SqlRow,
} from "../../src/server/index.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * Session management (migration 6, the client label, the optional client
 * hashes, listing and revocation) over real PostgreSQL. Gated on
 * W2SC_TEST_DATABASE_URL like the other server suites.
 *
 * The enrolled keys are plain Ed25519 keys under the sign-in profile's codec,
 * so no test pays for scrypt: the service verifies signatures against the
 * enrolled public key and never sees how a key was made.
 */
const url = process.env["W2SC_TEST_DATABASE_URL"];

type Client = {
  connect(): Promise<void>;
  end(): Promise<void>;
  query(text: string, parameters?: readonly unknown[]): Promise<{ rows: SqlRow[] }>;
};

const encoder = new TextEncoder();
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
const prefix = `wsm_${suffix}`;
const concurrencyPrefix = `wsc_${suffix}`;
const serviceProfileId = `w2sc-sessions-${suffix}`;
const tables = [
  "account_resets", "account_recoveries", "account_recovery_keys", "wallet_setups", "wallet_policy", "audit_events", "rate_limits", "email_verifications",
  "sessions", "auth_challenges", "account_wallets", "accounts", "service_profile_bootstrap",
  "service_profiles", "schema_migrations",
];

const config = (tablePrefix: string): IdentityServiceConfig => ({
  serviceProfileId,
  profile: signInEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-testnet",
  tablePrefix,
  sessionTtlSeconds: 3_600,
});

type Key = Readonly<{ secret: Uint8Array; identifier: string }>;

function newKey(): Key {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  return Object.freeze({ secret, identifier: `S_${bytesToHex(ed25519.getPublicKey(secret))}` });
}

function sign(key: Key, message: string): string {
  return bytesToHex(ed25519.sign(encoder.encode(message), key.secret));
}

const listedKeys = ["clientLabel", "current", "expiresAt", "id", "issuedAt", "lastSeenAt"];

let PgClient: new (options: { connectionString: string }) => Client;
let first: Client;
let second: Client;
let sql: SqlDriver;
let service: IdentityService;

type Connection = Readonly<{ client: Client; service: IdentityService; pid: number }>;

/** Extra connections, each with its own service, for statements that must really overlap. */
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

/** Resolves once the backend `pid` is blocked waiting for a lock. */
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

/** A unique username per call, so rate-limit buckets never carry across tests. */
function username(label: string): string {
  return `${label}-${crypto.randomUUID().slice(0, 8)}@example.com`;
}

async function register(
  name: string,
  context?: RequestContext,
  via: IdentityService = service,
): Promise<Readonly<{ key: Key; accountId: string; session: IssuedSession }>> {
  const key = newKey();
  const challenge = await via.createChallenge(name, "registration", context);
  const registered = await via.register(
    { username: name, address: key.identifier, publicKey: key.identifier, challengeId: challenge.id, signature: sign(key, challenge.message) },
    context,
  );
  return { key, accountId: registered.account.id, session: registered.session };
}

async function login(
  name: string,
  key: Key,
  context?: RequestContext,
  via: IdentityService = service,
): Promise<IssuedSession> {
  const challenge = await via.createChallenge(name, "login", context);
  const result = await via.login(
    { username: name, challengeId: challenge.id, signature: sign(key, challenge.message) },
    context,
  );
  return result.session;
}

async function sessionRow(sessionId: string): Promise<SqlRow | undefined> {
  return (
    await first.query(
      `SELECT ip_hash, user_agent_hash, client_label, revoked_at FROM ${prefix}_sessions WHERE id = $1::uuid`,
      [sessionId],
    )
  ).rows[0];
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

async function auditRows(accountId: string, action: string): Promise<readonly SqlRow[]> {
  return (
    await first.query(
      `SELECT metadata FROM ${prefix}_audit_events WHERE account_id = $1::uuid AND action = $2 ORDER BY created_at`,
      [accountId, action],
    )
  ).rows;
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

describe.skipIf(!url)("session management on PostgreSQL", () => {
  beforeAll(async () => {
    const moduleName: string = "pg";
    const pg = (await import(moduleName)) as { Client: new (options: { connectionString: string }) => Client };
    PgClient = pg.Client;
    first = new PgClient({ connectionString: url! });
    second = new PgClient({ connectionString: url! });
    await Promise.all([first.connect(), second.connect()]);
    sql = pgDriver(first);
    service = createIdentityService(sql, config(prefix));
    expect(await service.migrate()).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  }, 60_000);

  afterAll(async () => {
    if (!first) return;
    for (const tablePrefix of [prefix, concurrencyPrefix]) {
      await first.query(`DROP TABLE IF EXISTS ${tables.map((t) => `${tablePrefix}_${t}`).join(", ")} CASCADE`);
      await first.query(`DROP FUNCTION IF EXISTS ${tablePrefix}_reject_immutable_mutation() CASCADE`);
    }
    await Promise.all([first.end(), second.end()]);
  }, 60_000);

  describe("migration 6", () => {
    async function labelColumnAndConstraints(): Promise<Readonly<{ columns: number; named: number; checks: number }>> {
      const row = (
        await first.query(
          `SELECT
             (SELECT count(*)::int FROM pg_attribute
               WHERE attrelid = to_regclass($1) AND attname = 'client_label' AND NOT attisdropped) AS columns,
             (SELECT count(*)::int FROM pg_constraint
               WHERE conrelid = to_regclass($1) AND conname = $2) AS named,
             (SELECT count(*)::int FROM pg_constraint
               WHERE conrelid = to_regclass($1) AND contype = 'c'
                 AND pg_get_constraintdef(oid) LIKE '%client_label%') AS checks`,
          [`${concurrencyPrefix}_sessions`, `${concurrencyPrefix}_sessions_client_label`],
        )
      ).rows[0]!;
      return { columns: Number(row["columns"]), named: Number(row["named"]), checks: Number(row["checks"]) };
    }

    it("leaves one column and one constraint when run twice and from two concurrent runners", async () => {
      const one = createIdentityService(pgDriver(first), config(concurrencyPrefix));
      const two = createIdentityService(pgDriver(second), config(concurrencyPrefix));
      await one.migrate();
      const exactlyOne = { columns: 1, named: 1, checks: 1 };
      expect(await labelColumnAndConstraints()).toEqual(exactlyOne);

      const statement = identityMigrations(one.config).find((m) => m.version === 6)!.statements[0]!;

      // Re-run in place, as a runner does when it applied the statement but
      // died before recording the version.
      await applyMigrationStatement(pgDriver(first), statement);
      await applyMigrationStatement(pgDriver(first), statement);
      expect(await labelColumnAndConstraints()).toEqual(exactlyOne);

      // From scratch, two connections at once, several times: the loser waits
      // on the table lock and then skips the column and its constraint together.
      for (let round = 0; round < 5; round += 1) {
        await first.query(`ALTER TABLE ${concurrencyPrefix}_sessions DROP COLUMN client_label`);
        expect((await labelColumnAndConstraints()).columns).toBe(0);
        await Promise.all([
          applyMigrationStatement(pgDriver(first), statement),
          applyMigrationStatement(pgDriver(second), statement),
        ]);
        expect(await labelColumnAndConstraints()).toEqual(exactlyOne);
      }

      // The whole runner, twice at once, with version 6 not yet recorded.
      await first.query(`ALTER TABLE ${concurrencyPrefix}_sessions DROP COLUMN client_label`);
      await first.query(`DELETE FROM ${concurrencyPrefix}_schema_migrations WHERE version = 6`);
      const [ranOne, ranTwo] = await Promise.all([one.migrate(), two.migrate()]);
      expect([...ranOne, ...ranTwo]).toContain(6);
      expect(await labelColumnAndConstraints()).toEqual(exactlyOne);
      const recorded = await first.query(
        `SELECT name FROM ${concurrencyPrefix}_schema_migrations WHERE version = 6`,
      );
      expect(recorded.rows).toEqual([{ name: "session-client-labels" }]);
      expect(await one.migrate()).toEqual([]);
    }, 60_000);

    it("adds no index to the sessions table", async () => {
      const indexes = await first.query(
        `SELECT indexname FROM pg_indexes WHERE tablename = $1 ORDER BY indexname`,
        [`${prefix}_sessions`],
      );
      expect(indexes.rows.map((row) => row["indexname"])).toEqual([
        `${prefix}_sessions_account_idx`,
        `${prefix}_sessions_expires_idx`,
        `${prefix}_sessions_pkey`,
        `${prefix}_sessions_token_hash_key`,
      ]);
    });
  });

  describe("listSessions", () => {
    it("lists the account's live sessions with display fields only and flags the caller", async () => {
      const name = username("list");
      const { key, accountId, session: s0 } = await register(name, {
        clientLabel: "Firefox on macOS", ipHash: "ip-list", userAgentHash: "ua-list",
      });
      const s1 = await login(name, key, { clientLabel: "Safari on iOS" });
      const s2 = await login(name, key);
      const revokedLater = await login(name, key, { clientLabel: "Edge on Windows" });
      await service.revokeSession(revokedLater.token);
      // Another account's session must never appear.
      await register(username("list-other"), { clientLabel: "Chrome on Linux" });

      const listed = await service.listSessions(s1.token);
      expect(listed).toHaveLength(3);
      for (const entry of listed) {
        expect(Object.keys(entry).sort()).toEqual(listedKeys);
      }
      expect(listed.filter((entry) => entry.current).map((entry) => entry.id)).toEqual([s1.session.id]);
      expect(new Set(listed.map((entry) => entry.id))).toEqual(
        new Set([s0.session.id, s1.session.id, s2.session.id]),
      );
      const byId = new Map(listed.map((entry) => [entry.id, entry]));
      expect(byId.get(s0.session.id)?.clientLabel).toBe("Firefox on macOS");
      expect(byId.get(s1.session.id)?.clientLabel).toBe("Safari on iOS");
      expect(byId.get(s2.session.id)?.clientLabel).toBeNull();
      expect(byId.get(s0.session.id)?.issuedAt).toEqual(s0.session.issuedAt);
      expect(byId.get(s0.session.id)?.expiresAt).toEqual(s0.session.expiresAt);

      // Most recently active first; the call itself is activity, so the caller leads.
      const seen = listed.map((entry) => entry.lastSeenAt.getTime());
      expect([...seen].sort((a, b) => b - a)).toEqual(seen);
      expect(listed[0]?.id).toBe(s1.session.id);
      expect((await service.authenticate(s1.token)).session.lastSeenAt.getTime()).toBeGreaterThanOrEqual(
        listed[0]!.lastSeenAt.getTime(),
      );

      // Another session's view flags that session instead.
      const fromS2 = await service.listSessions(s2.token);
      expect(fromS2.filter((entry) => entry.current).map((entry) => entry.id)).toEqual([s2.session.id]);

      expect(JSON.stringify(listed)).not.toMatch(/ip-list|ua-list|token|hash/u);
      expect(accountId).toMatch(/^[0-9a-f-]{36}$/u);
    });

    it("refuses an unknown, revoked or expired token the way authenticate does", async () => {
      const name = username("list-refuse");
      const { key } = await register(name);
      const dead = await login(name, key);
      await service.revokeSession(dead.token);
      expect((await rejection(() => service.listSessions("not-a-token"))).code).toBe("session-not-found");
      expect((await rejection(() => service.listSessions(""))).code).toBe("session-not-found");
      expect((await rejection(() => service.listSessions(dead.token))).code).toBe("session-not-found");
      const live = await login(name, key);
      const later = { now: new Date(live.session.expiresAt.getTime() + 1_000) };
      expect((await rejection(() => service.listSessions(live.token, later))).code).toBe("session-expired");
      expect((await rejection(() => service.liveSessionIds(live.token, later))).code).toBe("session-expired");
    });
  });

  describe("liveSessionIds", () => {
    it("returns every live session, past the 50 rows listSessions shows", async () => {
      const name = username("bulk");
      const { key, session: oldest } = await register(name);
      const issued: IssuedSession[] = [oldest];
      // A distinct address hash per login keeps each under its own rate limit.
      for (let index = 0; index < 55; index += 1) {
        issued.push(await login(name, key, { ipHash: `bulk-${String(index)}-${suffix}` }));
      }
      const ids = new Set(issued.map((entry) => entry.session.id));
      expect(ids.size).toBe(56);

      const live = await service.liveSessionIds(issued[10]!.token);
      expect(live).toHaveLength(56);
      expect(new Set(live)).toEqual(ids);

      const listed = await service.listSessions(issued[10]!.token);
      expect(listed).toHaveLength(50);
      expect(listed.filter((entry) => entry.current).map((entry) => entry.id)).toEqual([issued[10]!.session.id]);

      // The caller stays on the page even when its activity is the oldest:
      // here the clock is set back, so its slid last_seen_at sorts last.
      const stale = await service.listSessions(oldest.token, { now: new Date(oldest.session.issuedAt.getTime() + 1) });
      expect(stale).toHaveLength(50);
      expect(stale.filter((entry) => entry.current).map((entry) => entry.id)).toEqual([oldest.session.id]);
      expect(stale[stale.length - 1]?.id).toBe(oldest.session.id);

      await service.revokeSessionById(oldest.token, issued[20]!.session.id);
      const afterRevoke = await service.liveSessionIds(oldest.token);
      expect(afterRevoke).toHaveLength(55);
      expect(afterRevoke).not.toContain(issued[20]!.session.id);
    }, 60_000);
  });

  describe("revokeSessionById", () => {
    it("revokes one other session and leaves the rest", async () => {
      const name = username("revoke-one");
      const { key, accountId, session: s0 } = await register(name);
      const s1 = await login(name, key);
      const s2 = await login(name, key);

      expect(await service.revokeSessionById(s0.token, s1.session.id)).toEqual({ revoked: true });
      expect(await authenticates(s1.token)).toBe(false);
      expect(await authenticates(s0.token)).toBe(true);
      expect(await authenticates(s2.token)).toBe(true);
      expect((await sessionRow(s1.session.id))?.["revoked_at"]).not.toBeNull();

      // Already revoked: the same uniform answer, and nothing is audited twice.
      expect(await service.revokeSessionById(s0.token, s1.session.id)).toEqual({ revoked: false });
      // The acting session's id, so the security events can show its label.
      expect((await auditRows(accountId, "session.revoke")).map((row) => row["metadata"])).toEqual([
        { scope: "other", sessionId: s0.session.id },
      ]);

      // Ids are matched case-insensitively, like every other id the service takes.
      expect(await service.revokeSessionById(s0.token, s2.session.id.toUpperCase())).toEqual({ revoked: true });
      expect(await authenticates(s2.token)).toBe(false);
      expect(await authenticates(s0.token)).toBe(true);
    });

    it("refuses the caller's own session and a malformed id, changing nothing", async () => {
      const name = username("revoke-self");
      const { key, accountId, session: s0 } = await register(name);
      const s1 = await login(name, key);
      const own = await rejection(() => service.revokeSessionById(s0.token, s0.session.id));
      expect(own.code).toBe("invalid-request");
      for (const malformed of ["", "current", "not-a-uuid", `${s1.session.id}x`, 42 as unknown as string]) {
        expect((await rejection(() => service.revokeSessionById(s0.token, malformed))).code).toBe("invalid-request");
      }
      expect(await authenticates(s0.token)).toBe(true);
      expect(await authenticates(s1.token)).toBe(true);
      expect(await auditRows(accountId, "session.revoke")).toEqual([]);
      expect((await rejection(() => service.revokeSessionById("not-a-token", s1.session.id))).code).toBe("session-not-found");
      expect(await authenticates(s1.token)).toBe(true);
    });

    it("answers another account's session id exactly like an unknown one, and revokes nothing", async () => {
      const alice = await register(username("alice"));
      const bobName = username("bob");
      const bob = await register(bobName);

      expect(await service.revokeSessionById(alice.session.token, bob.session.session.id)).toEqual({ revoked: false });
      expect(await service.revokeSessionById(alice.session.token, crypto.randomUUID())).toEqual({ revoked: false });
      expect(await authenticates(bob.session.token)).toBe(true);
      expect(await auditRows(alice.accountId, "session.revoke")).toEqual([]);
      expect(await auditRows(bob.accountId, "session.revoke")).toEqual([]);

      // And over HTTP the two answers are byte-identical.
      const router = createIdentityRouter(service, { useCookies: false, accountSecurityRoutes: true });
      const revokeOver = (id: string) =>
        router(new Request(`https://example.test/identity/sessions/${id}`, {
          method: "DELETE", headers: { Authorization: `Bearer ${alice.session.token}` },
        }));
      const foreign = await revokeOver(bob.session.session.id);
      const unknown = await revokeOver(crypto.randomUUID());
      expect(foreign.status).toBe(200);
      expect(unknown.status).toBe(200);
      expect(await foreign.text()).toBe(await unknown.text());
      expect(await authenticates(bob.session.token)).toBe(true);
    });
  });

  describe("revokeOtherSessions", () => {
    it("revokes every other session of the account and keeps the caller's", async () => {
      const name = username("revoke-others");
      const { key, accountId, session: s0 } = await register(name);
      const s1 = await login(name, key);
      const s2 = await login(name, key);
      const s3 = await login(name, key);
      const bystander = await register(username("bystander"));

      const result = await service.revokeOtherSessions(s1.token);
      expect([...result.revokedSessionIds].sort()).toEqual(
        [s0.session.id, s2.session.id, s3.session.id].sort(),
      );
      expect(await authenticates(s1.token)).toBe(true);
      for (const other of [s0, s2, s3]) {
        expect(await authenticates(other.token)).toBe(false);
      }
      expect(await authenticates(bystander.session.token)).toBe(true);

      expect(await service.revokeOtherSessions(s1.token)).toEqual({ revokedSessionIds: [] });
      expect((await auditRows(accountId, "session.revoke-others")).map((row) => row["metadata"])).toEqual([
        { scope: "others", revoked: 3, sessionId: s1.session.id },
        { scope: "others", revoked: 0, sessionId: s1.session.id },
      ]);
      expect(await service.liveSessionIds(s1.token)).toEqual([s1.session.id]);
      expect((await rejection(() => service.revokeOtherSessions(s0.token))).code).toBe("session-not-found");
    });

    it("lets two sessions revoke each other at once without a deadlock", async () => {
      // Two connections, so the statements really overlap. Neither statement
      // ever locks the caller's own row.
      const otherConnection = createIdentityService(pgDriver(second), config(prefix));
      // Two legal outcomes: the statements overlap and both callers act on a
      // snapshot in which the other was live, or one commits first and the
      // other finds its own session already revoked (`session-not-found`).
      // Anything else, a deadlock above all, fails the test.
      const settle = async <T>(calls: readonly Promise<T>[]): Promise<readonly T[]> => {
        const settled = await Promise.allSettled(calls);
        const fulfilled: T[] = [];
        for (const outcome of settled) {
          if (outcome.status === "fulfilled") {
            fulfilled.push(outcome.value);
          } else {
            expect(outcome.reason).toBeInstanceOf(IdentityError);
            expect((outcome.reason as IdentityError).code).toBe("session-not-found");
          }
        }
        expect(fulfilled.length).toBeGreaterThan(0);
        return fulfilled;
      };
      for (let round = 0; round < 10; round += 1) {
        const name = username(`race-${String(round)}`);
        const { key, session: a } = await register(name);
        const b = await login(name, key);
        const c = await login(name, key);
        const results = await settle([
          service.revokeOtherSessions(a.token),
          otherConnection.revokeOtherSessions(b.token),
        ]);
        // A row is revoked once, by whichever statement reached it first.
        const revoked = results.flatMap((result) => result.revokedSessionIds);
        expect(revoked.filter((id) => id === c.session.id)).toHaveLength(1);
        expect(await authenticates(c.token)).toBe(false);

        const d = await login(name, key);
        const e = await login(name, key);
        const answers = await settle([
          service.revokeSessionById(d.token, e.session.id),
          otherConnection.revokeSessionById(e.token, d.session.id),
        ]);
        expect(answers.some((answer) => answer.revoked)).toBe(true);
        expect([await authenticates(d.token), await authenticates(e.token)]).toContain(false);
      }
    }, 60_000);

    it("locks the rows it revokes in id order and never the caller's, as revokeAllSessions does", async () => {
      // A third connection holds the row with the middle id, so the revocation
      // stops there. A statement that locks in id order then holds exactly the
      // rows with smaller ids; one that locks in scan order holds whichever rows
      // its scan reached first. The probe reads which rows are locked without
      // waiting for any.
      const pair = await openConnections(2);
      const holder = pair[0]!;
      const revoker = pair[1]!;
      try {
        for (const variant of ["others", "all"] as const) {
          const name = username(`lock-order-${variant}`);
          const { key, accountId, session: caller } = await register(name);
          const others: IssuedSession[] = [];
          for (let index = 0; index < 15; index += 1) {
            others.push(await login(name, key, { ipHash: `lock-order-${variant}-${String(index)}-${suffix}` }));
          }
          // Lowercase UUID text sorts as PostgreSQL orders uuid values.
          const targets = (variant === "others" ? others : [caller, ...others])
            .map((issued) => issued.session.id)
            .sort();
          const middle = Math.floor(targets.length / 2);
          const blocker = targets[middle]!;

          await holder.client.query("BEGIN");
          let revocation: Promise<readonly string[] | number> | undefined;
          try {
            await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [blocker]);
            revocation =
              variant === "others"
                ? revoker.service.revokeOtherSessions(caller.token).then((result) => result.revokedSessionIds)
                : revoker.service.revokeAllSessions(accountId);
            // Awaited below; this only keeps a failed assertion from leaving it unhandled.
            void revocation.catch(() => undefined);
            await waitUntilBlocked(revoker.pid);
            const unlocked = await first.query(
              `SELECT id FROM ${prefix}_sessions WHERE account_id = $1::uuid FOR SHARE SKIP LOCKED`,
              [accountId],
            );
            const unlockedIds = new Set(unlocked.rows.map((row) => String(row["id"])));
            const all = [caller, ...others].map((issued) => issued.session.id);
            const heldByRevocation = all.filter((id) => id !== blocker && !unlockedIds.has(id)).sort();
            expect(heldByRevocation).toEqual(targets.slice(0, middle));
            if (variant === "others") expect(unlockedIds.has(caller.session.id)).toBe(true);
          } finally {
            await holder.client.query("COMMIT");
          }
          const result = await revocation;
          expect(result).toEqual(variant === "others" ? targets : targets.length);
        }
      } finally {
        await closeConnections(pair);
      }
    }, 60_000);

    it("never deadlocks with many revoke-others at once under authenticate traffic", async () => {
      // `authenticate` rewrites `last_seen_at`, which moves row versions between
      // the snapshots of overlapping revocations. Locking in scan order then
      // locks the same rows in different orders: before the rows were locked in
      // id order this failed most runs with PostgreSQL 40P01.
      const revokers = 6;
      const lanes = 4;
      const perAccount = 24;
      const connections = await openConnections(revokers + lanes);
      try {
        for (let round = 0; round < 60; round += 1) {
          const name = username(`deadlock-${String(round)}`);
          const { key, session: s0 } = await register(name);
          const sessions: IssuedSession[] = [s0];
          while (sessions.length < perAccount) {
            const start = sessions.length;
            sessions.push(...(await Promise.all(
              connections.slice(0, Math.min(connections.length, perAccount - start)).map((connection, index) =>
                login(name, key, { ipHash: `deadlock-${String(round)}-${String(start + index)}-${suffix}` }, connection.service),
              ),
            )));
          }

          const unexpected: unknown[] = [];
          const traffic = connections.slice(revokers).map(async (connection, lane) => {
            for (let pass = 0; pass < 2; pass += 1) {
              for (let index = revokers + lane; index < perAccount; index += lanes) {
                try {
                  await connection.service.authenticate(sessions[index]!.token);
                } catch (error) {
                  if (!(error instanceof IdentityError && error.code === "session-not-found")) unexpected.push(error);
                }
              }
            }
          });
          const revocations = connections
            .slice(0, revokers)
            .map((connection, index) => connection.service.revokeOtherSessions(sessions[index]!.token));
          const [settled] = await Promise.all([Promise.allSettled(revocations), Promise.all(traffic)]);
          expect(unexpected).toEqual([]);

          // Legal outcomes only: a revocation succeeds, or finds its own session
          // already revoked by one that committed first.
          const revoked: string[] = [];
          settled.forEach((outcome, index) => {
            if (outcome.status === "rejected") {
              expect(outcome.reason).toBeInstanceOf(IdentityError);
              expect((outcome.reason as IdentityError).code).toBe("session-not-found");
              return;
            }
            expect(outcome.value.revokedSessionIds).not.toContain(sessions[index]!.session.id);
            revoked.push(...outcome.value.revokedSessionIds);
          });
          expect(settled.some((outcome) => outcome.status === "fulfilled")).toBe(true);
          // Each row is revoked once, by whichever statement locked it first.
          expect(new Set(revoked).size).toBe(revoked.length);
          for (const bystander of sessions.slice(revokers)) {
            expect(revoked).toContain(bystander.session.id);
          }
        }
      } finally {
        await closeConnections(connections);
      }
    }, 120_000);
  });

  describe("client label and client hashes", () => {
    it("stores a valid label and drops an invalid one without failing the sign-in", async () => {
      const name = username("label");
      const { key, session } = await register(name, { clientLabel: "Samsung Internet on Android" });
      expect((await sessionRow(session.session.id))?.["client_label"]).toBe("Samsung Internet on Android");
      for (const invalid of [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "a".repeat(65),
        "",
        "Firefox on macOS\n",
        "Firefox; DROP TABLE",
        42 as unknown as string,
      ]) {
        const issued = await login(name, key, { clientLabel: invalid, ipHash: `label-${crypto.randomUUID()}` });
        expect((await sessionRow(issued.session.id))?.["client_label"]).toBeNull();
      }
      // The issued session object gains no field.
      expect(Object.keys(session.session).sort()).toEqual(["accountId", "expiresAt", "id", "issuedAt", "lastSeenAt"]);
    });

    it("deletes the label with its row when pruneExpired removes a revoked or expired session", async () => {
      const name = username("prune");
      const label = `Opera on ChromeOS ${suffix}`;
      const { key, session: keep } = await register(name);
      const revoked = await login(name, key, { clientLabel: label });
      const short = createIdentityService(sql, { ...config(prefix), sessionTtlSeconds: 1 });
      const expiring = await login(name, key, { clientLabel: label }, short);
      expect(await service.revokeSessionById(keep.token, revoked.session.id)).toEqual({ revoked: true });

      await service.pruneExpired({ now: new Date(expiring.session.expiresAt.getTime() + 1_000) });
      expect(await sessionRow(revoked.session.id)).toBeUndefined();
      expect(await sessionRow(expiring.session.id)).toBeUndefined();
      const remaining = await first.query(
        `SELECT count(*)::int AS n FROM ${prefix}_sessions WHERE client_label = $1`,
        [label],
      );
      expect(remaining.rows[0]?.["n"]).toBe(0);
      expect(await authenticates(keep.token)).toBe(true);
    });

    it("prunes around a dead session another statement holds locked instead of waiting on it", async () => {
      const opened = await openConnections(1);
      const holder = opened[0]!;
      try {
        const name = username("prune-locked");
        const { key, session: keep } = await register(name);
        const locked = await login(name, key, { ipHash: `prune-locked-1-${suffix}` });
        const unlocked = await login(name, key, { ipHash: `prune-locked-2-${suffix}` });
        for (const issued of [locked, unlocked]) {
          expect(await service.revokeSessionById(keep.token, issued.session.id)).toEqual({ revoked: true });
        }

        await holder.client.query("BEGIN");
        try {
          await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [
            locked.session.id,
          ]);
          // Bounded, so a prune that waits on the lock fails the test rather than hanging it.
          let timer: ReturnType<typeof setTimeout> | undefined;
          const outcome = await Promise.race([
            service.pruneExpired().then(() => "finished"),
            new Promise<string>((resolve) => {
              timer = setTimeout(() => resolve("waited on the lock"), 5_000);
            }),
          ]);
          clearTimeout(timer);
          expect(outcome).toBe("finished");
          expect(await sessionRow(unlocked.session.id)).toBeUndefined();
          expect(await sessionRow(locked.session.id)).toBeDefined();
        } finally {
          await holder.client.query("ROLLBACK");
        }

        await service.pruneExpired();
        expect(await sessionRow(locked.session.id)).toBeUndefined();
        expect(await authenticates(keep.token)).toBe(true);
      } finally {
        await closeConnections(opened);
      }
    });

    it("writes NULL client hashes with storeSessionClientHashes false, and still rate-limits by the ip hash", async () => {
      const noHashes = createIdentityService(sql, { ...config(prefix), storeSessionClientHashes: false });
      expect(noHashes.config.storeSessionClientHashes).toBe(false);
      expect(service.config.storeSessionClientHashes).toBe(true);

      const name = username("nohash");
      const ipHash = `ip-nohash-${suffix}`;
      const context = { ipHash, userAgentHash: "ua-nohash", clientLabel: "Chrome on Windows" };
      const { key, session } = await register(name, context, noHashes);
      const loggedIn = await login(name, key, context, noHashes);
      for (const issued of [session, loggedIn]) {
        expect(await sessionRow(issued.session.id)).toMatchObject({
          ip_hash: null, user_agent_hash: null, client_label: "Chrome on Windows",
        });
      }
      // The default keeps writing them, so existing consumers see no change.
      const withHashes = await login(name, key, context);
      expect(await sessionRow(withHashes.session.id)).toMatchObject({
        ip_hash: ipHash, user_agent_hash: "ua-nohash", client_label: "Chrome on Windows",
      });

      // The login bucket is keyed by the context's ip hash, not by the column.
      const bucket = (subject: string) =>
        bytesToHex(sha256(encoder.encode(
          ["web2-ish-self-custody rate limit bucket v1", serviceProfileId, "login", subject, normalizeUsername(name)].join("\n"),
        )));
      const counts = await first.query(
        `SELECT bucket, count FROM ${prefix}_rate_limits WHERE bucket = ANY($1::text[])`,
        [[bucket(ipHash), bucket("missing-ip-hash")]],
      );
      expect(counts.rows).toEqual([{ bucket: bucket(ipHash), count: 2 }]);
    });
  });

  describe("router", () => {
    const base = "https://example.test/identity";
    const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

    it("mounts none of the session routes by default", async () => {
      const router = createIdentityRouter(service, { useCookies: false });
      const name = username("default-router");
      const { key, session: s0 } = await register(name);
      const s1 = await login(name, key);

      const list = await router(new Request(`${base}/sessions`, { headers: bearer(s0.token) }));
      expect(list.status).toBe(405);
      expect(list.headers.get("allow")).toBe("POST");
      const others = await router(new Request(`${base}/sessions`, { method: "DELETE", headers: bearer(s0.token) }));
      expect(others.status).toBe(405);
      for (const method of ["DELETE", "GET"]) {
        const one = await router(new Request(`${base}/sessions/${s1.session.id}`, { method, headers: bearer(s0.token) }));
        expect(one.status).toBe(404);
        expect(await one.json()).toEqual({ error: { code: "not-found", message: "No such identity route." } });
      }
      expect(await authenticates(s0.token)).toBe(true);
      expect(await authenticates(s1.token)).toBe(true);
    });

    it("stores the hook's label on register and login, and drops an invalid or failing one", async () => {
      const router = createIdentityRouter(service, {
        useCookies: false,
        accountSecurityRoutes: true,
        clientLabel: (request) => {
          const agent = request.headers.get("user-agent") ?? "";
          if (agent.includes("Throw")) throw new Error("parser bug");
          if (agent.includes("Raw")) return agent;
          if (agent.includes("Firefox")) return "Firefox on macOS";
          if (agent.includes("Safari")) return "Safari on iOS";
          return undefined;
        },
      });
      const post = (path: string, body: unknown, userAgent: string) =>
        router(new Request(`${base}${path}`, {
          method: "POST",
          headers: { "Content-Type": "application/json", "User-Agent": userAgent },
          body: JSON.stringify(body),
        }));
      const challenge = async (name: string, purpose: string) =>
        (await (await post("/challenges", { username: name, purpose }, "Test")).json()) as { id: string; message: string };

      const name = username("router-label");
      const key = newKey();
      const registration = await challenge(name, "registration");
      const registered = await post("/accounts", {
        username: name, address: key.identifier, publicKey: key.identifier,
        challengeId: registration.id, signature: sign(key, registration.message),
      }, "Mozilla/5.0 Firefox/131.0");
      expect(registered.status).toBe(201);
      const registeredBody = (await registered.json()) as { session: { id: string }; token: string };
      expect(Object.keys(registeredBody).sort()).toEqual(["account", "session", "token", "wallet"]);
      expect(Object.keys(registeredBody.session).sort()).toEqual(["accountId", "expiresAt", "id", "issuedAt", "lastSeenAt"]);
      expect((await sessionRow(registeredBody.session.id))?.["client_label"]).toBe("Firefox on macOS");

      const loginWith = async (userAgent: string) => {
        const c = await challenge(name, "login");
        const response = await post("/sessions", { username: name, challengeId: c.id, signature: sign(key, c.message) }, userAgent);
        expect(response.status).toBe(200);
        const body = (await response.json()) as { session: { id: string }; token: string };
        expect(Object.keys(body).sort()).toEqual(["account", "session", "token"]);
        return body;
      };
      const safari = await loginWith("Mozilla/5.0 (iPhone) Safari/604.1");
      expect((await sessionRow(safari.session.id))?.["client_label"]).toBe("Safari on iOS");
      const raw = await loginWith("Raw Mozilla/5.0 (X11; Linux x86_64)");
      expect((await sessionRow(raw.session.id))?.["client_label"]).toBeNull();
      const failing = await loginWith("Throw");
      expect((await sessionRow(failing.session.id))?.["client_label"]).toBeNull();
      const unknown = await loginWith("curl/8.0");
      expect((await sessionRow(unknown.session.id))?.["client_label"]).toBeNull();

      // Listing over HTTP: the label is what was stored, the caller is flagged.
      const listed = await router(new Request(`${base}/sessions`, { headers: { ...bearer(safari.token), "User-Agent": "Mozilla/5.0 Firefox/131.0" } }));
      expect(listed.status).toBe(200);
      const { sessions } = (await listed.json()) as { sessions: { id: string; clientLabel: string | null; current: boolean }[] };
      expect(sessions).toHaveLength(5);
      expect(sessions.filter((entry) => entry.current).map((entry) => entry.id)).toEqual([safari.session.id]);
      expect(sessions.find((entry) => entry.id === registeredBody.session.id)?.clientLabel).toBe("Firefox on macOS");
      for (const entry of sessions) {
        expect(Object.keys(entry).sort()).toEqual(listedKeys);
      }
      // Only session-issuing routes store a label: listing changed none.
      expect((await sessionRow(safari.session.id))?.["client_label"]).toBe("Safari on iOS");
    });

    it("serves list, revoke-one and revoke-others when accountSecurityRoutes is on", async () => {
      const router = createIdentityRouter(service, { useCookies: false, accountSecurityRoutes: true });
      const name = username("router-revoke");
      const { key, session: s0 } = await register(name);
      const s1 = await login(name, key);
      const s2 = await login(name, key);
      const s3 = await login(name, key);
      const call = (method: string, path: string, token?: string) =>
        router(new Request(`${base}${path}`, { method, headers: token === undefined ? {} : bearer(token) }));

      const one = await call("DELETE", `/sessions/${s1.session.id}`, s0.token);
      expect(one.status).toBe(200);
      expect(await one.json()).toEqual({ revoked: true });
      expect(await authenticates(s1.token)).toBe(false);

      const self = await call("DELETE", `/sessions/${s0.session.id}`, s0.token);
      expect(self.status).toBe(400);
      expect(((await self.json()) as { error: { code: string } }).error.code).toBe("invalid-request");
      const malformed = await call("DELETE", "/sessions/not-a-uuid", s0.token);
      expect(malformed.status).toBe(400);
      const wrongMethod = await call("GET", `/sessions/${s2.session.id}`, s0.token);
      expect(wrongMethod.status).toBe(405);
      expect(wrongMethod.headers.get("allow")).toBe("DELETE");
      for (const [method, path] of [["GET", "/sessions"], ["DELETE", "/sessions"], ["DELETE", `/sessions/${s2.session.id}`]] as const) {
        const anonymous = await call(method, path);
        expect(anonymous.status).toBe(401);
      }

      const others = await call("DELETE", "/sessions", s0.token);
      expect(others.status).toBe(200);
      const { revokedSessionIds } = (await others.json()) as { revokedSessionIds: string[] };
      expect([...revokedSessionIds].sort()).toEqual([s2.session.id, s3.session.id].sort());
      expect(await authenticates(s0.token)).toBe(true);

      const remaining = (await (await call("GET", "/sessions", s0.token)).json()) as { sessions: { id: string }[] };
      expect(remaining.sessions.map((entry) => entry.id)).toEqual([s0.session.id]);

      // Sign-out is unchanged and still answers on its own path.
      const signOut = await call("DELETE", "/sessions/current", s0.token);
      expect(signOut.status).toBe(200);
      expect(await signOut.json()).toEqual({ revoked: true });
      expect(await authenticates(s0.token)).toBe(false);
    });

    it("applies the cookie-mode origin gate to the revoke routes", async () => {
      const origin = "https://app.example";
      const router = createIdentityRouter(service, { accountSecurityRoutes: true, trustedOrigins: [origin] });
      const name = username("router-cookie");
      const { key, session: s0 } = await register(name);
      const s1 = await login(name, key);
      const cookie = `__Host-w2sc_session=${encodeURIComponent(s0.token)}`;

      const listed = await router(new Request(`${base}/sessions`, { headers: { Cookie: cookie } }));
      expect(listed.status).toBe(200);
      for (const path of ["/sessions", `/sessions/${s1.session.id}`]) {
        const forged = await router(new Request(`${base}${path}`, {
          method: "DELETE", headers: { Cookie: cookie, Origin: "https://evil.example" },
        }));
        expect(forged.status).toBe(403);
      }
      expect(await authenticates(s1.token)).toBe(true);
      const allowed = await router(new Request(`${base}/sessions/${s1.session.id}`, {
        method: "DELETE", headers: { Cookie: cookie, Origin: origin },
      }));
      expect(await allowed.json()).toEqual({ revoked: true });
    });
  });
});
