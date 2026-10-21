import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAccountChangeMessage,
  normalizeEmail,
  signInEd25519ExternalSalt,
  type AccountChangeAction,
} from "../../src/index.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import { applyMigrationStatement, identityMigrations } from "../../src/server/migrations.js";
import {
  createIdentityService,
  pgDriver,
  type IdentityChallenge,
  type IdentityService,
  type IdentityServiceConfig,
  type IssuedSession,
  type RequestContext,
  type SecurityEventNotice,
  type SqlDriver,
  type SqlParameter,
  type SqlRow,
} from "../../src/server/index.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * Account changes and recovery keys (migration 7, sign-in-key rotation, the
 * email change, recovery-key enrollment and removal, recovery begin and
 * completion, the security events, the operator revocation, the hook, the
 * rate limits) over real PostgreSQL. Gated on W2SC_TEST_DATABASE_URL like the
 * other server suites.
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
const prefix = `wac_${suffix}`;
const concurrencyPrefix = `wam_${suffix}`;
const serviceProfileId = `w2sc-account-${suffix}`;
const tables = [
  "account_resets", "account_recoveries", "account_recovery_keys", "wallet_setups", "wallet_policy", "audit_events",
  "rate_limits", "email_verifications", "sessions", "auth_challenges", "account_wallets", "accounts",
  "service_profile_bootstrap", "service_profiles", "schema_migrations",
];

const events: SecurityEventNotice[] = [];

const config = (tablePrefix: string, overrides: Partial<IdentityServiceConfig> = {}): IdentityServiceConfig => ({
  serviceProfileId,
  profile: signInEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-testnet",
  tablePrefix,
  sessionTtlSeconds: 3_600,
  accountSecurity: { signInKeyRotation: true, recoveryKeys: true },
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
const recoveryPrincipal = (key: Key): string => `recovery-key:${key.publicKeyHex}`;
const enrolled = (key: Key) => ({ address: key.identifier, publicKey: key.identifier });

/** A fresh hashed IP per call, so rate-limit buckets never carry across tests. */
let ipCounter = 0;
function ctx(extra: Omit<RequestContext, "ipHash"> = {}): RequestContext {
  ipCounter += 1;
  return { ipHash: `ip-${suffix}-${String(ipCounter)}`, ...extra };
}

/** A unique username per call. */
function username(label: string): string {
  return `${label}-${crypto.randomUUID().slice(0, 8)}@example.com`;
}

function messageFor(
  challenge: IdentityChallenge,
  action: AccountChangeAction,
  authorizer: string,
  subject: string,
): string {
  // A client reads the nonce from the challenge message's seventh line.
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

async function register(
  name: string,
  via: IdentityService = service,
  context: RequestContext = ctx(),
): Promise<Readonly<{ key: Key; accountId: string; session: IssuedSession }>> {
  const key = newKey();
  const challenge = await via.createChallenge(name, "registration", ctx());
  const registered = await via.register(
    { username: name, address: key.identifier, publicKey: key.identifier, challengeId: challenge.id, signature: sign(key, challenge.message) },
    context,
  );
  return { key, accountId: registered.account.id, session: registered.session };
}

async function login(
  name: string,
  key: Key,
  via: IdentityService = service,
  context: RequestContext = ctx(),
): Promise<IssuedSession> {
  const challenge = await via.createChallenge(name, "login", ctx());
  return (
    await via.login({ username: name, challengeId: challenge.id, signature: sign(key, challenge.message) }, context)
  ).session;
}

async function rotate(
  name: string,
  token: string,
  from: Key,
  to: Key,
  via: IdentityService = service,
  context: RequestContext = ctx(),
) {
  const challenge = await via.createChallenge(name, "rotation", ctx());
  const message = messageFor(challenge, "sign-in-key-rotation", keyPrincipal(from), keyPrincipal(to));
  return via.rotateSignInKey(
    token,
    { challengeId: challenge.id, newKey: enrolled(to), authorizerSignature: sign(from, message), subjectSignature: sign(to, message) },
    context,
  );
}

async function enroll(name: string, token: string, primary: Key, recovery: Key, via: IdentityService = service) {
  const challenge = await via.createChallenge(name, "rotation", ctx());
  const message = messageFor(challenge, "recovery-key-enrollment", keyPrincipal(primary), recoveryPrincipal(recovery));
  return via.enrollRecoveryKey(
    token,
    {
      challengeId: challenge.id,
      recoveryPublicKey: recovery.publicKeyHex,
      authorizerSignature: sign(primary, message),
      subjectSignature: sign(recovery, message),
    },
    ctx(),
  );
}

async function removeRecovery(name: string, token: string, primary: Key) {
  const challenge = await service.createChallenge(name, "rotation", ctx());
  const message = messageFor(challenge, "recovery-key-removal", keyPrincipal(primary), "none");
  return service.removeRecoveryKey(token, { challengeId: challenge.id, authorizerSignature: sign(primary, message) }, ctx());
}

async function begin(name: string, recovery: Key, via: IdentityService = service, context: RequestContext = ctx()) {
  const challenge = await via.createChallenge(name, "rotation", ctx());
  const message = messageFor(challenge, "recovery-begin", recoveryPrincipal(recovery), "none");
  return via.beginRecovery(
    { username: name, challengeId: challenge.id, recoveryPublicKey: recovery.publicKeyHex, signature: sign(recovery, message) },
    context,
  );
}

async function complete(
  name: string,
  recoveryToken: string,
  recovery: Key,
  to: Key,
  via: IdentityService = service,
  context: RequestContext = ctx(),
) {
  const challenge = await via.createChallenge(name, "rotation", ctx());
  const message = messageFor(challenge, "recovery-reset", recoveryPrincipal(recovery), keyPrincipal(to));
  return via.completeRecovery(
    recoveryToken,
    { challengeId: challenge.id, newKey: enrolled(to), authorizerSignature: sign(recovery, message), subjectSignature: sign(to, message) },
    context,
  );
}

async function changeEmail(name: string, token: string, primary: Key, email: string, signedAs = normalizeEmail(email)) {
  const challenge = await service.createChallenge(name, "rotation", ctx());
  const message = messageFor(challenge, "email-change", keyPrincipal(primary), `email:${signedAs}`);
  return service.changeEmail(token, { challengeId: challenge.id, email, authorizerSignature: sign(primary, message) }, ctx());
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

async function auditRows(accountId: string, action: string): Promise<readonly SqlRow[]> {
  return (
    await first.query(
      `SELECT metadata, created_at FROM ${prefix}_audit_events WHERE account_id = $1::uuid AND action = $2 ORDER BY created_at, id`,
      [accountId, action],
    )
  ).rows;
}

async function liveTokens(accountId: string): Promise<number> {
  return Number(
    (
      await first.query(
        `SELECT count(*)::int AS live FROM ${prefix}_account_recoveries
          WHERE account_id = $1::uuid AND completed_at IS NULL AND revoked_at IS NULL`,
        [accountId],
      )
    ).rows[0]?.["live"],
  );
}

async function suspend(accountId: string): Promise<void> {
  await first.query(`UPDATE ${prefix}_accounts SET status = 'suspended' WHERE id = $1::uuid`, [accountId]);
}

function eventsFor(accountId: string): readonly SecurityEventNotice[] {
  return events.filter((event) => event.accountId === accountId);
}

describe.skipIf(!url)("account changes and recovery keys on PostgreSQL", () => {
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

  describe("migration 7", () => {
    /** The two tables, their indexes and their constraints, found by relation, not by name. */
    async function recoveryObjects(): Promise<readonly string[]> {
      const rows = await first.query(
        `WITH t AS (
           SELECT oid FROM pg_class WHERE oid IN (to_regclass($1), to_regclass($2))
         )
         SELECT c.relname || ':r' AS object FROM pg_class c WHERE c.oid IN (SELECT oid FROM t)
          UNION ALL
         SELECT i.indexrelid::regclass::text || ':i' FROM pg_index i WHERE i.indrelid IN (SELECT oid FROM t)
          UNION ALL
         SELECT con.conname::text || ':' || con.contype::text FROM pg_constraint con WHERE con.conrelid IN (SELECT oid FROM t)
          ORDER BY 1`,
        [`${concurrencyPrefix}_account_recovery_keys`, `${concurrencyPrefix}_account_recoveries`],
      );
      return rows.rows.map((row) => String(row["object"]));
    }

    it("leaves one of each object when run twice and from two concurrent runners", async () => {
      const one = createIdentityService(pgDriver(first), config(concurrencyPrefix));
      const two = createIdentityService(pgDriver(second), config(concurrencyPrefix));
      await one.migrate();
      const expected = await recoveryObjects();
      // Two tables; eight indexes (two primary keys, two UNIQUE constraints,
      // the two partial unique indexes, the account-history and key indexes);
      // two primary keys, two UNIQUE constraints, four foreign keys and six
      // named checks.
      expect(expected.filter((object) => object.endsWith(":r"))).toHaveLength(2);
      expect(expected.filter((object) => object.endsWith(":i"))).toHaveLength(8);
      expect(expected.filter((object) => object.endsWith(":p"))).toHaveLength(2);
      expect(expected.filter((object) => object.endsWith(":u"))).toHaveLength(2);
      expect(expected.filter((object) => object.endsWith(":f"))).toHaveLength(4);
      expect(expected.filter((object) => object.endsWith(":c"))).toHaveLength(6);

      const statements = identityMigrations(one.config).find((migration) => migration.version === 7)!.statements;
      for (const statement of statements) {
        await applyMigrationStatement(pgDriver(first), statement);
        await applyMigrationStatement(pgDriver(first), statement);
      }
      expect(await recoveryObjects()).toEqual(expected);

      const drop = async (): Promise<void> => {
        await first.query(
          `DROP TABLE ${concurrencyPrefix}_account_recoveries, ${concurrencyPrefix}_account_recovery_keys`,
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
        expect(await recoveryObjects()).toEqual(expected);
      }

      // The whole runner, twice at once, with version 7 not yet recorded.
      await drop();
      await first.query(`DELETE FROM ${concurrencyPrefix}_schema_migrations WHERE version = 7`);
      const [ranOne, ranTwo] = await Promise.all([one.migrate(), two.migrate()]);
      expect([...ranOne, ...ranTwo]).toContain(7);
      expect(await recoveryObjects()).toEqual(expected);
      expect(
        (await first.query(`SELECT name FROM ${concurrencyPrefix}_schema_migrations WHERE version = 7`)).rows,
      ).toEqual([{ name: "account-recovery-keys" }]);
      expect(await one.migrate()).toEqual([]);
    }, 60_000);

    it("serves an account's key history and a key's tokens from an index, not a scan", async () => {
      // With sequential scans priced out, a plan that still scans means no
      // index can answer: the partial active index covers only active keys.
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
      const history = await plan(
        `SELECT id FROM ${prefix}_account_recovery_keys k WHERE k.account_id = $1::uuid
          ORDER BY (k.status = 'active') DESC, k.created_at DESC, k.id DESC LIMIT 1`,
      );
      expect(history).toContain(`${prefix}_account_recovery_keys_account_idx`);
      expect(history).not.toMatch(/Seq Scan/u);
      const tokens = await plan(`SELECT id FROM ${prefix}_account_recoveries WHERE recovery_key_id = $1::uuid`);
      expect(tokens).toContain(`${prefix}_account_recoveries_key_idx`);
      expect(tokens).not.toMatch(/Seq Scan/u);
    });

    it("refuses a second active key and a second live token for one account", async () => {
      const name = username("unique");
      const { key, accountId, session } = await register(name);
      const recovery = newKey();
      await enroll(name, session.token, key, recovery);
      const insertKey = (status: string) =>
        first.query(
          `INSERT INTO ${prefix}_account_recovery_keys (account_id, service_profile_id, public_key, status)
           VALUES ($1::uuid, $2, $3, $4)`,
          [accountId, serviceProfileId, newKey().publicKeyHex, status],
        );
      await expect(insertKey("active")).rejects.toMatchObject({ code: "23505" });
      await expect(insertKey("used")).rejects.toMatchObject({ code: "23514" });
      await begin(name, recovery);
      await expect(
        first.query(
          `INSERT INTO ${prefix}_account_recoveries (account_id, recovery_key_id, token_hash, expires_at)
           SELECT account_id, id, $2, now() + interval '1 minute' FROM ${prefix}_account_recovery_keys
            WHERE account_id = $1::uuid AND status = 'active'`,
          [accountId, "ab".repeat(32)],
        ),
      ).rejects.toMatchObject({ code: "23505" });
    });
  });

  describe("registration", () => {
    it("refuses a small-order key even with the signature zip215 accepts, and a non-canonical one", async () => {
      const name = username("small-order");
      const challenge = await service.createChallenge(name, "registration", ctx());
      const smallOrder = `S_01${"00".repeat(31)}`;
      // R = identity, S = 0 verifies under noble's default rule for any message.
      const forged = `01${"00".repeat(63)}`;
      expect(ed25519.verify(hexToBytes(forged), encoder.encode(challenge.message), hexToBytes(smallOrder.slice(2)))).toBe(true);
      await expectCode(
        () => service.register({ username: name, address: smallOrder, publicKey: smallOrder, challengeId: challenge.id, signature: forged }, ctx()),
        "invalid-public-key",
      );
      const nonCanonical = `S_f0${"ff".repeat(30)}7f`;
      await expectCode(
        () => service.register({ username: name, address: nonCanonical, publicKey: nonCanonical, challengeId: challenge.id, signature: forged }, ctx()),
        "invalid-public-key",
      );
      // Refused before the challenge: it is still usable by a real key.
      const key = newKey();
      const registered = await service.register(
        { username: name, address: key.identifier, publicKey: key.identifier, challengeId: challenge.id, signature: sign(key, challenge.message) },
        ctx(),
      );
      expect(registered.account.usernameNormalized).toBe(name.toLowerCase());
    });
  });

  describe("rotateSignInKey", () => {
    it("rebinds the account in place, revokes every other session and keeps the caller's", async () => {
      const name = username("rotate");
      const { key, accountId, session: s0 } = await register(name, service, ctx({ clientLabel: "Firefox on macOS" }));
      const s1 = await login(name, key);
      const s2 = await login(name, key);
      const bystander = await register(username("bystander"));
      const [before] = await service.listWallets(accountId);
      const next = newKey();

      const result = await rotate(name, s0.token, key, next, service, ctx({ clientLabel: "Firefox on macOS" }));
      expect(result.wallets).toHaveLength(1);
      expect(result.wallets[0]).toMatchObject({
        id: before!.id,
        accountId,
        address: next.identifier,
        addressNormalized: next.identifier.toLowerCase(),
        publicKey: next.identifier,
        isPrimary: true,
      });
      expect(result.wallets[0]!.fingerprint).not.toBe(before!.fingerprint);
      expect([...result.revokedSessionIds].sort()).toEqual([s1.session.id, s2.session.id].sort());
      expect(await service.listWallets(accountId)).toEqual(result.wallets);

      expect(await authenticates(s0.token)).toBe(true);
      expect(await authenticates(s1.token)).toBe(false);
      expect(await authenticates(s2.token)).toBe(false);
      expect(await authenticates(bystander.session.token)).toBe(true);

      // The old key no longer signs in; the new one does.
      expect(await loginFails(name, key)).toBe(true);
      expect(await authenticates((await login(name, next)).token)).toBe(true);

      expect((await auditRows(accountId, "account.key-rotate")).map((row) => row["metadata"])).toEqual([
        { method: "password", revokedSessions: 2, sessionId: s0.session.id },
      ]);
      expect(eventsFor(accountId).filter((event) => event.action === "account.key-rotate")).toEqual([
        expect.objectContaining({ clientLabel: "Firefox on macOS", revokedSessions: 2 }),
      ]);
    });

    it("is atomic under a concurrent rotation: exactly one wins, the other is stale", async () => {
      for (let round = 0; round < 8; round += 1) {
        const name = username(`race-${String(round)}`);
        const { key, accountId, session: a } = await register(name);
        const b = await login(name, key);
        const [winnerA, winnerB] = [newKey(), newKey()];
        // Two sessions, and in odd rounds one session twice (two tabs).
        const tokenB = round % 2 === 0 ? b.token : a.token;
        const settled = await Promise.allSettled([
          rotate(name, a.token, key, winnerA, service),
          rotate(name, tokenB, key, winnerB, otherService),
        ]);
        const fulfilled = settled.filter((outcome) => outcome.status === "fulfilled");
        expect(fulfilled).toHaveLength(1);
        for (const outcome of settled) {
          if (outcome.status === "rejected") {
            expect(outcome.reason).toBeInstanceOf(IdentityError);
            // Stale when the statements overlapped; session-not-found when the
            // winner had already revoked the loser's session; invalid-signature
            // when the loser read the winner's key and so built a message its
            // old-key signature does not match.
            expect(["stale-key", "session-not-found", "invalid-signature"]).toContain(
              (outcome.reason as IdentityError).code,
            );
          }
        }
        const winner = settled[0]!.status === "fulfilled" ? winnerA : winnerB;
        expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([winner.identifier]);
        expect(await auditRows(accountId, "account.key-rotate")).toHaveLength(1);
      }
    }, 60_000);

    it("answers stale-key when the key moved after the change was signed", async () => {
      const name = username("stale");
      const { key, accountId, session } = await register(name);
      const intruding = newKey();
      // Another change commits between the read that built the message and
      // the statement: here, the moment the statement is sent.
      const racing: SqlDriver = {
        kind: "racing",
        async query<T extends SqlRow = SqlRow>(text: string, parameters: readonly SqlParameter[] = []): Promise<T[]> {
          if (text.includes("'account.key-rotate'")) {
            await first.query(
              `UPDATE ${prefix}_account_wallets SET address = $2, address_normalized = lower($2), public_key = $2 WHERE account_id = $1::uuid`,
              [accountId, intruding.identifier],
            );
          }
          return (await first.query(text, parameters)).rows as T[];
        },
      };
      const racingService = createIdentityService(racing, config(prefix));
      await expectCode(() => rotate(name, session.token, key, newKey(), racingService), "stale-key");
      expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([intruding.identifier]);
      expect(await auditRows(accountId, "account.key-rotate")).toHaveLength(0);
      expect(await authenticates(session.token)).toBe(true);
    });

    it("keeps a login that verified the old key from issuing a session after the rotation", async () => {
      const name = username("login-race");
      const { key, accountId } = await register(name);
      const before = Number(
        (await first.query(`SELECT count(*)::int AS n FROM ${prefix}_sessions WHERE account_id = $1::uuid`, [accountId])).rows[0]?.["n"],
      );
      const rotated = newKey();
      const racing: SqlDriver = {
        kind: "racing",
        async query<T extends SqlRow = SqlRow>(text: string, parameters: readonly SqlParameter[] = []): Promise<T[]> {
          if (parameters[6] === "account.login") {
            // A rotation commits after login read and verified the old key.
            await first.query(
              `UPDATE ${prefix}_account_wallets SET address = $2, address_normalized = lower($2), public_key = $2 WHERE account_id = $1::uuid`,
              [accountId, rotated.identifier],
            );
          }
          return (await first.query(text, parameters)).rows as T[];
        },
      };
      await expectCode(() => login(name, key, createIdentityService(racing, config(prefix))), "invalid-signature");
      const after = Number(
        (await first.query(`SELECT count(*)::int AS n FROM ${prefix}_sessions WHERE account_id = $1::uuid`, [accountId])).rows[0]?.["n"],
      );
      expect(after).toBe(before);
      expect(await auditRows(accountId, "account.login")).toHaveLength(0);
    });

    it("refuses an unchanged key, bad signatures and a challenge of another username", async () => {
      const name = username("refuse");
      const { key, accountId, session } = await register(name);
      await expectCode(() => rotate(name, session.token, key, key), "key-unchanged");

      const next = newKey();
      const challenge = await service.createChallenge(name, "rotation", ctx());
      const message = messageFor(challenge, "sign-in-key-rotation", keyPrincipal(key), keyPrincipal(next));
      const attempt = (authorizerSignature: string, subjectSignature: string, challengeId = challenge.id) =>
        service.rotateSignInKey(session.token, { challengeId, newKey: enrolled(next), authorizerSignature, subjectSignature }, ctx());
      // Each attempt consumes its challenge, so each gets a fresh one.
      await expectCode(() => attempt(sign(next, message), sign(next, message)), "invalid-signature");
      const fresh = async () => {
        const c = await service.createChallenge(name, "rotation", ctx());
        return { c, m: messageFor(c, "sign-in-key-rotation", keyPrincipal(key), keyPrincipal(next)) };
      };
      let { c, m } = await fresh();
      await expectCode(() => attempt(sign(key, m), sign(key, m), c.id), "invalid-signature");
      ({ c, m } = await fresh());
      // Signed for the login purpose's message instead: a different message.
      await expectCode(() => attempt(sign(key, c.message), sign(next, m), c.id), "invalid-signature");

      // A challenge of another username.
      const otherName = username("other");
      await register(otherName);
      const foreign = await service.createChallenge(otherName, "rotation", ctx());
      const foreignMessage = messageFor(foreign, "sign-in-key-rotation", keyPrincipal(key), keyPrincipal(next));
      await expectCode(
        () => attempt(sign(key, foreignMessage), sign(next, foreignMessage), foreign.id),
        "invalid-signature",
      );
      // A login challenge is the wrong purpose.
      const loginChallenge = await service.createChallenge(name, "login", ctx());
      await expectCode(() => attempt(sign(key, m), sign(next, m), loginChallenge.id), "invalid-purpose");
      // A spent challenge stays spent.
      await expectCode(() => attempt(sign(key, message), sign(next, message)), "challenge-consumed");

      expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([key.identifier]);
      expect(await authenticates(session.token)).toBe(true);
    });

    it("refuses the negative vectors' shapes and a small-order newKey", async () => {
      const name = username("negative");
      const { key, accountId, session } = await register(name);
      const next = newKey();
      const challenge = await service.createChallenge(name, "rotation", ctx());
      const message = messageFor(challenge, "sign-in-key-rotation", keyPrincipal(key), keyPrincipal(next));
      const good = sign(key, message);
      const L = 2n ** 252n + 27742317777372353535851937790883648493n;
      const littleEndian = (hex: string): bigint => BigInt(`0x${hex.match(/../gu)!.reverse().join("")}`);
      const toLittleEndian = (value: bigint): string => value.toString(16).padStart(64, "0").match(/../gu)!.reverse().join("");
      // The vector's two signature shapes, over this challenge: S + L (a
      // malleated valid signature) and a non-canonical R (y = p + 3).
      for (const shape of ["s-not-below-l", "non-canonical-r"] as const) {
        const c = await service.createChallenge(name, "rotation", ctx());
        const m = messageFor(c, "sign-in-key-rotation", keyPrincipal(key), keyPrincipal(next));
        const valid = sign(key, m);
        const shaped =
          shape === "s-not-below-l"
            ? valid.slice(0, 64) + toLittleEndian(littleEndian(valid.slice(64)) + L)
            : `f0${"ff".repeat(30)}7f${valid.slice(64)}`;
        await expectCode(
          () => service.rotateSignInKey(session.token, { challengeId: c.id, newKey: enrolled(next), authorizerSignature: shaped, subjectSignature: sign(next, m) }, ctx()),
          "invalid-signature",
        );
      }
      // A small-order newKey with the subject signature zip215 accepts: refused
      // before the challenge is even read.
      const smallOrder = { address: `S_01${"00".repeat(31)}`, publicKey: `S_01${"00".repeat(31)}` };
      await expectCode(
        () => service.rotateSignInKey(session.token, { challengeId: challenge.id, newKey: smallOrder, authorizerSignature: good, subjectSignature: `01${"00".repeat(63)}` }, ctx()),
        "invalid-public-key",
      );
      const nonCanonical = { address: `S_f0${"ff".repeat(30)}7f`, publicKey: `S_f0${"ff".repeat(30)}7f` };
      await expectCode(
        () => service.rotateSignInKey(session.token, { challengeId: challenge.id, newKey: nonCanonical, authorizerSignature: good, subjectSignature: good }, ctx()),
        "invalid-public-key",
      );
      // The challenge was never consumed by the refused calls.
      const result = await service.rotateSignInKey(
        session.token,
        { challengeId: challenge.id, newKey: enrolled(next), authorizerSignature: good, subjectSignature: sign(next, message) },
        ctx(),
      );
      expect(result.wallets[0]!.publicKey).toBe(next.identifier);
      expect(await auditRows(accountId, "account.key-rotate")).toHaveLength(1);
    });

    it("refuses an account with more than one enrolled key with wallet-conflict", async () => {
      const name = username("conflict");
      const { key, accountId, session } = await register(name);
      const extra = newKey();
      await first.query(
        `INSERT INTO ${prefix}_account_wallets (account_id, service_profile_id, profile_id, codec_id, curve,
           application_id, network_id, address, address_normalized, public_key, fingerprint, is_primary)
         SELECT account_id, service_profile_id, profile_id, codec_id, curve, application_id, network_id,
                $2, lower($2), $2, 'EXTRA', false
           FROM ${prefix}_account_wallets WHERE account_id = $1::uuid`,
        [accountId, extra.identifier],
      );
      await expectCode(() => rotate(name, session.token, key, newKey()), "wallet-conflict");
    });
  });

  describe("changeEmail", () => {
    async function verifiedAccount(label: string) {
      const name = username(label);
      const email = `${label}-${suffix}@example.org`;
      const started = await service.startEmailVerification({ username: name, email }, ctx());
      await service.confirmEmailVerification(started.verificationId, started.code, ctx());
      const key = newKey();
      const challenge = await service.createChallenge(name, "registration", ctx());
      const registered = await service.register(
        { username: name, email, address: key.identifier, publicKey: key.identifier, challengeId: challenge.id, signature: sign(key, challenge.message) },
        ctx(),
      );
      expect(registered.account.emailVerifiedAt).not.toBeNull();
      return { name, email, key, accountId: registered.account.id, session: registered.session };
    }

    it("clears verification and returns the previous verified address to the host only", async () => {
      const { name, email, key, accountId, session } = await verifiedAccount("email");
      const result = await changeEmail(name, session.token, key, "  New.Address@Example.ORG ");
      expect(result.account.email).toBe("new.address@example.org");
      expect(result.account.emailVerifiedAt).toBeNull();
      expect(result.previousVerifiedEmail).toBe(email);

      const audit = await auditRows(accountId, "account.email-change");
      expect(audit.map((row) => row["metadata"])).toEqual([
        {
          emailChanged: true,
          verificationCleared: true,
          emailResetDisabled: false,
          closedResets: 0,
          sessionId: session.session.id,
        },
      ]);
      expect(JSON.stringify(audit)).not.toContain("@");
      expect(eventsFor(accountId).filter((event) => event.action === "account.email-change")).toEqual([
        expect.objectContaining({ previousVerifiedEmail: email }),
      ]);

      // From an unverified address there is no previous verified one.
      const again = await changeEmail(name, session.token, key, "third@example.org");
      expect(again.previousVerifiedEmail).toBeNull();
    });

    it("keeps verification for the same address and signs the normalized subject only", async () => {
      const { name, email, key, session } = await verifiedAccount("same-email");
      const same = await changeEmail(name, session.token, key, email.toUpperCase());
      expect(same.account.emailVerifiedAt).not.toBeNull();
      expect(same.previousVerifiedEmail).toBeNull();
      // Signed for another address than the one submitted.
      await expectCode(
        () => changeEmail(name, session.token, key, "other@example.org", "different@example.org"),
        "invalid-signature",
      );
      await expectCode(
        () => service.changeEmail(session.token, { challengeId: crypto.randomUUID(), email: "not an address", authorizerSignature: "00" }, ctx()),
        "invalid-email",
      );
    });

    it("refuses an address with a control character as invalid-email, before the challenge is spent", async () => {
      const { name, key, session } = await verifiedAccount("control-email");
      const challenge = await service.createChallenge(name, "rotation", ctx());
      for (const email of ["a\u0085b@example.org", "a\u0000b@example.org", "a\u001fb@example.org"]) {
        await expectCode(
          () => service.changeEmail(session.token, { challengeId: challenge.id, email, authorizerSignature: "00".repeat(64) }, ctx()),
          "invalid-email",
        );
      }
      // The refusals left the challenge unspent: it still authorizes a change.
      const message = messageFor(challenge, "email-change", keyPrincipal(key), "email:plain@example.org");
      const changed = await service.changeEmail(
        session.token,
        { challengeId: challenge.id, email: "plain@example.org", authorizerSignature: sign(key, message) },
        ctx(),
      );
      expect(changed.account.email).toBe("plain@example.org");
    });
  });

  describe("recovery keys", () => {
    it("enrolls one active key, replaces it, is idempotent, never re-enrolls, and removes", async () => {
      const name = username("enroll");
      const { key, accountId, session } = await register(name);
      expect(await service.recoveryStatus(session.token)).toEqual({ recoveryKey: null });

      const r1 = newKey();
      const enrolled1 = await enroll(name, session.token, key, r1);
      expect(enrolled1.changed).toBe(true);
      expect(enrolled1.recoveryKey).toMatchObject({ publicKey: r1.publicKeyHex, status: "active", usedAt: null, removedAt: null });
      expect((await service.recoveryStatus(session.token)).recoveryKey?.publicKey).toBe(r1.publicKeyHex);

      // The same key again: success, nothing changed, nothing audited.
      const again = await enroll(name, session.token, key, r1);
      expect(again).toEqual({ recoveryKey: enrolled1.recoveryKey, changed: false });

      // A live token of the replaced key dies with it.
      const token1 = await begin(name, r1);
      const r2 = newKey();
      await enroll(name, session.token, key, r2);
      await expectCode(() => service.authenticateRecovery(token1.recoveryToken), "invalid-signature");
      expect((await service.recoveryStatus(session.token)).recoveryKey?.publicKey).toBe(r2.publicKeyHex);
      const keys = await first.query(
        `SELECT public_key, status FROM ${prefix}_account_recovery_keys WHERE account_id = $1::uuid ORDER BY created_at`,
        [accountId],
      );
      expect(keys.rows).toEqual([
        { public_key: r1.publicKeyHex, status: "removed" },
        { public_key: r2.publicKeyHex, status: "active" },
      ]);

      // A key this service has seen is never enrolled again.
      await expectCode(() => enroll(name, session.token, key, r1), "invalid-public-key");

      expect((await auditRows(accountId, "account.recovery-key.enroll")).map((row) => row["metadata"])).toEqual([
        { replaced: false, sessionId: session.session.id },
        { replaced: true, sessionId: session.session.id },
      ]);

      expect(await removeRecovery(name, session.token, key)).toEqual({ removed: true });
      expect(await service.recoveryStatus(session.token)).toEqual({ recoveryKey: null });
      expect(await removeRecovery(name, session.token, key)).toEqual({ removed: false });
      expect(await auditRows(accountId, "account.recovery-key.remove")).toHaveLength(1);
      expect(eventsFor(accountId).map((event) => event.action)).toEqual([
        "account.recovery-key.enroll",
        "account.recovery-begin",
        "account.recovery-key.enroll",
        "account.recovery-key.remove",
      ]);
    });

    it("keeps one active key under concurrent enrollments, of two keys or of one", async () => {
      // A holder parks both enrollments on the enrolled key's row, so both
      // take their snapshots first; the loser's insert meets the winner's row
      // in a unique index and its retry decides on a fresh snapshot.
      const trio = await openConnections(3);
      const [holder, one, two] = [trio[0]!, trio[1]!, trio[2]!];
      try {
        for (let round = 0; round < 4; round += 1) {
          const name = username(`enroll-race-${String(round)}`);
          const { key, accountId, session } = await register(name);
          const [r1, r2] = [newKey(), newKey()];
          const same = round % 2 === 1;
          // Rounds 0 and 1 start from an active key, which both try to retire.
          if (round < 2) await enroll(name, session.token, key, newKey());
          await holder.client.query("BEGIN");
          let pending: Promise<readonly Awaited<ReturnType<typeof enroll>>[]> | undefined;
          try {
            await holder.client.query(
              `SELECT 1 FROM ${prefix}_account_wallets WHERE account_id = $1::uuid FOR UPDATE`,
              [accountId],
            );
            const a = enroll(name, session.token, key, r1, one.service);
            void a.catch(() => undefined);
            await waitUntilBlocked(one.pid);
            const b = enroll(name, session.token, key, same ? r1 : r2, two.service);
            void b.catch(() => undefined);
            await waitUntilBlocked(two.pid);
            pending = Promise.all([a, b]);
          } finally {
            await holder.client.query("COMMIT");
          }
          const results = await pending!;
          const active = await first.query(
            `SELECT public_key FROM ${prefix}_account_recovery_keys WHERE account_id = $1::uuid AND status = 'active'`,
            [accountId],
          );
          expect(active.rows).toHaveLength(1);
          if (same) {
            // One inserted it; the other found it active and changed nothing.
            expect(results.map((result) => result.changed).sort()).toEqual([false, true]);
            expect(active.rows[0]?.["public_key"]).toBe(r1.publicKeyHex);
          } else {
            expect(results.every((result) => result.changed)).toBe(true);
            expect([r1.publicKeyHex, r2.publicKeyHex]).toContain(active.rows[0]?.["public_key"]);
          }
        }
      } finally {
        await closeConnections(trio);
      }
    }, 60_000);

    it("needs the enrolled key's signature and the recovery key's proof of possession", async () => {
      const name = username("enroll-proof");
      const { key, session } = await register(name);
      const recovery = newKey();
      const challenge = await service.createChallenge(name, "rotation", ctx());
      const message = messageFor(challenge, "recovery-key-enrollment", keyPrincipal(key), recoveryPrincipal(recovery));
      await expectCode(
        () => service.enrollRecoveryKey(session.token, { challengeId: challenge.id, recoveryPublicKey: recovery.publicKeyHex, authorizerSignature: sign(key, message), subjectSignature: sign(key, message) }, ctx()),
        "invalid-signature",
      );
      expect(await service.recoveryStatus(session.token)).toEqual({ recoveryKey: null });
    });

    it("begin spends nothing; a second begin revokes the first token; completion is single use", async () => {
      const name = username("recover");
      const { key, accountId, session: s0 } = await register(name);
      const s1 = await login(name, key);
      const recovery = newKey();
      await enroll(name, s0.token, key, recovery);

      const firstBegin = await begin(name, recovery);
      expect(firstBegin.accountId).toBe(accountId);
      expect(firstBegin.recoveryToken).toMatch(/^[A-Za-z0-9_-]{43}$/u);
      expect(firstBegin.expiresAt.getTime() - Date.now()).toBeGreaterThan(14 * 60_000);
      expect(firstBegin.expiresAt.getTime() - Date.now()).toBeLessThanOrEqual(15 * 60_000 + 1_000);
      // Nothing spent: the key, the sessions and the login are untouched.
      expect((await service.recoveryStatus(s0.token)).recoveryKey?.status).toBe("active");
      expect(await authenticates(s0.token)).toBe(true);
      expect(await authenticates(s1.token)).toBe(true);
      expect(await authenticates((await login(name, key)).token)).toBe(true);
      expect(await service.authenticateRecovery(firstBegin.recoveryToken)).toEqual({
        accountId,
        usernameNormalized: name.toLowerCase(),
        expiresAt: firstBegin.expiresAt,
      });
      // Only its digest is stored.
      const stored = await first.query(`SELECT token_hash FROM ${prefix}_account_recoveries WHERE account_id = $1::uuid`, [accountId]);
      expect(JSON.stringify(stored.rows)).not.toContain(firstBegin.recoveryToken);

      const secondBegin = await begin(name, recovery);
      await expectCode(() => service.authenticateRecovery(firstBegin.recoveryToken), "invalid-signature");
      await expectCode(() => complete(name, firstBegin.recoveryToken, recovery, newKey()), "invalid-signature");
      expect(await liveTokens(accountId)).toBe(1);

      const next = newKey();
      const recovered = await complete(name, secondBegin.recoveryToken, recovery, next, service, ctx({ clientLabel: "Safari on iOS" }));
      expect(recovered.account.id).toBe(accountId);
      expect(recovered.wallets.map((wallet) => wallet.publicKey)).toEqual([next.identifier]);
      // Every earlier session is revoked; the new one works.
      expect(await authenticates(s0.token)).toBe(false);
      expect(await authenticates(s1.token)).toBe(false);
      expect(recovered.revokedSessionIds.length).toBeGreaterThanOrEqual(3);
      expect(await authenticates(recovered.session.token)).toBe(true);
      expect(await loginFails(name, key)).toBe(true);
      expect(await authenticates((await login(name, next)).token)).toBe(true);

      // Single use: the token, the key and a fresh begin with the key all fail.
      await expectCode(() => complete(name, secondBegin.recoveryToken, recovery, newKey()), "invalid-signature");
      await expectCode(() => begin(name, recovery), "invalid-signature");
      const status = await service.recoveryStatus(recovered.session.token);
      expect(status.recoveryKey).toMatchObject({ publicKey: recovery.publicKeyHex, status: "used" });
      expect(status.recoveryKey?.usedAt).not.toBeNull();
      expect(await liveTokens(accountId)).toBe(0);

      const audit = await auditRows(accountId, "account.recover");
      expect(audit.map((row) => row["metadata"])).toEqual([
        { method: "recovery-key", revokedSessions: recovered.revokedSessionIds.length, sessionId: recovered.session.session.id },
      ]);
      expect((await auditRows(accountId, "account.recovery-begin")).map((row) => row["metadata"])).toEqual([
        { method: "recovery-key", supersededTokens: 0 },
        { method: "recovery-key", supersededTokens: 1 },
      ]);
      expect(eventsFor(accountId).filter((event) => event.action === "account.recover")).toEqual([
        expect.objectContaining({ clientLabel: "Safari on iOS", revokedSessions: recovered.revokedSessionIds.length }),
      ]);
      const label = await first.query(`SELECT client_label FROM ${prefix}_sessions WHERE id = $1::uuid`, [recovered.session.session.id]);
      expect(label.rows).toEqual([{ client_label: "Safari on iOS" }]);
    });

    it("answers one uniform 401 for every begin failure", async () => {
      const name = username("uniform");
      const { key, accountId, session } = await register(name);
      const recovery = newKey();
      await enroll(name, session.token, key, recovery);
      const shapes: string[] = [];
      const record = async (run: () => Promise<unknown>): Promise<void> => {
        const error = await expectCode(run, "invalid-signature");
        shapes.push(`${error.code}|${String(error.status)}|${error.message}`);
      };
      // Unknown username, no recovery key, the wrong key, a bad signature.
      await record(() => begin(username("nobody"), recovery));
      const plain = username("no-key");
      await register(plain);
      await record(() => begin(plain, recovery));
      await record(() => begin(name, newKey()));
      const challenge = await service.createChallenge(name, "rotation", ctx());
      await record(() =>
        service.beginRecovery({ username: name, challengeId: challenge.id, recoveryPublicKey: recovery.publicKeyHex, signature: sign(recovery, challenge.message) }, ctx()),
      );
      // A challenge for another username.
      const foreign = await service.createChallenge(plain, "rotation", ctx());
      const foreignMessage = messageFor(foreign, "recovery-begin", recoveryPrincipal(recovery), "none");
      await record(() =>
        service.beginRecovery({ username: name, challengeId: foreign.id, recoveryPublicKey: recovery.publicKeyHex, signature: sign(recovery, foreignMessage) }, ctx()),
      );
      // A token that is unknown or expired.
      await record(() => service.authenticateRecovery("unknown-token"));
      const issued = await begin(name, recovery);
      await record(() => service.authenticateRecovery(issued.recoveryToken, { now: new Date(issued.expiresAt.getTime() + 1) }));
      // A suspended account.
      await suspend(accountId);
      await record(() => begin(name, recovery));
      await record(() => service.authenticateRecovery(issued.recoveryToken));
      expect(new Set(shapes).size).toBe(1);
    });

    it("keeps at most one live token under concurrent begins", async () => {
      // A holder parks both begins on the recovery key's row, so both take
      // their snapshots before either inserts: the second insert then meets
      // the first token in the unique live index, and its retry revokes it.
      const trio = await openConnections(3);
      const [holder, one, two] = [trio[0]!, trio[1]!, trio[2]!];
      try {
        for (let round = 0; round < 3; round += 1) {
          const name = username(`begin-race-${String(round)}`);
          const { key, accountId, session } = await register(name);
          const recovery = newKey();
          await enroll(name, session.token, key, recovery);
          await holder.client.query("BEGIN");
          let results: Promise<readonly Awaited<ReturnType<typeof begin>>[]> | undefined;
          try {
            await holder.client.query(
              `SELECT 1 FROM ${prefix}_account_recovery_keys WHERE account_id = $1::uuid AND status = 'active' FOR UPDATE`,
              [accountId],
            );
            const a = begin(name, recovery, one.service);
            void a.catch(() => undefined);
            await waitUntilBlocked(one.pid);
            const b = begin(name, recovery, two.service);
            void b.catch(() => undefined);
            await waitUntilBlocked(two.pid);
            results = Promise.all([a, b]);
          } finally {
            await holder.client.query("COMMIT");
          }
          const issued = await results!;
          expect(await liveTokens(accountId)).toBe(1);
          const usable: string[] = [];
          for (const result of issued) {
            try {
              await service.authenticateRecovery(result.recoveryToken);
              usable.push(result.recoveryToken);
            } catch (error) {
              expect((error as IdentityError).code).toBe("invalid-signature");
            }
          }
          expect(usable).toHaveLength(1);
          expect(await auditRows(accountId, "account.recovery-begin")).toHaveLength(2);
        }
      } finally {
        await closeConnections(trio);
      }
    }, 60_000);

    it("lets exactly one of two concurrent completions win", async () => {
      for (let round = 0; round < 6; round += 1) {
        const name = username(`complete-race-${String(round)}`);
        const { key, accountId, session } = await register(name);
        const recovery = newKey();
        await enroll(name, session.token, key, recovery);
        const issued = await begin(name, recovery);
        const [a, b] = [newKey(), newKey()];
        const settled = await Promise.allSettled([
          complete(name, issued.recoveryToken, recovery, a, service),
          complete(name, issued.recoveryToken, recovery, b, otherService),
        ]);
        expect(settled.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
        const loser = settled.find((outcome) => outcome.status === "rejected") as PromiseRejectedResult;
        expect((loser.reason as IdentityError).code).toBe("invalid-signature");
        expect(await auditRows(accountId, "account.recover")).toHaveLength(1);
        const winner = settled[0]!.status === "fulfilled" ? a : b;
        expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([winner.identifier]);
      }
    }, 60_000);

    it("refuses an unchanged key at completion and spends nothing", async () => {
      const name = username("complete-same");
      const { key, session } = await register(name);
      const recovery = newKey();
      await enroll(name, session.token, key, recovery);
      const issued = await begin(name, recovery);
      await expectCode(() => complete(name, issued.recoveryToken, recovery, key), "key-unchanged");
      await expectCode(
        () => complete(name, issued.recoveryToken, recovery, { ...newKey(), identifier: `S_01${"00".repeat(31)}` }),
        "invalid-public-key",
      );
      expect((await service.authenticateRecovery(issued.recoveryToken)).usernameNormalized).toBe(name.toLowerCase());
    });

    it("refuses a token of an overlapping begin once its key is retired, whichever call retired it", async () => {
      // A begin holds the account and the recovery key FOR SHARE while a
      // holder parks it on the earlier token; the retirement then waits on the
      // key behind it. Its token UPDATE runs on a snapshot taken before the
      // begin committed, so it cannot see (or stamp) the begin's new token.
      // The key gate is what makes that token unusable: every reader of a
      // token joins its key as `active`.
      const trio = await openConnections(3);
      const [holder, one, two] = [trio[0]!, trio[1]!, trio[2]!];
      try {
        for (const variant of ["revokeRecoveryKeys", "removeRecoveryKey", "enrollRecoveryKey"] as const) {
          const name = username(`retire-race-${variant}`);
          const { key, accountId, session } = await register(name);
          const recovery = newKey();
          await enroll(name, session.token, key, recovery);
          await begin(name, recovery);

          let retire: () => Promise<unknown>;
          if (variant === "revokeRecoveryKeys") {
            retire = () => two.service.revokeRecoveryKeys(accountId);
          } else if (variant === "removeRecoveryKey") {
            const challenge = await service.createChallenge(name, "rotation", ctx());
            const message = messageFor(challenge, "recovery-key-removal", keyPrincipal(key), "none");
            retire = () =>
              two.service.removeRecoveryKey(
                session.token,
                { challengeId: challenge.id, authorizerSignature: sign(key, message) },
                ctx(),
              );
          } else {
            const replacement = newKey();
            retire = () => enroll(name, session.token, key, replacement, two.service);
          }

          await holder.client.query("BEGIN");
          let second: Promise<Awaited<ReturnType<typeof begin>>> | undefined;
          let retiring: Promise<unknown> | undefined;
          try {
            await holder.client.query(
              `SELECT 1 FROM ${prefix}_account_recoveries WHERE account_id = $1::uuid FOR UPDATE`,
              [accountId],
            );
            second = begin(name, recovery, one.service);
            void second.catch(() => undefined);
            await waitUntilBlocked(one.pid);
            retiring = retire();
            void retiring.catch(() => undefined);
            await waitUntilBlocked(two.pid);
          } finally {
            await holder.client.query("COMMIT");
          }
          const issued = await second!;
          await retiring!;

          const keys = await first.query(
            `SELECT public_key, status FROM ${prefix}_account_recovery_keys WHERE account_id = $1::uuid`,
            [accountId],
          );
          expect(keys.rows.find((row) => row["public_key"] === recovery.publicKeyHex)?.["status"]).toBe("removed");
          // No token the service would honour: none is live for an active key.
          const usable = await first.query(
            `SELECT count(*)::int AS usable
               FROM ${prefix}_account_recoveries r
               JOIN ${prefix}_account_recovery_keys k ON k.id = r.recovery_key_id AND k.status = 'active'
              WHERE r.account_id = $1::uuid AND r.completed_at IS NULL AND r.revoked_at IS NULL`,
            [accountId],
          );
          expect(usable.rows[0]?.["usable"]).toBe(0);
          await expectCode(() => service.authenticateRecovery(issued.recoveryToken), "invalid-signature");
          await expectCode(() => complete(name, issued.recoveryToken, recovery, newKey()), "invalid-signature");
          expect(await authenticates(session.token)).toBe(true);
          expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([key.identifier]);
        }
      } finally {
        await closeConnections(trio);
      }
    }, 60_000);

    it("revokeRecoveryKeys removes the active key and its token, on a suspended account too", async () => {
      const name = username("revoke-keys");
      const { key, accountId, session } = await register(name);
      const recovery = newKey();
      await enroll(name, session.token, key, recovery);
      const issued = await begin(name, recovery);
      await suspend(accountId);
      expect(await service.revokeRecoveryKeys(accountId.toUpperCase())).toBe(1);
      expect(await service.revokeRecoveryKeys(accountId)).toBe(0);
      expect(await liveTokens(accountId)).toBe(0);
      await expectCode(() => service.authenticateRecovery(issued.recoveryToken), "invalid-signature");
      const status = await first.query(`SELECT status, removed_at FROM ${prefix}_account_recovery_keys WHERE account_id = $1::uuid`, [accountId]);
      expect(status.rows[0]?.["status"]).toBe("removed");
      expect((await auditRows(accountId, "account.recovery-key.revoke")).map((row) => row["metadata"])).toEqual([
        { revoked: 1, revokedTokens: 1 },
        { revoked: 0, revokedTokens: 0 },
      ]);
      expect(eventsFor(accountId).filter((event) => event.action === "account.recovery-key.revoke")).toHaveLength(1);
      await expectCode(() => service.revokeRecoveryKeys(crypto.randomUUID()), "account-not-found");
      await expectCode(() => service.revokeRecoveryKeys("not-a-uuid"), "account-not-found");
    });
  });

  describe("the status rule", () => {
    it("refuses every operation of a suspended account", async () => {
      const name = username("suspended");
      const { key, accountId, session } = await register(name);
      const recovery = newKey();
      await enroll(name, session.token, key, recovery);
      const issued = await begin(name, recovery);
      await suspend(accountId);
      const refusals = [
        () => rotate(name, session.token, key, newKey()),
        () => changeEmail(name, session.token, key, "suspended@example.org"),
        () => enroll(name, session.token, key, newKey()),
        () => removeRecovery(name, session.token, key),
        () => service.recoveryStatus(session.token),
        () => service.listSecurityEvents(session.token),
        () => begin(name, recovery),
        () => service.authenticateRecovery(issued.recoveryToken),
        () => complete(name, issued.recoveryToken, recovery, newKey()),
      ];
      for (const run of refusals) {
        const error = await expectCode(run, "invalid-signature");
        expect(error.status).toBe(401);
      }
      expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([key.identifier]);
    });

    it("refuses a suspension that commits while a change waits, under the account lock", async () => {
      const name = username("suspend-race");
      const { key, accountId, session } = await register(name);
      const [holder] = await openConnections(1);
      try {
        await holder!.client.query("BEGIN");
        await holder!.client.query(`UPDATE ${prefix}_accounts SET status = 'suspended' WHERE id = $1::uuid`, [accountId]);
        // The read before the statement still sees an active account; the
        // statement's FOR SHARE then waits for the suspension and re-checks.
        const rotation = rotate(name, session.token, key, newKey(), otherService);
        void rotation.catch(() => undefined);
        await waitUntilBlocked(secondPid);
        await holder!.client.query("COMMIT");
        await expectCode(() => rotation, "invalid-signature");
      } finally {
        await closeConnections([holder!]);
      }
      expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([key.identifier]);
    });
  });

  describe("listSecurityEvents", () => {
    it("lists the last 20 events with action, time and the acting session's label, nothing else", async () => {
      const name = username("events");
      const { key, accountId, session } = await register(name, service, ctx({ clientLabel: "Chrome on Linux" }));
      for (let index = 0; index < 22; index += 1) {
        await login(name, key, service, ctx({ clientLabel: index === 21 ? "Edge on Windows" : "Firefox on macOS" }));
      }
      const events_ = await service.listSecurityEvents(session.token);
      expect(events_).toHaveLength(20);
      for (const event of events_) {
        expect(Object.keys(event).sort()).toEqual(["action", "clientLabel", "createdAt", "id"]);
      }
      expect(events_[0]).toMatchObject({ action: "account.login", clientLabel: "Edge on Windows" });
      const times = events_.map((event) => event.createdAt.getTime());
      expect([...times].sort((a, b) => b - a)).toEqual(times);

      // A label goes with its session row.
      const revokedLater = await login(name, key, service, ctx({ clientLabel: "Opera on Android" }));
      await service.revokeSession(revokedLater.token);
      expect((await service.listSecurityEvents(session.token))[0]).toMatchObject({ action: "session.revoke", clientLabel: "Opera on Android" });
      await service.pruneExpired();
      expect((await service.listSecurityEvents(session.token))[0]).toMatchObject({ action: "session.revoke", clientLabel: null });

      // Another account's token sees only its own events.
      const other = await register(username("events-other"));
      const theirs = await service.listSecurityEvents(other.session.token);
      expect(theirs.map((event) => event.action)).toEqual(["account.register"]);
      expect((await first.query(`SELECT count(*)::int AS n FROM ${prefix}_audit_events WHERE account_id = $1::uuid`, [accountId])).rows[0]?.["n"]).toBeGreaterThan(20);
    });
  });

  describe("pruneExpired", () => {
    it("deletes recovery tokens a day after they expire, and audit rows only with a retention", async () => {
      const name = username("prune");
      const { key, accountId, session } = await register(name);
      const recovery = newKey();
      await enroll(name, session.token, key, recovery);
      const issued = await begin(name, recovery);
      const justAfter = await service.pruneExpired({ now: new Date(issued.expiresAt.getTime() + 60_000) });
      expect(justAfter.recoveryTokens).toBe(0);
      expect(justAfter.auditEvents).toBe(0);
      const dayAfter = await service.pruneExpired({ now: new Date(issued.expiresAt.getTime() + 86_400_000 + 1) });
      expect(dayAfter.recoveryTokens).toBeGreaterThanOrEqual(1);
      expect(await liveTokens(accountId)).toBe(0);

      // Without auditRetentionDays nothing is deleted, however old.
      const far = new Date(Date.now() + 400 * 86_400_000);
      expect((await service.pruneExpired({ now: far })).auditEvents).toBe(0);
      // With it, account.* and session.* rows older than the window go; others stay.
      await first.query(
        `INSERT INTO ${prefix}_audit_events (account_id, action, metadata) VALUES ($1::uuid, 'email.verified', '{}'::jsonb)`,
        [accountId],
      );
      const retaining = createIdentityService(pgDriver(first), config(prefix, { auditRetentionDays: 395 }));
      expect((await retaining.pruneExpired({ now: new Date(Date.now() + 394 * 86_400_000) })).auditEvents).toBe(0);
      expect((await retaining.pruneExpired({ now: far })).auditEvents).toBeGreaterThan(0);
      const left = await first.query(`SELECT action FROM ${prefix}_audit_events WHERE account_id = $1::uuid`, [accountId]);
      expect(left.rows.map((row) => row["action"])).toEqual(["email.verified"]);
    });

    it("never prunes an audit row that names no account, which no service profile owns", async () => {
      // account_id is ON DELETE SET NULL and the table has no service profile
      // column, so a deleted account's rows cannot be attributed to the
      // service whose retention runs; another service on the prefix may own
      // them, or keep its audit rows forever.
      const orphan = await first.query(
        `INSERT INTO ${prefix}_audit_events (account_id, action, metadata, created_at)
         VALUES (NULL, 'account.login', '{}'::jsonb, now() - interval '1000 days') RETURNING id`,
      );
      const orphanId = orphan.rows[0]?.["id"];
      const retaining = createIdentityService(pgDriver(first), config(prefix, { auditRetentionDays: 1 }));
      await retaining.pruneExpired({ now: new Date(Date.now() + 2 * 86_400_000) });
      const kept = await first.query(`SELECT 1 FROM ${prefix}_audit_events WHERE id = $1::uuid`, [orphanId]);
      expect(kept.rows).toHaveLength(1);
      await first.query(`DELETE FROM ${prefix}_audit_events WHERE id = $1::uuid`, [orphanId]);
    });
  });

  describe("onSecurityEvent", () => {
    it("is called after the commit, and a failing or slow hook never fails the change", async () => {
      const seen: { action: string; committed: boolean }[] = [];
      const observing = createIdentityService(
        pgDriver(first),
        config(prefix, {
          onSecurityEvent: async (event) => {
            // Read from another connection: only a committed change is visible there.
            const rows = await second.query(
              `SELECT count(*)::int AS n FROM ${prefix}_audit_events WHERE account_id = $1::uuid AND action = $2`,
              [event.accountId, event.action],
            );
            seen.push({ action: event.action, committed: Number(rows.rows[0]?.["n"]) > 0 });
          },
        }),
      );
      const name = username("hook");
      const { key, session } = await register(name);
      await rotate(name, session.token, key, newKey(), observing);
      expect(seen).toEqual([{ action: "account.key-rotate", committed: true }]);

      const failing = createIdentityService(
        pgDriver(first),
        config(prefix, {
          onSecurityEvent: () => {
            throw new Error("notice provider down");
          },
        }),
      );
      const name2 = username("hook-fail");
      const registered = await register(name2);
      await expect(rotate(name2, registered.session.token, registered.key, newKey(), failing)).resolves.toBeDefined();

      const hanging = createIdentityService(
        pgDriver(first),
        config(prefix, { onSecurityEvent: () => new Promise<void>(() => undefined) }),
      );
      const name3 = username("hook-hang");
      const third = await register(name3);
      const started = Date.now();
      await expect(rotate(name3, third.session.token, third.key, newKey(), hanging)).resolves.toBeDefined();
      const elapsed = Date.now() - started;
      expect(elapsed).toBeGreaterThanOrEqual(2_900);
      expect(elapsed).toBeLessThan(6_000);
    }, 30_000);

    it("reports revoke-others only when it revoked something", async () => {
      const name = username("hook-others");
      const { key, accountId, session } = await register(name);
      await service.revokeOtherSessions(session.token);
      expect(eventsFor(accountId).filter((event) => event.action === "session.revoke-others")).toHaveLength(0);
      await login(name, key);
      await service.revokeOtherSessions(session.token);
      expect(eventsFor(accountId).filter((event) => event.action === "session.revoke-others")).toEqual([
        expect.objectContaining({ revokedSessions: 1 }),
      ]);
    });
  });

  describe("rate limits", () => {
    it("bounds account changes at 10 per 5 minutes per caller and account, recovery completion included", async () => {
      const name = username("rate");
      const { key, accountId, session } = await register(name);
      const sameCaller = { ipHash: `rate-${suffix}` };
      for (let attempt = 0; attempt < 10; attempt += 1) {
        await expectCode(
          () => service.rotateSignInKey(session.token, { challengeId: crypto.randomUUID(), newKey: enrolled(newKey()), authorizerSignature: "00", subjectSignature: "00" }, sameCaller),
          "challenge-not-found",
        );
      }
      const limited = await expectCode(
        () => service.rotateSignInKey(session.token, { challengeId: crypto.randomUUID(), newKey: enrolled(newKey()), authorizerSignature: "00", subjectSignature: "00" }, sameCaller),
        "rate-limited",
      );
      expect(limited.details?.["rule"]).toBe("account-change");
      // The same bucket counts every change of this account from this caller.
      const recovery = newKey();
      await expectCode(
        () => service.enrollRecoveryKey(session.token, { challengeId: crypto.randomUUID(), recoveryPublicKey: recovery.publicKeyHex, authorizerSignature: "00", subjectSignature: "00" }, sameCaller),
        "rate-limited",
      );
      // ...and a recovery completion for the account.
      await enroll(name, session.token, key, recovery);
      const issued = await begin(name, recovery);
      await expectCode(() => complete(name, issued.recoveryToken, recovery, newKey(), service, sameCaller), "rate-limited");
      // Another caller is not affected.
      expect((await rotate(name, session.token, key, newKey())).wallets).toHaveLength(1);
      expect(accountId).toBeTruthy();
    });

    it("bounds recovery begins at 5 per hour per caller and username, and 20 per caller", async () => {
      const name = username("rate-begin");
      const { key, session } = await register(name);
      const recovery = newKey();
      await enroll(name, session.token, key, recovery);
      const caller = { ipHash: `begin-${suffix}` };
      for (let attempt = 0; attempt < 5; attempt += 1) {
        await expectCode(
          () => service.beginRecovery({ username: name, challengeId: crypto.randomUUID(), recoveryPublicKey: recovery.publicKeyHex, signature: "00" }, caller),
          "challenge-not-found",
        );
      }
      const limited = await expectCode(() => begin(name, recovery, service, caller), "rate-limited");
      expect(limited.details?.["rule"]).toBe("recovery-begin");

      const spray = { ipHash: `spray-${suffix}` };
      for (let attempt = 0; attempt < 20; attempt += 1) {
        await expectCode(
          () => service.beginRecovery({ username: username(`spray-${String(attempt)}`), challengeId: crypto.randomUUID(), recoveryPublicKey: recovery.publicKeyHex, signature: "00" }, spray),
          "challenge-not-found",
        );
      }
      const sprayed = await expectCode(
        () => service.beginRecovery({ username: username("spray-last"), challengeId: crypto.randomUUID(), recoveryPublicKey: recovery.publicKeyHex, signature: "00" }, spray),
        "rate-limited",
      );
      expect(sprayed.details?.["rule"]).toBe("recovery-begin-ip");
    });
  });

  describe("lock order", () => {
    it("rotation and recovery hold the account FOR SHARE and lock sessions in id order, never the caller's", async () => {
      const pair = await openConnections(2);
      const holder = pair[0]!;
      const actor = pair[1]!;
      try {
        for (const variant of ["rotation", "recovery"] as const) {
          const name = username(`lock-${variant}`);
          const { key, accountId, session: caller } = await register(name);
          const recovery = newKey();
          if (variant === "recovery") await enroll(name, caller.token, key, recovery);
          const issued = variant === "recovery" ? await begin(name, recovery) : null;
          const others: IssuedSession[] = [];
          for (let index = 0; index < 15; index += 1) others.push(await login(name, key));
          const targets = (variant === "rotation" ? others : [caller, ...others]).map((s) => s.session.id).sort();
          const middle = Math.floor(targets.length / 2);
          const blocker = targets[middle]!;

          await holder.client.query("BEGIN");
          let change: Promise<readonly string[]> | undefined;
          try {
            await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [blocker]);
            change =
              variant === "rotation"
                ? rotate(name, caller.token, key, newKey(), actor.service).then((result) => result.revokedSessionIds)
                : complete(name, issued!.recoveryToken, recovery, newKey(), actor.service).then((result) => result.revokedSessionIds);
            void change.catch(() => undefined);
            await waitUntilBlocked(actor.pid);

            const unlocked = await first.query(
              `SELECT id FROM ${prefix}_sessions WHERE account_id = $1::uuid FOR SHARE SKIP LOCKED`,
              [accountId],
            );
            const unlockedIds = new Set(unlocked.rows.map((row) => String(row["id"])));
            const all = [caller, ...others].map((s) => s.session.id);
            const held = all.filter((id) => id !== blocker && !unlockedIds.has(id)).sort();
            expect(held).toEqual(targets.slice(0, middle));
            if (variant === "rotation") expect(unlockedIds.has(caller.session.id)).toBe(true);

            // The account row is held FOR SHARE: a revoke-others audit insert's
            // FOR KEY SHARE passes, an update's FOR NO KEY UPDATE does not.
            await first.query(`SELECT 1 FROM ${prefix}_accounts WHERE id = $1::uuid FOR KEY SHARE NOWAIT`, [accountId]);
            await expect(
              first.query(`SELECT 1 FROM ${prefix}_accounts WHERE id = $1::uuid FOR NO KEY UPDATE NOWAIT`, [accountId]),
            ).rejects.toMatchObject({ code: "55P03" });
            // The enrolled key was locked before any session.
            await expect(
              first.query(`SELECT 1 FROM ${prefix}_account_wallets WHERE account_id = $1::uuid FOR KEY SHARE NOWAIT`, [accountId]),
            ).rejects.toMatchObject({ code: "55P03" });
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
      // Orchestrated, so the interleaving is the dangerous one every time:
      //   1. a holder locks session X;
      //   2. revoke-others (caller B) locks the sessions below X and waits on X;
      //   3. the change takes its account lock and the enrolled key, then waits
      //      on a session revoke-others holds;
      //   4. the holder commits; revoke-others locks the rest and inserts its
      //      audit row, whose foreign key takes FOR KEY SHARE on the account.
      // Had step 3 taken the account FOR UPDATE, step 4 would wait on it while
      // the change waits on revoke-others: PostgreSQL 40P01. With FOR SHARE the
      // audit insert passes and both statements commit.
      const trio = await openConnections(3);
      const [holder, revoker, actor] = [trio[0]!, trio[1]!, trio[2]!];
      try {
        for (const variant of ["rotation", "recovery"] as const) {
          const name = username(`cycle-${variant}`);
          const { key, session: a } = await register(name);
          const recovery = newKey();
          if (variant === "recovery") await enroll(name, a.token, key, recovery);
          const issued = variant === "recovery" ? await begin(name, recovery) : null;
          const sessions: IssuedSession[] = [a];
          for (let index = 0; index < 12; index += 1) sessions.push(await login(name, key));
          // B is the smallest id but A's, so the change's first target that
          // revoke-others also targets is held by revoke-others.
          const sorted = [...sessions.slice(1)].sort((x, y) => (x.session.id < y.session.id ? -1 : 1));
          const b = sorted[0]!;
          const others = sorted.slice(1);
          const blocker = others[Math.floor(others.length / 2)]!.session.id;

          await holder.client.query("BEGIN");
          let revocation: Promise<readonly string[]> | undefined;
          let change: Promise<readonly string[]> | undefined;
          try {
            await holder.client.query(`SELECT 1 FROM ${prefix}_sessions WHERE id = $1::uuid FOR UPDATE`, [blocker]);
            revocation = revoker.service.revokeOtherSessions(b.token).then((result) => result.revokedSessionIds);
            void revocation.catch(() => undefined);
            await waitUntilBlocked(revoker.pid);
            change =
              variant === "rotation"
                ? rotate(name, a.token, key, newKey(), actor.service).then((result) => result.revokedSessionIds)
                : complete(name, issued!.recoveryToken, recovery, newKey(), actor.service).then((result) => result.revokedSessionIds);
            void change.catch(() => undefined);
            await waitUntilBlocked(actor.pid);
          } finally {
            await holder.client.query("COMMIT");
          }
          const [revoked, changed] = await Promise.all([revocation!, change!]);
          // Each row is revoked once, by whichever statement locked it first.
          expect(new Set([...revoked, ...changed]).size).toBe(revoked.length + changed.length);
          expect(changed).toContain(b.session.id);
          expect(await authenticates(b.token)).toBe(false);
        }
      } finally {
        await closeConnections(trio);
      }
    }, 60_000);

    it("never deadlocks with revoke-others, authenticate and login traffic", async () => {
      // Rotation and recovery must not close a lock cycle with revoke-others
      // (sessions in id order, then the account FOR KEY SHARE through the
      // audit insert), revoke-all, authenticate (one session row) or login
      // (inserts). Anything but a legal refusal fails.
      const lanes = 8;
      const connections = await openConnections(lanes);
      const legal: ReadonlySet<string> = new Set(["session-not-found", "stale-key", "invalid-signature"]);
      const unexpected: unknown[] = [];
      const settle = async (work: Promise<unknown>): Promise<void> => {
        try {
          await work;
        } catch (error) {
          if (!(error instanceof IdentityError && legal.has(error.code))) unexpected.push(error);
        }
      };
      try {
        for (let round = 0; round < 24; round += 1) {
          const viaRecovery = round % 2 === 1;
          const name = username(`stress-${String(round)}`);
          const { key, accountId, session: s0 } = await register(name);
          const recovery = newKey();
          if (viaRecovery) await enroll(name, s0.token, key, recovery);
          const issued = viaRecovery ? await begin(name, recovery) : null;
          const sessions: IssuedSession[] = [s0];
          while (sessions.length < 18) {
            sessions.push(...(await Promise.all(connections.map((connection) => login(name, key, connection.service)))));
          }
          const next = newKey();
          const change: Promise<unknown> = viaRecovery
            ? complete(name, issued!.recoveryToken, recovery, next, connections[0]!.service)
            : rotate(name, s0.token, key, next, connections[0]!.service);
          let changed = false;
          const work: Promise<unknown>[] = [change.then(() => { changed = true; })];
          for (let index = 1; index <= 3; index += 1) {
            work.push(connections[index]!.service.revokeOtherSessions(sessions[index]!.token));
          }
          work.push(connections[4]!.service.revokeAllSessions(accountId));
          for (const lane of [5, 6]) {
            work.push(
              (async () => {
                for (let index = 4 + lane - 5; index < sessions.length; index += 2) {
                  await settle(connections[lane]!.service.authenticate(sessions[index]!.token));
                }
              })(),
            );
          }
          work.push(login(name, key, connections[7]!.service), login(name, key, connections[7]!.service));
          await Promise.all(work.map(settle));
          expect(unexpected).toEqual([]);
          // A recovery always lands; a rotation may find its own session
          // already revoked by the operator or a revoke-others.
          if (viaRecovery) expect(changed).toBe(true);
          expect((await service.listWallets(accountId)).map((wallet) => wallet.publicKey)).toEqual([
            (changed ? next : key).identifier,
          ]);
        }
      } finally {
        await closeConnections(connections);
      }
    }, 180_000);
  });
});
