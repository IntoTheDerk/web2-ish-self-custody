import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { afterAll, describe, expect, it } from "vitest";
import { zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import { withDerivedWallet } from "../../src/index.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import { runIdentityMigrations } from "../../src/server/migrations.js";
import {
  provisionPlatformSalt,
  readPlatformSalt,
} from "../../src/server/serviceProfile.js";
import { createIdentityService } from "../../src/server/service.js";
import { pgDriver, type SqlDriver } from "../../src/server/sql.js";
import type { IdentityServiceConfig } from "../../src/server/types.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * Adopting an existing deployment's public salt is the one irreversible step in
 * consolidating separate identity stores: the salt IS the wallet namespace, so
 * getting it wrong silently reassigns every existing user to an address they
 * cannot reach. These tests pin the guarantees that make the cutover safe.
 */
const connectionString = process.env["W2SC_TEST_DATABASE_URL"];

const profile = zeraEd25519ExternalSalt;
const applicationId = "existing-service";
const networkId = "zera-testnet";
const derivationTimeoutMs = 120_000;

type PgLikeClient = Readonly<{
  query: (
    text: string,
    params?: readonly unknown[],
  ) => Promise<{ rows: Record<string, unknown>[] }>;
  connect?: () => Promise<unknown>;
  end?: () => Promise<unknown>;
}>;

type PgLikeConstructor = new (options: { connectionString: string }) => PgLikeClient;

async function importOptional(specifier: string): Promise<Record<string, unknown> | null> {
  try {
    return (await import(/* @vite-ignore */ specifier)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function namedExport(loaded: Record<string, unknown>, name: string): unknown {
  const direct = loaded[name];
  if (direct !== undefined) {
    return direct;
  }
  const fallback = loaded["default"];
  if (typeof fallback === "object" && fallback !== null) {
    return (fallback as Record<string, unknown>)[name];
  }
  return undefined;
}

async function openClient(url: string): Promise<PgLikeClient | null> {
  const specifiers = [process.env["W2SC_TEST_PG_MODULE"], "pg"].filter(
    (specifier): specifier is string => specifier !== undefined && specifier.length > 0,
  );
  for (const specifier of specifiers) {
    const pg = await importOptional(specifier);
    if (pg === null) {
      continue;
    }
    const clientCtor = namedExport(pg, "Client");
    if (typeof clientCtor === "function") {
      const client = new (clientCtor as PgLikeConstructor)({ connectionString: url });
      await client.connect?.();
      return client;
    }
  }
  return null;
}

const client =
  connectionString === undefined || connectionString.length === 0
    ? null
    : await openClient(connectionString);

function randomSuffix(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const createdPrefixes: string[] = [];

function configFor(
  prefix: string,
  adoptPublicSaltHex?: string,
): IdentityServiceConfig {
  const base = {
    serviceProfileId: `w2sc-adopt-${prefix.slice(-8)}`,
    profile,
    applicationId,
    networkId,
    tablePrefix: prefix,
  } as const;
  return adoptPublicSaltHex === undefined ? base : { ...base, adoptPublicSaltHex };
}

function newPrefix(): string {
  const prefix = `w2sca${randomSuffix()}`;
  createdPrefixes.push(prefix);
  return prefix;
}

async function storedSaltHex(sql: SqlDriver, prefix: string): Promise<string> {
  const rows = await sql.query<{ salt: string }>(
    `SELECT encode(public_salt, 'hex') AS salt FROM ${prefix}_service_profiles`,
  );
  const row = rows[0];
  if (row === undefined) {
    throw new Error("service profile row is missing");
  }
  return row.salt;
}

afterAll(async () => {
  if (client === null) {
    return;
  }
  for (const prefix of createdPrefixes) {
    for (const table of [
      "audit_events",
      "rate_limits",
      "email_verifications",
      "sessions",
      "auth_challenges",
      "account_wallets",
      "accounts",
      "service_profile_bootstrap",
      "service_profiles",
      "schema_migrations",
    ]) {
      await client.query(`DROP TABLE IF EXISTS ${prefix}_${table} CASCADE`);
    }
    await client.query(
      `DROP FUNCTION IF EXISTS ${prefix}_reject_immutable_mutation() CASCADE`,
    );
  }
  await client.end?.();
});

describe.skipIf(client === null)("adopting an existing public salt", () => {
  const sql = pgDriver(client as PgLikeClient);
  // A salt standing in for one exported from an existing production service.
  const inheritedSalt = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

  it("provisions exactly the adopted salt rather than minting one", async () => {
    const prefix = newPrefix();
    await runIdentityMigrations(sql, resolveIdentityServiceConfig(configFor(prefix, inheritedSalt)));

    expect(await storedSaltHex(sql, prefix)).toBe(inheritedSalt);
  });

  it("is idempotent when re-run with the same adopted salt", async () => {
    const prefix = newPrefix();
    const config = resolveIdentityServiceConfig(configFor(prefix, inheritedSalt));

    const first = await runIdentityMigrations(sql, config);
    const second = await runIdentityMigrations(sql, config);

    expect(first).toEqual([1, 2, 3, 4]);
    expect(second).toEqual([]);
    expect(await storedSaltHex(sql, prefix)).toBe(inheritedSalt);
  });

  it("refuses to continue when a different salt is already provisioned", async () => {
    const prefix = newPrefix();
    await runIdentityMigrations(sql, resolveIdentityServiceConfig(configFor(prefix, inheritedSalt)));

    // Simulate an operator re-pointing the deployment at the wrong exported
    // salt. Silently ignoring this is exactly how a namespace gets orphaned.
    const wrongSalt = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    await sql.query(`DELETE FROM ${prefix}_schema_migrations WHERE version = 1`);

    await expect(
      runIdentityMigrations(sql, resolveIdentityServiceConfig(configFor(prefix, wrongSalt))),
    ).rejects.toThrow(/different public salt/u);

    expect(await storedSaltHex(sql, prefix)).toBe(inheritedSalt);
  });

  it("keeps the provisioned salt immutable against update, delete, and truncate", async () => {
    const prefix = newPrefix();
    await runIdentityMigrations(sql, resolveIdentityServiceConfig(configFor(prefix, inheritedSalt)));

    await expect(
      sql.query(
        `UPDATE ${prefix}_service_profiles SET public_salt = decode($1, 'hex')`,
        [bytesToHex(crypto.getRandomValues(new Uint8Array(32)))],
      ),
    ).rejects.toThrow(/immutable/u);
    await expect(sql.query(`DELETE FROM ${prefix}_service_profiles`)).rejects.toThrow(
      /immutable/u,
    );
    // A bare TRUNCATE never reaches the trigger: the accounts foreign key
    // rejects it first. CASCADE is the variant that gets past the key, and it
    // is the trigger that has to stop it.
    await expect(sql.query(`TRUNCATE ${prefix}_service_profiles`)).rejects.toThrow(
      /foreign key/u,
    );
    await expect(
      sql.query(`TRUNCATE ${prefix}_service_profiles CASCADE`),
    ).rejects.toThrow(/immutable/u);

    expect(await storedSaltHex(sql, prefix)).toBe(inheritedSalt);
  });

  it("mints a fresh non-zero salt when nothing is adopted", async () => {
    const prefix = newPrefix();
    await runIdentityMigrations(sql, resolveIdentityServiceConfig(configFor(prefix)));

    const minted = await storedSaltHex(sql, prefix);
    expect(minted).toMatch(/^[0-9a-f]{64}$/u);
    expect(minted).not.toBe("0".repeat(64));
    expect(minted).not.toBe(inheritedSalt);
  });

  it("converges when several runners migrate the same namespace at once", async () => {
    // Serverless deployments cold-start in parallel, so concurrent migration is
    // the normal case, not an edge case. Every DDL step here has to tolerate a
    // peer having just done it: `CREATE EXTENSION IF NOT EXISTS` is
    // check-then-act and raises a unique violation on pg_extension, and
    // `CREATE TRIGGER` has no IF NOT EXISTS at all.
    const prefix = newPrefix();
    const config = resolveIdentityServiceConfig(configFor(prefix, inheritedSalt));

    // Separate connections: one client would serialize the statements and
    // prove nothing.
    const clients = await Promise.all(
      Array.from({ length: 4 }, () => openClient(connectionString as string)),
    );
    const live = clients.filter((each): each is PgLikeClient => each !== null);
    expect(live.length).toBe(4);

    try {
      const outcomes = await Promise.allSettled(
        live.map((each) => runIdentityMigrations(pgDriver(each), config)),
      );
      const rejected = outcomes.filter((each) => each.status === "rejected");
      expect(
        rejected.map((each) => String((each as PromiseRejectedResult).reason)),
      ).toEqual([]);

      // Exactly one profile row, holding the adopted salt.
      const rows = await sql.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM ${prefix}_service_profiles`,
      );
      expect(rows[0]?.count).toBe("1");
      expect(await storedSaltHex(sql, prefix)).toBe(inheritedSalt);

      // Every immutability trigger landed exactly once.
      const triggers = await sql.query<{ count: string }>(
        `SELECT count(*)::text AS count FROM pg_trigger
          WHERE NOT tgisinternal
            AND tgrelid IN (
              ${`'${prefix}_service_profiles'::regclass`},
              ${`'${prefix}_service_profile_bootstrap'::regclass`}
            )`,
      );
      expect(triggers[0]?.count).toBe("4");
    } finally {
      await Promise.all(live.map((each) => each.end?.()));
    }
  });

  it(
    "reproduces the exact wallet an existing user already derived",
    async () => {
      const prefix = newPrefix();
      const config = configFor(prefix, inheritedSalt);
      const service = createIdentityService(sql, config);
      await service.migrate();

      const username = `legacy-user-${randomSuffix()}`;
      const password = new TextEncoder().encode("correct horse battery staple etc");

      // What the user's wallet was before consolidation: derived against the
      // salt the old deployment issued.
      const legacyAddress = await withDerivedWallet(
        {
          profile,
          username,
          password: Uint8Array.from(password),
          context: { applicationId, networkId },
          salt: hexToBytes(inheritedSalt),
        },
        (wallet) => wallet.identity.address,
      );

      // What the consolidated service now publishes.
      const published = await service.derivationProfile();
      expect(published.publicSaltHex).toBe(inheritedSalt);

      const challenge = await service.createChallenge(username, "registration");
      const proof = await withDerivedWallet(
        {
          profile,
          username,
          password: Uint8Array.from(password),
          context: { applicationId, networkId },
          salt: hexToBytes(published.publicSaltHex),
        },
        (wallet) => ({
          address: wallet.identity.address,
          publicKey: wallet.identity.publicKey,
          signature: bytesToHex(
            wallet.signExactMessageUnsafe(new TextEncoder().encode(challenge.message)),
          ),
        }),
      );

      // The whole point: the same credentials still produce the same wallet.
      expect(proof.address).toBe(legacyAddress);

      const registered = await service.register({
        username,
        address: proof.address,
        publicKey: proof.publicKey,
        challengeId: challenge.id,
        signature: proof.signature,
      });
      expect(registered.wallet.address).toBe(legacyAddress);
      expect(registered.wallet.codecId).toBe(profile.codec.id);

      const authenticated = await service.authenticate(registered.session.token);
      expect(authenticated.wallets[0]?.address).toBe(legacyAddress);
      expect(authenticated.wallets[0]?.codecId).toBe(profile.codec.id);
    },
    derivationTimeoutMs,
  );
});

describe.skipIf(client === null)("platform salt provisioned on its own", () => {
  const sql = pgDriver(client as PgLikeClient);

  it("interoperates with the full identity schema", async () => {
    const prefix = newPrefix();
    const platform = {
      serviceProfileId: `w2sc-plat-${prefix.slice(-8)}`,
      profile,
      applicationId,
      networkId,
      tablePrefix: prefix,
    } as const;

    // A host that owns its own accounts provisions only the salt.
    const provisioned = await provisionPlatformSalt(sql, platform);
    expect(provisioned.publicSaltHex).toMatch(/^[0-9a-f]{64}$/u);
    expect(provisioned.publicSaltHex).not.toBe("0".repeat(64));
    expect(provisioned.applicationId).toBe(applicationId);

    // Re-provisioning is a no-op rather than a fresh namespace.
    expect((await provisionPlatformSalt(sql, platform)).publicSaltHex).toBe(
      provisioned.publicSaltHex,
    );
    expect((await readPlatformSalt(sql, platform)).publicSaltHex).toBe(provisioned.publicSaltHex);

    // The identity service adopting the same database must treat version 1 as
    // already applied and must not remint the salt.
    const applied = await runIdentityMigrations(
      sql,
      resolveIdentityServiceConfig({ ...platform }),
    );
    expect(applied).not.toContain(1);
    expect(await storedSaltHex(sql, prefix)).toBe(provisioned.publicSaltHex);

    // And the salt is still immutable.
    await expect(
      sql.query(`UPDATE ${prefix}_service_profiles SET public_salt = gen_random_bytes(32)`),
    ).rejects.toThrow(/immutable/u);
  });

  it("refuses to publish a salt that does not match the configuration", async () => {
    const prefix = newPrefix();
    const platform = {
      serviceProfileId: `w2sc-plat-${prefix.slice(-8)}`,
      profile,
      applicationId,
      networkId,
      tablePrefix: prefix,
    } as const;
    await provisionPlatformSalt(sql, platform);

    // Same database, different platform identity: publishing the stored salt
    // would hand clients a namespace this build does not own.
    await expect(
      readPlatformSalt(sql, { ...platform, applicationId: "some-other-platform" }),
    ).rejects.toThrowError(expect.objectContaining({ code: "invalid-service-profile" }));
  });
});
