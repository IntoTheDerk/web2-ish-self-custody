import type { DerivationProfile } from "../profile.js";
import { resolveIdentityServiceConfig } from "./config.js";
import { IdentityError } from "./errors.js";
import {
  applyMigrationStatement,
  identityMigrations,
  type IdentityMigration,
} from "./migrations.js";
import { integerColumn, requireSingleRow, textColumn, type SqlDriver } from "./sql.js";
import type { PublishedDerivationProfile } from "./types.js";

/**
 * The platform salt, on its own.
 *
 * Every service that derives wallets needs exactly one durable, immutable
 * 32-byte public salt: it is what makes the same username and password produce
 * a different wallet on each platform. That is a smaller thing than an identity
 * service, and a host with its own accounts and sessions should not have to
 * adopt one to get it. Before this module existed, three codebases had each
 * hand-rolled the same table with the same invariants and slightly different
 * names.
 *
 * The salt is public. It is a namespace separator, not a secret. It is also the
 * one derivation input a service cannot recompute, so it is integrity-critical
 * and must be in backups: lose it and every wallet derived under it is
 * unreachable.
 */
export type PlatformSaltConfig = Readonly<{
  /** Stable id for this platform's wallet namespace. */
  serviceProfileId: string;
  /** Must use the `external-32` salt policy; a self-salting profile has nothing to hold. */
  profile: DerivationProfile;
  applicationId: string;
  networkId: string;
  /** Table namespace, so one database can host several platforms. */
  tablePrefix?: string;
}>;

function resolve(config: PlatformSaltConfig) {
  return resolveIdentityServiceConfig(config);
}

/**
 * The migration that provisions the salt.
 *
 * This is version 1 of the identity schema, verbatim -- the identity service and
 * a salt-only host emit byte-identical SQL and share the same version number, so
 * a database provisioned by one is already migrated for the other.
 */
export function platformSaltMigration(config: PlatformSaltConfig): IdentityMigration {
  const [migration] = identityMigrations(resolve(config));
  if (migration === undefined) {
    throw new IdentityError("Migration set is empty.", "invalid-service-profile");
  }
  return migration;
}

/**
 * Provisions the salt once and returns it. Safe to call on every boot and safe
 * to run concurrently: the statements are idempotent and retried on the
 * catalog races that parallel cold starts produce.
 */
export async function provisionPlatformSalt(
  sql: SqlDriver,
  config: PlatformSaltConfig,
): Promise<PublishedDerivationProfile> {
  const resolved = resolve(config);
  const prefix = resolved.tablePrefix;
  const migration = platformSaltMigration(config);

  await applyMigrationStatement(
    sql,
    `CREATE TABLE IF NOT EXISTS ${prefix}_schema_migrations (
       version integer PRIMARY KEY,
       name text NOT NULL,
       applied_at timestamptz NOT NULL DEFAULT now()
     )`,
  );

  const applied = await sql.query<{ version: number }>(
    `SELECT version FROM ${prefix}_schema_migrations WHERE version = $1`,
    [migration.version],
  );
  if (applied.length === 0) {
    for (const statement of migration.statements) {
      await applyMigrationStatement(sql, statement);
    }
    // Recorded under the shared ledger, so a later full identity migration
    // correctly skips version 1 rather than re-running it.
    await sql.query(
      `INSERT INTO ${prefix}_schema_migrations (version, name)
       VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`,
      [migration.version, migration.name],
    );
  }

  return readPlatformSalt(sql, config);
}

/**
 * Reads the provisioned salt and KDF parameters.
 *
 * The stored row is checked against the configuration rather than trusted: a
 * database whose profile, application, or network disagrees with this build is
 * serving a different wallet namespace than the code expects, and silently
 * publishing it would hand clients the wrong salt.
 */
export async function readPlatformSalt(
  sql: SqlDriver,
  config: PlatformSaltConfig,
): Promise<PublishedDerivationProfile> {
  const resolved = resolve(config);
  const prefix = resolved.tablePrefix;

  const rows = await sql.query(
    `SELECT service_profile_id, profile_id, algorithm, curve, application_id,
            network_id, encode(public_salt, 'hex') AS public_salt_hex,
            kdf_n, kdf_r, kdf_p, kdf_dk_len
       FROM ${prefix}_service_profiles
      WHERE service_profile_id = $1::text`,
    [resolved.serviceProfileId],
  );
  const row = requireSingleRow(
    rows,
    () =>
      new IdentityError(
        "The platform salt has not been provisioned; run provisionPlatformSalt first.",
        "service-profile-missing",
      ),
  );

  const published: PublishedDerivationProfile = Object.freeze({
    serviceProfileId: textColumn(row, "service_profile_id"),
    profileId: textColumn(row, "profile_id"),
    codecId: resolved.profile.codec.id,
    algorithm: textColumn(row, "algorithm"),
    curve: "ed25519",
    applicationId: textColumn(row, "application_id"),
    networkId: textColumn(row, "network_id"),
    publicSaltHex: textColumn(row, "public_salt_hex"),
    kdf: Object.freeze({
      N: integerColumn(row, "kdf_n"),
      r: integerColumn(row, "kdf_r"),
      p: integerColumn(row, "kdf_p"),
      dkLen: integerColumn(row, "kdf_dk_len"),
    }),
  });

  if (
    published.profileId !== resolved.profile.id ||
    published.applicationId !== resolved.applicationId ||
    published.networkId !== resolved.networkId
  ) {
    throw new IdentityError(
      "The stored platform salt does not match this service configuration; every wallet in this namespace depends on it.",
      "invalid-service-profile",
    );
  }
  if (!/^[0-9a-f]{64}$/u.test(published.publicSaltHex)) {
    throw new IdentityError("The stored platform salt is malformed.", "invalid-service-profile");
  }

  return published;
}
