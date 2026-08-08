import { IdentityError } from "./errors.js";
import type { SqlDriver } from "./sql.js";
import type { ResolvedIdentityServiceConfig } from "./types.js";

const identifierPattern = /^[a-z][a-z0-9_]{0,31}$/u;
const literalPattern = /^[a-z0-9][a-z0-9._:-]{0,79}$/u;

/**
 * DDL cannot bind identifiers or CHECK-constraint literals, so every value
 * that reaches the generated SQL is validated against a strict allowlist
 * first. Nothing here interpolates caller text that has not passed one of
 * these two gates.
 */
function assertIdentifier(value: string, field: string): string {
  if (!identifierPattern.test(value)) {
    throw new IdentityError(
      `Invalid ${field}; expected lowercase snake_case, 1-32 characters.`,
      "invalid-service-profile",
    );
  }
  return value;
}

function assertLiteral(value: string, field: string): string {
  if (!literalPattern.test(value)) {
    throw new IdentityError(
      `Invalid ${field}; expected 1-80 lowercase characters from [a-z0-9._:-].`,
      "invalid-service-profile",
    );
  }
  return value;
}

/**
 * Emits a `CREATE TRIGGER` that tolerates another runner having already made
 * it. The dollar-quote tag must not collide with the `$$` used inside trigger
 * function bodies elsewhere in these migrations.
 */
function createTriggerOnce(name: string, definition: string): string {
  return `DO $trg$
          BEGIN
            CREATE TRIGGER ${name} ${definition};
          EXCEPTION WHEN duplicate_object THEN
            NULL;
          END;
          $trg$`;
}

export type IdentityMigration = Readonly<{
  version: number;
  name: string;
  statements: readonly string[];
}>;

export function identityMigrations(
  config: ResolvedIdentityServiceConfig,
): readonly IdentityMigration[] {
  const p = assertIdentifier(config.tablePrefix, "tablePrefix");
  const serviceProfileId = assertLiteral(config.serviceProfileId, "serviceProfileId");
  const applicationId = assertLiteral(config.applicationId, "applicationId");
  const networkId = assertLiteral(config.networkId, "networkId");
  const profile = config.profile;
  const profileId = assertLiteral(profile.id, "profileId");
  // Recorded per wallet: the address encoding is what makes a stored address
  // resolvable, so a deployment that ever changed codecs must still be able to
  // tell which one produced each row.
  const codecId = assertLiteral(profile.codec.id, "codecId");
  const algorithm = assertLiteral(profile.algorithm, "algorithm");
  const curve = profile.curve;

  const mutationGuard = `${p}_reject_immutable_mutation`;

  // Re-validated here rather than trusted from config: this value is
  // interpolated into DDL, and it decides which wallets the deployment can
  // still reach. An adopted salt is only ever consumed on first provisioning.
  const adopted = config.adoptPublicSaltHex;
  if (adopted !== null && !/^[0-9a-f]{64}$/u.test(adopted)) {
    throw new IdentityError(
      "adoptPublicSaltHex must be exactly 32 hex-encoded bytes.",
      "invalid-service-profile",
    );
  }
  const saltExpression =
    adopted === null ? "gen_random_bytes(32)" : `decode('${adopted}', 'hex')`;

  // Adoption is a no-op once provisioning has happened. Without this check an
  // operator who adopts the wrong salt onto an already-provisioned database
  // gets silence and assumes success, while the deployment keeps serving a
  // different wallet namespace than they intended.
  const adoptionGuard =
    adopted === null
      ? ""
      : `
             IF NOT EXISTS (
               SELECT 1 FROM ${p}_service_profiles
               WHERE service_profile_id = '${serviceProfileId}'
                 AND public_salt = decode('${adopted}', 'hex')
             ) THEN
               RAISE EXCEPTION
                 'service profile ${serviceProfileId} is already provisioned with a different public salt than adoptPublicSaltHex; refusing to continue';
             END IF;`;

  return Object.freeze([
    Object.freeze({
      version: 1,
      name: "service-profile",
      statements: Object.freeze([
        // `IF NOT EXISTS` is check-then-act, so two runners starting together
        // against a fresh database both see it missing and both create it; the
        // loser gets a unique-violation on pg_extension. That is not
        // hypothetical — several serverless instances cold-starting at once do
        // exactly this. Swallow only the concurrency outcome.
        `DO $ext$
         BEGIN
           CREATE EXTENSION IF NOT EXISTS pgcrypto;
         EXCEPTION WHEN duplicate_object OR unique_violation THEN
           NULL;
         END;
         $ext$`,

        `CREATE TABLE IF NOT EXISTS ${p}_service_profiles (
           service_profile_id text PRIMARY KEY,
           profile_id text NOT NULL,
           algorithm text NOT NULL,
           curve text NOT NULL,
           application_id text NOT NULL,
           network_id text NOT NULL,
           public_salt bytea NOT NULL,
           kdf_n integer NOT NULL,
           kdf_r integer NOT NULL,
           kdf_p integer NOT NULL,
           kdf_dk_len integer NOT NULL,
           created_at timestamptz NOT NULL DEFAULT now(),
           CONSTRAINT ${p}_service_profiles_exact CHECK (
             service_profile_id = '${serviceProfileId}'
             AND profile_id = '${profileId}'
             AND algorithm = '${algorithm}'
             AND curve = '${curve}'
             AND application_id = '${applicationId}'
             AND network_id = '${networkId}'
             AND octet_length(public_salt) = 32
             AND public_salt <> decode(repeat('00', 32), 'hex')
             AND kdf_n = ${profile.kdf.N}
             AND kdf_r = ${profile.kdf.r}
             AND kdf_p = ${profile.kdf.p}
             AND kdf_dk_len = ${profile.kdf.dkLen}
           )
         )`,

        // Separate from the profile table so a dropped profile row is
        // detectable. Without this, a wiped profile would silently regenerate
        // a fresh salt and orphan every existing wallet.
        `CREATE TABLE IF NOT EXISTS ${p}_service_profile_bootstrap (
           service_profile_id text PRIMARY KEY,
           provisioned_at timestamptz NOT NULL DEFAULT now()
         )`,

        `CREATE OR REPLACE FUNCTION ${mutationGuard}()
         RETURNS trigger
         LANGUAGE plpgsql
         SET search_path = pg_catalog, public
         AS $$
         BEGIN
           RAISE EXCEPTION 'wallet derivation service profile is immutable'
             USING ERRCODE = '55000';
         END;
         $$`,

        // `CREATE TRIGGER` has no IF NOT EXISTS, and a DROP-then-CREATE pair
        // would leave a window where the table is unprotected while another
        // runner is mid-migration. Creating inside an exception handler is both
        // idempotent and safe to run concurrently.
        createTriggerOnce(
          `${p}_service_profiles_immutable`,
          `BEFORE UPDATE OR DELETE ON ${p}_service_profiles
           FOR EACH ROW EXECUTE FUNCTION ${mutationGuard}()`,
        ),
        createTriggerOnce(
          `${p}_service_profiles_no_truncate`,
          `BEFORE TRUNCATE ON ${p}_service_profiles
           FOR EACH STATEMENT EXECUTE FUNCTION ${mutationGuard}()`,
        ),
        createTriggerOnce(
          `${p}_bootstrap_immutable`,
          `BEFORE UPDATE OR DELETE ON ${p}_service_profile_bootstrap
           FOR EACH ROW EXECUTE FUNCTION ${mutationGuard}()`,
        ),
        createTriggerOnce(
          `${p}_bootstrap_no_truncate`,
          `BEFORE TRUNCATE ON ${p}_service_profile_bootstrap
           FOR EACH STATEMENT EXECUTE FUNCTION ${mutationGuard}()`,
        ),

        // Provision exactly once. If bootstrap says we already minted a salt
        // but the profile row is gone, fail closed and demand a restore
        // instead of quietly issuing a new namespace.
        `DO $$
         BEGIN
           IF EXISTS (
             SELECT 1 FROM ${p}_service_profile_bootstrap
             WHERE service_profile_id = '${serviceProfileId}'
           ) THEN
             IF NOT EXISTS (
               SELECT 1 FROM ${p}_service_profiles
               WHERE service_profile_id = '${serviceProfileId}'
             ) THEN
               RAISE EXCEPTION
                 'service profile ${serviceProfileId} is missing; restore its original public salt from backup';
             END IF;${adoptionGuard}
           ELSE
             INSERT INTO ${p}_service_profiles (
               service_profile_id, profile_id, algorithm, curve,
               application_id, network_id, public_salt,
               kdf_n, kdf_r, kdf_p, kdf_dk_len
             ) VALUES (
               '${serviceProfileId}', '${profileId}', '${algorithm}', '${curve}',
               '${applicationId}', '${networkId}', ${saltExpression},
               ${profile.kdf.N}, ${profile.kdf.r}, ${profile.kdf.p}, ${profile.kdf.dkLen}
             ) ON CONFLICT (service_profile_id) DO NOTHING;

             INSERT INTO ${p}_service_profile_bootstrap (service_profile_id)
             VALUES ('${serviceProfileId}')
             ON CONFLICT (service_profile_id) DO NOTHING;
           END IF;
         END;
         $$`,

        `REVOKE ALL ON TABLE ${p}_service_profiles FROM PUBLIC`,
        `REVOKE ALL ON TABLE ${p}_service_profile_bootstrap FROM PUBLIC`,
      ]),
    }),

    Object.freeze({
      version: 2,
      name: "accounts-and-wallets",
      statements: Object.freeze([
        `CREATE TABLE IF NOT EXISTS ${p}_accounts (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           service_profile_id text NOT NULL REFERENCES ${p}_service_profiles(service_profile_id),
           username_normalized text NOT NULL,
           display_name text NOT NULL,
           email text,
           email_verified_at timestamptz,
           status text NOT NULL DEFAULT 'active',
           created_at timestamptz NOT NULL DEFAULT now(),
           updated_at timestamptz NOT NULL DEFAULT now(),
           CONSTRAINT ${p}_accounts_status CHECK (status IN ('active', 'suspended')),
           CONSTRAINT ${p}_accounts_username CHECK (
             char_length(username_normalized) BETWEEN 3 AND 320
           ),
           CONSTRAINT ${p}_accounts_display_name CHECK (
             char_length(display_name) BETWEEN 1 AND 120
           ),
           CONSTRAINT ${p}_accounts_email_verified_requires_email CHECK (
             email_verified_at IS NULL OR email IS NOT NULL
           ),
           UNIQUE (service_profile_id, username_normalized)
         )`,

        `CREATE INDEX IF NOT EXISTS ${p}_accounts_email_idx
           ON ${p}_accounts (service_profile_id, email)
           WHERE email IS NOT NULL`,

        `CREATE TABLE IF NOT EXISTS ${p}_account_wallets (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           account_id uuid NOT NULL REFERENCES ${p}_accounts(id) ON DELETE CASCADE,
           service_profile_id text NOT NULL REFERENCES ${p}_service_profiles(service_profile_id),
           profile_id text NOT NULL,
           codec_id text NOT NULL,
           curve text NOT NULL,
           application_id text NOT NULL,
           network_id text NOT NULL,
           address text NOT NULL,
           address_normalized text NOT NULL,
           public_key text NOT NULL,
           fingerprint text NOT NULL,
           is_primary boolean NOT NULL DEFAULT true,
           created_at timestamptz NOT NULL DEFAULT now(),
           CONSTRAINT ${p}_account_wallets_binding CHECK (
             profile_id = '${profileId}'
             AND codec_id = '${codecId}'
             AND curve = '${curve}'
             AND application_id = '${applicationId}'
             AND network_id = '${networkId}'
           ),
           CONSTRAINT ${p}_account_wallets_address CHECK (
             char_length(address) BETWEEN 8 AND 128
             AND address_normalized = lower(address)
           ),
           CONSTRAINT ${p}_account_wallets_public_key CHECK (
             char_length(public_key) BETWEEN 8 AND 160
           ),
           UNIQUE (service_profile_id, address_normalized)
         )`,

        `CREATE INDEX IF NOT EXISTS ${p}_account_wallets_account_idx
           ON ${p}_account_wallets (account_id)`,

        // One primary wallet per account. A partial unique index expresses
        // this without needing a trigger.
        `CREATE UNIQUE INDEX IF NOT EXISTS ${p}_account_wallets_primary_idx
           ON ${p}_account_wallets (account_id)
           WHERE is_primary`,
      ]),
    }),

    Object.freeze({
      version: 3,
      name: "challenges-sessions-email",
      statements: Object.freeze([
        `CREATE TABLE IF NOT EXISTS ${p}_auth_challenges (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           service_profile_id text NOT NULL REFERENCES ${p}_service_profiles(service_profile_id),
           username_normalized text NOT NULL,
           purpose text NOT NULL,
           nonce bytea NOT NULL,
           expires_at timestamptz NOT NULL,
           consumed_at timestamptz,
           created_at timestamptz NOT NULL DEFAULT now(),
           CONSTRAINT ${p}_auth_challenges_purpose CHECK (
             purpose IN ('registration', 'login', 'rotation')
           ),
           CONSTRAINT ${p}_auth_challenges_nonce CHECK (octet_length(nonce) = 32)
         )`,

        `CREATE INDEX IF NOT EXISTS ${p}_auth_challenges_username_idx
           ON ${p}_auth_challenges (service_profile_id, username_normalized, created_at DESC)`,
        `CREATE INDEX IF NOT EXISTS ${p}_auth_challenges_expires_idx
           ON ${p}_auth_challenges (expires_at)`,

        `CREATE TABLE IF NOT EXISTS ${p}_sessions (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           account_id uuid NOT NULL REFERENCES ${p}_accounts(id) ON DELETE CASCADE,
           token_hash text NOT NULL UNIQUE,
           issued_at timestamptz NOT NULL DEFAULT now(),
           expires_at timestamptz NOT NULL,
           last_seen_at timestamptz NOT NULL DEFAULT now(),
           revoked_at timestamptz,
           ip_hash text,
           user_agent_hash text,
           CONSTRAINT ${p}_sessions_token_hash CHECK (token_hash ~ '^[0-9a-f]{64}$')
         )`,

        `CREATE INDEX IF NOT EXISTS ${p}_sessions_account_idx
           ON ${p}_sessions (account_id, expires_at DESC)`,
        `CREATE INDEX IF NOT EXISTS ${p}_sessions_expires_idx
           ON ${p}_sessions (expires_at)`,

        `CREATE TABLE IF NOT EXISTS ${p}_email_verifications (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           service_profile_id text NOT NULL REFERENCES ${p}_service_profiles(service_profile_id),
           username_normalized text NOT NULL,
           email text NOT NULL,
           code_hash text NOT NULL,
           attempts integer NOT NULL DEFAULT 0,
           expires_at timestamptz NOT NULL,
           consumed_at timestamptz,
           created_at timestamptz NOT NULL DEFAULT now(),
           CONSTRAINT ${p}_email_verifications_code_hash CHECK (code_hash ~ '^[0-9a-f]{64}$'),
           CONSTRAINT ${p}_email_verifications_attempts CHECK (attempts >= 0)
         )`,

        `CREATE INDEX IF NOT EXISTS ${p}_email_verifications_lookup_idx
           ON ${p}_email_verifications (service_profile_id, username_normalized, created_at DESC)`,
        `CREATE INDEX IF NOT EXISTS ${p}_email_verifications_expires_idx
           ON ${p}_email_verifications (expires_at)`,

        `CREATE TABLE IF NOT EXISTS ${p}_rate_limits (
           bucket text PRIMARY KEY,
           rule_id text NOT NULL,
           count integer NOT NULL DEFAULT 0,
           window_start timestamptz NOT NULL DEFAULT now(),
           updated_at timestamptz NOT NULL DEFAULT now()
         )`,

        `CREATE INDEX IF NOT EXISTS ${p}_rate_limits_updated_idx
           ON ${p}_rate_limits (updated_at)`,

        `CREATE TABLE IF NOT EXISTS ${p}_audit_events (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           account_id uuid REFERENCES ${p}_accounts(id) ON DELETE SET NULL,
           action text NOT NULL,
           metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
           created_at timestamptz NOT NULL DEFAULT now(),
           CONSTRAINT ${p}_audit_events_action CHECK (char_length(action) BETWEEN 1 AND 64)
         )`,

        `CREATE INDEX IF NOT EXISTS ${p}_audit_events_account_idx
           ON ${p}_audit_events (account_id, created_at DESC)`,
        `CREATE INDEX IF NOT EXISTS ${p}_audit_events_created_idx
           ON ${p}_audit_events (created_at DESC)`,
      ]),
    }),
  ]);
}

/**
 * PostgreSQL error codes raised when two sessions create the same object at
 * once. `CREATE ... IF NOT EXISTS` is check-then-act, so under concurrency the
 * loser sees a unique violation on a system catalog rather than a quiet no-op.
 */
const concurrentCreationCodes: ReadonlySet<string> = new Set([
  "23505", // unique_violation, e.g. pg_type_typname_nsp_index, pg_extension_name_index
  "42P07", // duplicate_table
  "42P06", // duplicate_schema
  "42710", // duplicate_object
  "42723", // duplicate_function
]);

function sqlStateOf(error: unknown): string | null {
  if (typeof error !== "object" || error === null) {
    return null;
  }
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

/**
 * Two sessions running `CREATE OR REPLACE FUNCTION` on the same function race
 * on its catalog tuple. PostgreSQL reports that as a generic internal error, so
 * it has to be matched on the message; tolerating every XX000 would swallow
 * unrelated server faults.
 */
function isConcurrentCatalogUpdate(error: unknown): boolean {
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const message = (error as { message?: unknown }).message;
  return typeof message === "string" && message.includes("tuple concurrently updated");
}

function isConcurrentCreation(error: unknown): boolean {
  const state = sqlStateOf(error);
  return (state !== null && concurrentCreationCodes.has(state)) || isConcurrentCatalogUpdate(error);
}

/**
 * Runs one migration statement, tolerating a peer runner having created the
 * same object mid-flight.
 *
 * Serverless deployments cold-start in parallel, so several instances racing
 * through these migrations is ordinary. A stateless HTTP transport has no
 * session-scoped advisory lock to serialize them with, so the recovery is to
 * retry: every statement here is written to be idempotent, and a retry after a
 * peer has finished simply finds the object present and does nothing.
 */
/**
 * Exported for `serviceProfile.ts`, which provisions the platform salt on its
 * own for hosts that do not want the rest of the identity schema. Both paths
 * must share this retry, or one of them races on a cold start and the other
 * does not.
 */
export async function applyMigrationStatement(sql: SqlDriver, statement: string): Promise<void> {
  const maxAttempts = 5;
  for (let attempt = 1; ; attempt += 1) {
    try {
      await sql.query(statement);
      return;
    } catch (error) {
      if (attempt >= maxAttempts || !isConcurrentCreation(error)) {
        throw error;
      }
      // Brief, growing pause so several racing runners do not retry in lockstep.
      await new Promise<void>((resolve) => setTimeout(resolve, attempt * 25));
    }
  }
}

/**
 * Applies pending migrations in order, recording each in the prefix's own
 * migration table. Statements run individually so the runner behaves the same
 * on Neon's HTTP transport as on a pooled `pg` connection.
 */
export async function runIdentityMigrations(
  sql: SqlDriver,
  config: ResolvedIdentityServiceConfig,
): Promise<readonly number[]> {
  const p = assertIdentifier(config.tablePrefix, "tablePrefix");

  await applyMigrationStatement(
    sql,
    `CREATE TABLE IF NOT EXISTS ${p}_schema_migrations (
       version integer PRIMARY KEY,
       name text NOT NULL,
       applied_at timestamptz NOT NULL DEFAULT now()
     )`,
  );

  const applied = await sql.query<{ version: number }>(
    `SELECT version FROM ${p}_schema_migrations`,
  );
  const appliedVersions = new Set(applied.map((row) => Number(row.version)));
  const executed: number[] = [];

  for (const migration of identityMigrations(config)) {
    if (appliedVersions.has(migration.version)) {
      continue;
    }
    for (const statement of migration.statements) {
      await applyMigrationStatement(sql, statement);
    }
    await sql.query(
      `INSERT INTO ${p}_schema_migrations (version, name)
       VALUES ($1, $2) ON CONFLICT (version) DO NOTHING`,
      [migration.version, migration.name],
    );
    executed.push(migration.version);
  }

  return Object.freeze(executed);
}
