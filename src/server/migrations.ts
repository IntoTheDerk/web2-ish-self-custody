import { getProfile } from "../profiles.js";
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
  const profileId = assertLiteral(config.profileId, "profileId");
  const profile = getProfile(config.profileId);
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
        `CREATE EXTENSION IF NOT EXISTS pgcrypto`,

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
             AND kdf_n = ${profile.N}
             AND kdf_r = ${profile.r}
             AND kdf_p = ${profile.p}
             AND kdf_dk_len = ${profile.dkLen}
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

        `DROP TRIGGER IF EXISTS ${p}_service_profiles_immutable ON ${p}_service_profiles`,
        `CREATE TRIGGER ${p}_service_profiles_immutable
           BEFORE UPDATE OR DELETE ON ${p}_service_profiles
           FOR EACH ROW EXECUTE FUNCTION ${mutationGuard}()`,
        `DROP TRIGGER IF EXISTS ${p}_service_profiles_no_truncate ON ${p}_service_profiles`,
        `CREATE TRIGGER ${p}_service_profiles_no_truncate
           BEFORE TRUNCATE ON ${p}_service_profiles
           FOR EACH STATEMENT EXECUTE FUNCTION ${mutationGuard}()`,
        `DROP TRIGGER IF EXISTS ${p}_bootstrap_immutable ON ${p}_service_profile_bootstrap`,
        `CREATE TRIGGER ${p}_bootstrap_immutable
           BEFORE UPDATE OR DELETE ON ${p}_service_profile_bootstrap
           FOR EACH ROW EXECUTE FUNCTION ${mutationGuard}()`,
        `DROP TRIGGER IF EXISTS ${p}_bootstrap_no_truncate ON ${p}_service_profile_bootstrap`,
        `CREATE TRIGGER ${p}_bootstrap_no_truncate
           BEFORE TRUNCATE ON ${p}_service_profile_bootstrap
           FOR EACH STATEMENT EXECUTE FUNCTION ${mutationGuard}()`,

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
               ${profile.N}, ${profile.r}, ${profile.p}, ${profile.dkLen}
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
 * Applies pending migrations in order, recording each in the prefix's own
 * migration table. Statements run individually so the runner behaves the same
 * on Neon's HTTP transport as on a pooled `pg` connection.
 */
export async function runIdentityMigrations(
  sql: SqlDriver,
  config: ResolvedIdentityServiceConfig,
): Promise<readonly number[]> {
  const p = assertIdentifier(config.tablePrefix, "tablePrefix");

  await sql.query(
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
      await sql.query(statement);
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
