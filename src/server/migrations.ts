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
             END IF;
           ELSE
             INSERT INTO ${p}_service_profiles (
               service_profile_id, profile_id, algorithm, curve,
               application_id, network_id, public_salt,
               kdf_n, kdf_r, kdf_p, kdf_dk_len
             ) VALUES (
               '${serviceProfileId}', '${profileId}', '${algorithm}', '${curve}',
               '${applicationId}', '${networkId}', gen_random_bytes(32),
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

        // One row per enrolled key. The table keeps its name under every
        // profile: the key is a wallet only when the profile is a chain wallet
        // profile, and the account's sign-in key under the sign-in profile.
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

    Object.freeze({
      version: 4,
      name: "optional-friendly-name",
      statements: Object.freeze([
        // The username is a derivation input and can never change without
        // changing the enrolled key (the wallet, under a chain wallet profile;
        // the sign-in key under the sign-in profile), so the friendly name is
        // the only part of an identity a user may edit. Making it nullable is
        // what lets "the user chose this" be distinguishable from "we
        // defaulted it to their username" -- previously every account carried
        // a name it never asked for, so a client could not tell whether to
        // show it.
        // One statement on purpose. Dropping and re-adding the length CHECK to
        // spell out `display_name IS NULL OR ...` would be redundant -- a CHECK
        // only fails on FALSE, and `char_length(NULL)` is NULL -- and an
        // ALTER/ADD CONSTRAINT pair is not safe to run concurrently the way
        // `CREATE ... IF NOT EXISTS` is: two migration runners race and the
        // loser gets "constraint already exists". DROP NOT NULL serializes on
        // the table lock and is a no-op the second time.
        `ALTER TABLE ${p}_accounts ALTER COLUMN display_name DROP NOT NULL`,
      ]),
    }),
    Object.freeze({
      version: 5,
      name: "account-wallet-modes",
      statements: Object.freeze([
        `CREATE TABLE IF NOT EXISTS ${p}_wallet_policy (
           service_profile_id text PRIMARY KEY REFERENCES ${p}_service_profiles(service_profile_id),
           mode text NOT NULL CHECK (mode IN ('service-deterministic', 'per-account-deterministic', 'random-vault'))
         )`,
        `INSERT INTO ${p}_wallet_policy (service_profile_id, mode)
         VALUES ('${serviceProfileId}', CASE WHEN EXISTS (SELECT 1 FROM ${p}_accounts)
           THEN 'service-deterministic' ELSE '${assertLiteral(config.walletMode, "walletMode")}' END)
         ON CONFLICT DO NOTHING`,
        createTriggerOnce(`${p}_wallet_policy_immutable`,
          `BEFORE UPDATE OR DELETE ON ${p}_wallet_policy FOR EACH ROW EXECUTE FUNCTION ${mutationGuard}()`),
        createTriggerOnce(`${p}_wallet_policy_no_truncate`,
          `BEFORE TRUNCATE ON ${p}_wallet_policy FOR EACH STATEMENT EXECUTE FUNCTION ${mutationGuard}()`),
        `CREATE TABLE IF NOT EXISTS ${p}_wallet_setups (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           service_profile_id text NOT NULL REFERENCES ${p}_service_profiles(service_profile_id),
           username_normalized text NOT NULL,
           public_salt bytea NOT NULL DEFAULT gen_random_bytes(32) CHECK (octet_length(public_salt) = 32),
           UNIQUE (service_profile_id, username_normalized)
         )`,
        createTriggerOnce(`${p}_wallet_setups_immutable`,
          `BEFORE UPDATE OR DELETE ON ${p}_wallet_setups FOR EACH ROW EXECUTE FUNCTION ${mutationGuard}()`),
        createTriggerOnce(`${p}_wallet_setups_no_truncate`,
          `BEFORE TRUNCATE ON ${p}_wallet_setups FOR EACH STATEMENT EXECUTE FUNCTION ${mutationGuard}()`),
        `ALTER TABLE ${p}_account_wallets ADD COLUMN IF NOT EXISTS vault jsonb,
           ADD COLUMN IF NOT EXISTS vault_revision integer NOT NULL DEFAULT 1`,
      ]),
    }),
    Object.freeze({
      version: 6,
      name: "session-client-labels",
      statements: Object.freeze([
        // A coarse, display-only client description per session, deleted with
        // its row by `pruneExpired`. One statement on purpose, like migration
        // 4: a separate DROP/ADD CONSTRAINT pair is not safe for concurrent
        // runners (the loser gets "constraint already exists" on every retry),
        // whereas ADD COLUMN IF NOT EXISTS serializes on the table lock and
        // skips the column and its constraint together on a re-run.
        // No index: `authenticate()` rewrites `last_seen_at` on every request,
        // and an index containing it would end HOT updates for that write.
        // Listing filters through `<p>_sessions_account_idx`.
        `ALTER TABLE ${p}_sessions ADD COLUMN IF NOT EXISTS client_label text
           CONSTRAINT ${p}_sessions_client_label
           CHECK (client_label IS NULL OR client_label ~ '^[A-Za-z0-9 .()-]{1,64}$')`,
      ]),
    }),
    Object.freeze({
      version: 7,
      name: "account-recovery-keys",
      statements: Object.freeze([
        // Recovery keys: the public half of an Ed25519 key the client derives
        // from a recovery secret it holds. At most one is active per account
        // (the partial unique index); a used or removed key keeps its row, so
        // `UNIQUE (service_profile_id, public_key)` also refuses re-enrolling
        // any key this service has seen. Every statement below is one
        // `CREATE ... IF NOT EXISTS` with its constraints inline, so a re-run
        // is a no-op and concurrent runners serialize on the catalog (the
        // loser's duplicate-object error is retried by the runner).
        `CREATE TABLE IF NOT EXISTS ${p}_account_recovery_keys (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           account_id uuid NOT NULL REFERENCES ${p}_accounts(id) ON DELETE CASCADE,
           service_profile_id text NOT NULL REFERENCES ${p}_service_profiles(service_profile_id),
           public_key text NOT NULL,
           status text NOT NULL,
           created_at timestamptz NOT NULL DEFAULT now(),
           used_at timestamptz,
           removed_at timestamptz,
           CONSTRAINT ${p}_account_recovery_keys_public_key CHECK (public_key ~ '^[0-9a-f]{64}$'),
           CONSTRAINT ${p}_account_recovery_keys_status CHECK (status IN ('active', 'used', 'removed')),
           CONSTRAINT ${p}_account_recovery_keys_used CHECK ((status = 'used') = (used_at IS NOT NULL)),
           CONSTRAINT ${p}_account_recovery_keys_removed CHECK ((status = 'removed') = (removed_at IS NOT NULL)),
           UNIQUE (service_profile_id, public_key)
         )`,
        `CREATE UNIQUE INDEX IF NOT EXISTS ${p}_account_recovery_keys_active_idx
           ON ${p}_account_recovery_keys (account_id) WHERE status = 'active'`,
        // Used and removed keys are kept forever, so the partial index above
        // cannot serve an account's whole history: `recoveryStatus` (its
        // latest key) and the account-delete cascade read it here.
        `CREATE INDEX IF NOT EXISTS ${p}_account_recovery_keys_account_idx
           ON ${p}_account_recovery_keys (account_id, created_at DESC)`,
        // Recovery tokens, stored as SHA-256 only. "Live" is neither completed
        // nor revoked; an expired token stays live until the next begin
        // revokes it or `pruneExpired` deletes it a day after it expires. The
        // live index is UNIQUE so that at most one token per account is live
        // even when two begins overlap: under READ COMMITTED the second
        // begin's snapshot cannot see the first one's new row to revoke it, so
        // only an index can refuse the second insert (the service then
        // retries, and the retry revokes the first token).
        `CREATE TABLE IF NOT EXISTS ${p}_account_recoveries (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           account_id uuid NOT NULL REFERENCES ${p}_accounts(id) ON DELETE CASCADE,
           recovery_key_id uuid NOT NULL REFERENCES ${p}_account_recovery_keys(id) ON DELETE CASCADE,
           token_hash text NOT NULL UNIQUE,
           created_at timestamptz NOT NULL DEFAULT now(),
           expires_at timestamptz NOT NULL,
           completed_at timestamptz,
           revoked_at timestamptz,
           CONSTRAINT ${p}_account_recoveries_token_hash CHECK (token_hash ~ '^[0-9a-f]{64}$'),
           CONSTRAINT ${p}_account_recoveries_expiry CHECK (expires_at > created_at)
         )`,
        `CREATE UNIQUE INDEX IF NOT EXISTS ${p}_account_recoveries_live_idx
           ON ${p}_account_recoveries (account_id)
           WHERE completed_at IS NULL AND revoked_at IS NULL`,
        // A retired key's tokens, and the cascade when a key row is deleted.
        `CREATE INDEX IF NOT EXISTS ${p}_account_recoveries_key_idx
           ON ${p}_account_recoveries (recovery_key_id)`,
      ]),
    }),
    Object.freeze({
      version: 8,
      name: "account-resets",
      statements: Object.freeze([
        // The two per-account reset settings. Each column is one ADD COLUMN
        // IF NOT EXISTS, like migration 6: concurrent runners serialize on the
        // table lock and a re-run skips it. A NOT NULL column with a constant
        // default needs no table rewrite (PostgreSQL 11+), so existing
        // accounts read the default at once: account recovery by email off,
        // the signed-in reset on (it does nothing unless the service's
        // `accountSecurity.signedInReset` opt-in is on too).
        `ALTER TABLE ${p}_accounts ADD COLUMN IF NOT EXISTS email_reset_enabled boolean NOT NULL DEFAULT false`,
        `ALTER TABLE ${p}_accounts ADD COLUMN IF NOT EXISTS signed_in_reset_enabled boolean NOT NULL DEFAULT true`,
        // One row per reset: an emailed code (`email`, signed out) or a
        // signed-in reset (`signed-in`, from one session, available after a
        // wait or at once with an emailed code). The code is stored as its
        // SHA-256 only. "Live" is neither completed nor aborted; a reset that
        // lapsed is closed with `aborted_at` when the next one starts.
        // `session_id` deliberately has no foreign key: `pruneExpired`
        // deletes dead sessions under SKIP LOCKED, and a cascade from them
        // would lock reset rows behind the session locks, against the order
        // every reset statement takes (reset before sessions). A reset whose
        // session is gone cannot complete, because completion requires that
        // session's live token.
        `CREATE TABLE IF NOT EXISTS ${p}_account_resets (
           id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
           account_id uuid NOT NULL REFERENCES ${p}_accounts(id) ON DELETE CASCADE,
           kind text NOT NULL,
           code_hash text,
           attempts integer NOT NULL DEFAULT 0,
           session_id uuid,
           created_at timestamptz NOT NULL DEFAULT now(),
           available_at timestamptz NOT NULL,
           expires_at timestamptz NOT NULL,
           completed_at timestamptz,
           aborted_at timestamptz,
           CONSTRAINT ${p}_account_resets_kind CHECK (kind IN ('email', 'signed-in')),
           CONSTRAINT ${p}_account_resets_code_hash CHECK (code_hash IS NULL OR code_hash ~ '^[0-9a-f]{64}$'),
           CONSTRAINT ${p}_account_resets_attempts CHECK (attempts >= 0),
           CONSTRAINT ${p}_account_resets_shape CHECK (
             (kind = 'email' AND code_hash IS NOT NULL AND session_id IS NULL AND available_at = created_at)
             OR (kind = 'signed-in' AND session_id IS NOT NULL)
           ),
           CONSTRAINT ${p}_account_resets_times CHECK (available_at >= created_at AND expires_at > available_at),
           CONSTRAINT ${p}_account_resets_closed CHECK (completed_at IS NULL OR aborted_at IS NULL)
         )`,
        // At most one live signed-in reset per account. Under READ COMMITTED a
        // second start cannot see the first one's new row, so only an index
        // can refuse it (the service retries on a fresh snapshot and answers
        // `reset-pending`). It also serves the login abort and the status.
        `CREATE UNIQUE INDEX IF NOT EXISTS ${p}_account_resets_signed_in_live_idx
           ON ${p}_account_resets (account_id)
           WHERE kind = 'signed-in' AND completed_at IS NULL AND aborted_at IS NULL`,
        // An account's resets: the live email codes that an email change, a
        // setting change or a completion closes, and the account-delete
        // cascade.
        `CREATE INDEX IF NOT EXISTS ${p}_account_resets_account_idx
           ON ${p}_account_resets (account_id, created_at DESC)`,
        // `pruneExpired` deletes rows a day after they expire.
        `CREATE INDEX IF NOT EXISTS ${p}_account_resets_expires_idx
           ON ${p}_account_resets (expires_at)`,
      ]),
    }),
    Object.freeze({
      version: 9,
      name: "signed-in-reset-cancellation-fence",
      statements: Object.freeze([
        `ALTER TABLE ${p}_accounts ADD COLUMN IF NOT EXISTS reset_generation bigint NOT NULL DEFAULT 0`,
        `ALTER TABLE ${p}_account_resets ADD COLUMN IF NOT EXISTS reset_generation bigint NOT NULL DEFAULT 0`,
      ]),
    }),
    Object.freeze({
      version: 10,
      name: "coalesced-email-resets",
      statements: Object.freeze([
        // Existing emailed reset ids were exposed to anonymous starters by
        // earlier SDKs. Close every such challenge before coalescing starts.
        `UPDATE ${p}_account_resets
            SET aborted_at = now()
          WHERE kind = 'email' AND completed_at IS NULL AND aborted_at IS NULL`,
        // Earlier anonymous starts could spend this quota without leaving a
        // usable mailbox challenge. Do not carry that denial into the cutover.
        `DELETE FROM ${p}_rate_limits WHERE rule_id = 'account-reset-recipient'`,
        `CREATE UNIQUE INDEX IF NOT EXISTS ${p}_account_resets_email_live_idx
           ON ${p}_account_resets (account_id)
           WHERE kind = 'email' AND completed_at IS NULL AND aborted_at IS NULL`,
        // A function keeps the account lock through a fresh READ COMMITTED
        // snapshot, the recipient reservation and issuance. Stateless SQL
        // transports cannot hold this lock across separate SDK queries.
        `CREATE OR REPLACE FUNCTION ${p}_start_email_reset(
           profile_id text, normalized_name text, recipient_prefix text,
           recipient_rule text, recipient_window double precision,
           recipient_limit integer, new_reset_id uuid, new_code_hash text,
           ttl_seconds double precision, request_at timestamptz
         ) RETURNS TABLE (delivery_email text, issued integer, expires_at timestamptz)
         LANGUAGE plpgsql AS $reset$
         DECLARE
           clock_at timestamptz := COALESCE(request_at, now());
           owner_id uuid;
           address text;
           recipient_count integer;
         BEGIN
           delivery_email := NULL;
           issued := 0;
           expires_at := date_trunc('milliseconds', clock_at + interval '1 second' * ttl_seconds);
           SELECT a.id, a.email INTO owner_id, address
             FROM ${p}_accounts a
            WHERE a.service_profile_id = profile_id
              AND a.username_normalized = normalized_name
              AND a.status = 'active'
              AND a.email_reset_enabled
              AND a.email IS NOT NULL
              AND a.email_verified_at IS NOT NULL
            FOR NO KEY UPDATE OF a;
           IF owner_id IS NULL THEN RETURN NEXT; RETURN; END IF;

           UPDATE ${p}_account_resets r SET aborted_at = clock_at
            WHERE r.account_id = owner_id AND r.kind = 'email'
              AND r.completed_at IS NULL AND r.aborted_at IS NULL
              AND r.expires_at <= clock_at;
           PERFORM 1 FROM ${p}_account_resets r
            WHERE r.account_id = owner_id AND r.kind = 'email'
              AND r.completed_at IS NULL AND r.aborted_at IS NULL;
           IF FOUND THEN RETURN NEXT; RETURN; END IF;

           INSERT INTO ${p}_rate_limits AS rl (bucket, rule_id, count, window_start, updated_at)
           VALUES (encode(sha256(convert_to(recipient_prefix || address, 'UTF8')), 'hex'),
                   recipient_rule, 1, clock_at, clock_at)
           ON CONFLICT (bucket) DO UPDATE
             SET count = CASE
                   WHEN rl.window_start + interval '1 second' * recipient_window <= excluded.updated_at
                   THEN 1 ELSE rl.count + 1 END,
                 window_start = CASE
                   WHEN rl.window_start + interval '1 second' * recipient_window <= excluded.updated_at
                   THEN excluded.window_start ELSE rl.window_start END,
                 updated_at = excluded.updated_at
           RETURNING rl.count INTO recipient_count;
           IF recipient_count > recipient_limit THEN RETURN NEXT; RETURN; END IF;

           INSERT INTO ${p}_account_resets
             (id, account_id, kind, code_hash, attempts, created_at, available_at, expires_at)
           VALUES (new_reset_id, owner_id, 'email', new_code_hash, 0, clock_at, clock_at, expires_at);
           INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
           VALUES (owner_id, 'account.email-reset.start', jsonb_build_object('method', 'email'), clock_at);
           delivery_email := address;
           issued := 1;
           RETURN NEXT;
         END;
         $reset$`,
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
