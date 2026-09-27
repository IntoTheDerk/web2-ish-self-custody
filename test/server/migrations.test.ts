import { describe, expect, it } from "vitest";
import { zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import type { DerivationProfile } from "../../src/profile.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import { identityMigrations } from "../../src/server/migrations.js";
import type { ResolvedIdentityServiceConfig } from "../../src/server/types.js";

const config = resolveIdentityServiceConfig({
  serviceProfileId: "acme.identity",
  profile: zeraEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "zera-mainnet",
  tablePrefix: "acme_id",
});

const migrations = identityMigrations(config);
const statements = migrations.flatMap((migration) => migration.statements);
const sql = statements.join("\n;\n");

function expectIdentityError(run: () => unknown, code: IdentityErrorCode): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe(code);
    return;
  }
  throw new Error(`Expected an IdentityError with code "${code}" but nothing was thrown.`);
}

function withConfig(
  overrides: Partial<ResolvedIdentityServiceConfig>,
): ResolvedIdentityServiceConfig {
  return { ...config, ...overrides };
}

/** A profile that never passed `defineDerivationProfile`, as a hostile caller's would not. */
function forgedProfile(overrides: Record<string, unknown>): DerivationProfile {
  return {
    ...zeraEd25519ExternalSalt,
    ...overrides,
  } as unknown as DerivationProfile;
}

function statementContaining(...needles: readonly string[]): string {
  const match = statements.find((statement) =>
    needles.every((needle) => statement.includes(needle)),
  );
  if (match === undefined) {
    throw new Error(`No generated statement contains all of: ${needles.join(", ")}`);
  }
  return match;
}

describe("identityMigrations input validation", () => {
  it("rejects table prefixes that are not lowercase snake_case identifiers", () => {
    for (const tablePrefix of [
      "",
      "W2SC",
      "1w2sc",
      "w2sc-test",
      "w2sc test",
      "w2sc;",
      'w2sc"',
      "w2sc_accounts; DROP TABLE w2sc_accounts; --",
      "a".repeat(33),
    ]) {
      expectIdentityError(
        () => identityMigrations(withConfig({ tablePrefix })),
        "invalid-service-profile",
      );
    }
  });

  it("rejects injection attempts in every interpolated literal", () => {
    const injection = "x'; DROP TABLE acme_id_accounts; --";
    const rejected: readonly Partial<ResolvedIdentityServiceConfig>[] = [
      { serviceProfileId: injection },
      { applicationId: injection },
      { networkId: injection },
      { serviceProfileId: "" },
      { applicationId: "Example-App" },
      { networkId: "zera mainnet" },
      { serviceProfileId: "acme.identity'" },
      { serviceProfileId: `a${"b".repeat(80)}` },
    ];
    for (const overrides of rejected) {
      expectIdentityError(
        () => identityMigrations(withConfig(overrides)),
        "invalid-service-profile",
      );
    }
  });

  it("re-validates the profile's own literals rather than trusting the object", () => {
    // A profile reaches DDL through `ResolvedIdentityServiceConfig`, which a
    // caller can construct by hand; every value it contributes is interpolated.
    const rejected: readonly Record<string, unknown>[] = [
      { id: "x'; DROP TABLE acme_id_accounts; --" },
      { algorithm: "x'; DROP TABLE acme_id_accounts; --" },
      { codec: { ...zeraEd25519ExternalSalt.codec, id: "x'; DROP TABLE acme_id_accounts; --" } },
      { id: "" },
      { codec: { ...zeraEd25519ExternalSalt.codec, id: "Zera-Ed25519" } },
    ];
    for (const overrides of rejected) {
      expectIdentityError(
        () => identityMigrations(withConfig({ profile: forgedProfile(overrides) })),
        "invalid-service-profile",
      );
    }
  });

  it("accepts the maximum-length identifier and literal forms", () => {
    expect(() =>
      identityMigrations(
        withConfig({
          tablePrefix: `a${"b".repeat(31)}`,
          serviceProfileId: `a${"b".repeat(79)}`,
        }),
      ),
    ).not.toThrow();
  });
});

describe("generated migration SQL", () => {
  it("numbers migrations contiguously from 1 and never emits an empty migration", () => {
    expect(migrations.map((migration) => migration.version)).toEqual(
      migrations.map((_migration, index) => index + 1),
    );
    expect(migrations.length).toBeGreaterThan(0);
    expect(Object.isFrozen(migrations)).toBe(true);

    for (const migration of migrations) {
      expect(migration.statements.length).toBeGreaterThan(0);
      expect(migration.name.length).toBeGreaterThan(0);
      expect(Object.isFrozen(migration)).toBe(true);
      expect(Object.isFrozen(migration.statements)).toBe(true);
      for (const statement of migration.statements) {
        expect(statement.trim().length).toBeGreaterThan(0);
      }
    }
  });

  it("never uses positional placeholders, because DDL cannot bind them", () => {
    for (const statement of statements) {
      expect(statement).not.toMatch(/\$\d/u);
    }
  });

  it("namespaces every object under the configured table prefix", () => {
    expect(sql).not.toContain("w2sc_");
    for (const table of [
      "acme_id_service_profiles",
      "acme_id_service_profile_bootstrap",
      "acme_id_accounts",
      "acme_id_account_wallets",
      "acme_id_auth_challenges",
      "acme_id_sessions",
      "acme_id_email_verifications",
      "acme_id_rate_limits",
      "acme_id_audit_events",
    ]) {
      expect(sql).toContain(table);
    }
  });

  it("installs immutability triggers on the profile and bootstrap tables", () => {
    expect(sql).toContain("CREATE OR REPLACE FUNCTION acme_id_reject_immutable_mutation()");
    expect(sql).toContain("RAISE EXCEPTION 'wallet derivation service profile is immutable'");
    expect(sql).toContain("USING ERRCODE = '55000'");

    for (const trigger of [
      "acme_id_service_profiles_immutable",
      "acme_id_service_profiles_no_truncate",
      "acme_id_bootstrap_immutable",
      "acme_id_bootstrap_no_truncate",
    ]) {
      expect(sql).toContain(`CREATE TRIGGER ${trigger}`);
    }

    // Triggers are created inside an exception handler rather than by
    // DROP-then-CREATE: the drop would leave a window in which the table is
    // unprotected while a second migration runner is mid-flight.
    expect(sql).not.toContain("DROP TRIGGER");
    expect(sql).toContain("EXCEPTION WHEN duplicate_object THEN");

    expect(sql).toContain("BEFORE UPDATE OR DELETE ON acme_id_service_profiles");
    expect(sql).toContain("BEFORE TRUNCATE ON acme_id_service_profiles");
    expect(sql).toContain("BEFORE UPDATE OR DELETE ON acme_id_service_profile_bootstrap");
    expect(sql).toContain("BEFORE TRUNCATE ON acme_id_service_profile_bootstrap");
    expect(sql).toContain("EXECUTE FUNCTION acme_id_reject_immutable_mutation()");
  });

  it("fails closed when bootstrap was recorded but the profile row is gone", () => {
    const guard = statementContaining(
      "acme_id_service_profile_bootstrap",
      "RAISE EXCEPTION",
    );

    expect(guard).toContain(
      "'service profile acme.identity is missing; restore its original public salt from backup'",
    );

    // The guard only provisions a salt when bootstrap has never been recorded.
    const bootstrapCheck = guard.indexOf("acme_id_service_profile_bootstrap");
    const profileCheck = guard.indexOf("IF NOT EXISTS (");
    const raise = guard.indexOf("RAISE EXCEPTION");
    const insert = guard.indexOf("INSERT INTO acme_id_service_profiles");
    expect(bootstrapCheck).toBeGreaterThanOrEqual(0);
    expect(profileCheck).toBeGreaterThan(bootstrapCheck);
    expect(raise).toBeGreaterThan(profileCheck);
    expect(insert).toBeGreaterThan(raise);
    expect(guard).toContain("gen_random_bytes(32)");
    expect(guard).toContain("ON CONFLICT (service_profile_id) DO NOTHING");
  });

  it("pins the service profile row to the configured derivation parameters", () => {
    const table = statementContaining("CREATE TABLE IF NOT EXISTS acme_id_service_profiles");
    expect(table).toContain("service_profile_id = 'acme.identity'");
    expect(table).toContain("profile_id = 'web2ish-zera-ed25519-external-salt-v1'");
    expect(table).toContain("algorithm = 'scrypt-sha512-ed25519-external-32-v1'");
    expect(table).toContain("curve = 'ed25519'");
    expect(table).toContain("application_id = 'example-app'");
    expect(table).toContain("network_id = 'zera-mainnet'");
    expect(table).toContain("octet_length(public_salt) = 32");
    expect(table).toContain("public_salt <> decode(repeat('00', 32), 'hex')");
    expect(table).toContain("kdf_n = 65536");
    expect(table).toContain("kdf_r = 8");
    expect(table).toContain("kdf_p = 1");
    expect(table).toContain("kdf_dk_len = 32");
  });

  it("records and pins each wallet's address encoding", () => {
    const table = statementContaining("CREATE TABLE IF NOT EXISTS acme_id_account_wallets");

    // Without the stored codec id, a deployment that ever changed encodings
    // could not tell which convention produced an existing address.
    expect(table).toContain("codec_id text NOT NULL");
    expect(table).toContain("codec_id = 'zera-ed25519-base58-v1'");
    expect(table).toContain("profile_id = 'web2ish-zera-ed25519-external-salt-v1'");
    expect(table).toContain("curve = 'ed25519'");
    expect(table).toContain("application_id = 'example-app'");
    expect(table).toContain("network_id = 'zera-mainnet'");
    expect(table).toContain("address_normalized = lower(address)");
  });

  it("stores only hashed session and verification secrets", () => {
    const sessions = statementContaining("CREATE TABLE IF NOT EXISTS acme_id_sessions");
    expect(sessions).toContain("token_hash text NOT NULL UNIQUE");
    expect(sessions).toContain("token_hash ~ '^[0-9a-f]{64}$'");
    expect(sessions).not.toContain("token text");

    const verifications = statementContaining(
      "CREATE TABLE IF NOT EXISTS acme_id_email_verifications",
    );
    expect(verifications).toContain("code_hash ~ '^[0-9a-f]{64}$'");
    expect(verifications).not.toContain("code text");
  });

  it("keeps no column that could reconstruct a wallet", () => {
    for (const forbidden of [
      "password",
      "password_hash",
      "seed",
      "secret_key",
      "private_key",
      "ciphertext",
      "recovery",
    ]) {
      expect(sql.toLowerCase()).not.toContain(forbidden);
    }
  });
});

describe("public salt provisioning", () => {
  it("always has the database mint the salt", () => {
    // The salt is generated by pgcrypto inside the migration, never supplied by
    // configuration, and never interpolated from caller text.
    expect(sql).toContain("gen_random_bytes(32)");
    expect(sql).not.toMatch(/public_salt[^;]*decode\('[0-9a-f]{64}'/u);
    expect(sql).not.toContain("adoptPublicSaltHex");
  });

  it("fails closed when the profile row was deleted after bootstrap", () => {
    expect(sql).toContain("restore its original public salt from backup");
  });
});
