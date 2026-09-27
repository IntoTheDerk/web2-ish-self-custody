import { describe, expect, it } from "vitest";
import { zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import { identityMigrations } from "../../src/server/migrations.js";
import {
  platformSaltMigration,
  type PlatformSaltConfig,
} from "../../src/server/serviceProfile.js";
import { krypticStateless } from "../support/kryptic-chain.js";

const config: PlatformSaltConfig = {
  serviceProfileId: "acme.identity",
  profile: zeraEd25519ExternalSalt,
  applicationId: "knight-armor",
  networkId: "zera-mainnet",
  tablePrefix: "acme_id",
};

describe("platform salt migration", () => {
  it("is byte-identical to version 1 of the identity schema", () => {
    // The two must not diverge: a database provisioned by a salt-only host has
    // to count as already migrated for a host that later adopts the full
    // identity service, and vice versa.
    const [identityVersionOne] = identityMigrations(resolveIdentityServiceConfig(config));
    const standalone = platformSaltMigration(config);

    expect(standalone.version).toBe(1);
    expect(standalone.name).toBe(identityVersionOne?.name);
    expect(standalone.statements).toEqual(identityVersionOne?.statements);
  });

  it("carries the invariants that make the salt safe to depend on", () => {
    const sql = platformSaltMigration(config).statements.join("\n;\n");

    // 32 bytes, never all zeros.
    expect(sql).toContain("octet_length(public_salt) = 32");
    expect(sql).toContain("public_salt <> decode(repeat('00', 32), 'hex')");
    // Immutable once written, including against TRUNCATE.
    expect(sql).toContain("wallet derivation service profile is immutable");
    expect(sql).toContain("BEFORE TRUNCATE ON acme_id_service_profiles");
    // A wiped profile row must be detectable rather than silently reminted.
    expect(sql).toContain("restore its original public salt from backup");
    // The namespace is pinned to this platform.
    expect(sql).toContain("application_id = 'knight-armor'");
    expect(sql).toContain("network_id = 'zera-mainnet'");
  });

  it("adopts an existing salt instead of minting one", () => {
    const adopted = "5c".repeat(32);
    const sql = platformSaltMigration({ ...config, adoptPublicSaltHex: adopted })
      .statements.join("\n;\n");

    expect(sql).toContain(`decode('${adopted}', 'hex')`);
    expect(sql).not.toContain("gen_random_bytes(32)");
    expect(sql).toContain("already provisioned with a different public salt");
  });

  it("refuses a profile that has no salt for a platform to own", () => {
    // A self-salting profile derives its salt from the username, so a service
    // holding one would be publishing a value clients must ignore.
    expect(() => platformSaltMigration({ ...config, profile: krypticStateless })).toThrowError(
      expect.objectContaining({ code: "invalid-service-profile" }),
    );
  });

  it("rejects an injection attempt in any interpolated field", () => {
    for (const override of [
      { tablePrefix: "acme'; DROP TABLE users; --" },
      { serviceProfileId: "x'; DROP TABLE users; --" },
      { applicationId: "x'; DROP TABLE users; --" },
      { networkId: "x'; DROP TABLE users; --" },
    ] as const) {
      expect(() => platformSaltMigration({ ...config, ...override })).toThrowError(
        expect.objectContaining({ code: "invalid-service-profile" }),
      );
    }
  });

  it("gives each platform a distinct namespace", () => {
    const knightArmor = platformSaltMigration(config).statements.join("");
    const democracyOs = platformSaltMigration({
      ...config,
      serviceProfileId: "democracyos-password-wallet-v1",
      applicationId: "democracy-os",
      tablePrefix: "dos_identity",
    }).statements.join("");

    expect(knightArmor).not.toBe(democracyOs);
    expect(democracyOs).toContain("application_id = 'democracy-os'");
    expect(democracyOs).toContain("dos_identity_service_profiles");
    expect(democracyOs).not.toContain("acme_id_service_profiles");
  });
});
