import { describe, expect, it } from "vitest";
import { signInEd25519ExternalSalt } from "../../src/index.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import type { IdentityService } from "../../src/server/contract.js";
import { IdentityError, identityErrorStatus, type IdentityErrorCode } from "../../src/server/errors.js";
import { identityMigrations } from "../../src/server/migrations.js";
import { createIdentityRouter } from "../../src/server/router.js";
import {
  generateSecondFactorTicket,
  hashSecondFactorTicket,
  hashSessionToken,
} from "../../src/server/tokens.js";
import type {
  IdentityServiceConfig,
  IssuedSession,
  SecondFactorIdentityServiceConfig,
  SecondFactorOptions,
} from "../../src/server/types.js";

/**
 * The second factor and account deletion without a database: the option's
 * resolution, the migrations, the ticket digest, the error codes and the
 * router's wiring against a stub service. The behavior over PostgreSQL is in
 * secondFactor.integration.test.ts and accountDeletion.integration.test.ts.
 */

const minimal: IdentityServiceConfig = {
  serviceProfileId: "example.identity",
  profile: signInEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "example-network",
};

const factor: SecondFactorOptions = {
  required: async () => true,
  verify: async () => "ok",
};

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

describe("the secondFactor option", () => {
  it("resolves to no key at all when unset, so existing configs resolve unchanged", () => {
    expect("secondFactor" in resolveIdentityServiceConfig(minimal)).toBe(false);
    expect("secondFactor" in resolveIdentityServiceConfig({ ...minimal, secondFactor: null })).toBe(false);
  });

  it("keeps the two functions, frozen, and resolves a resolved config to itself", () => {
    const resolved = resolveIdentityServiceConfig({ ...minimal, secondFactor: factor });
    expect(resolved.secondFactor?.required).toBe(factor.required);
    expect(resolved.secondFactor?.verify).toBe(factor.verify);
    expect(Object.isFrozen(resolved.secondFactor)).toBe(true);
    expect(resolveIdentityServiceConfig(resolved as SecondFactorIdentityServiceConfig).secondFactor?.verify).toBe(factor.verify);
  });

  it("refuses anything but exactly { required, verify } as functions", () => {
    const bad: unknown[] = [
      true,
      "totp",
      [],
      {},
      { required: factor.required },
      { verify: factor.verify },
      { required: true, verify: factor.verify },
      { required: factor.required, verify: "ok" },
      { ...factor, codeLength: 6 },
    ];
    for (const secondFactor of bad) {
      expectIdentityError(
        () => resolveIdentityServiceConfig({ ...minimal, secondFactor } as unknown as SecondFactorIdentityServiceConfig),
        "invalid-service-profile",
      );
    }
  });
});

describe("migrations 12 and 13", () => {
  const migrations = identityMigrations(resolveIdentityServiceConfig({ ...minimal, tablePrefix: "acme" }));

  it("add the ticket table and the deleted-account audit columns, idempotently", () => {
    const twelve = migrations.find((migration) => migration.version === 12);
    const thirteen = migrations.find((migration) => migration.version === 13);
    expect(twelve?.name).toBe("second-factor-tickets");
    expect(thirteen?.name).toBe("account-deletion");
    for (const statement of [...twelve!.statements, ...thirteen!.statements]) {
      expect(statement).toMatch(/IF NOT EXISTS|CREATE OR REPLACE FUNCTION|^DO \$trg\$/u);
    }
    const table = twelve!.statements[0]!;
    expect(table).toContain("acme_second_factor_tickets");
    expect(table).toContain("REFERENCES acme_accounts(id) ON DELETE CASCADE");
    expect(table).toContain("ticket_hash text NOT NULL UNIQUE");
    expect(table).toContain("challenge_id uuid NOT NULL UNIQUE");
    expect(table).toContain("attempts BETWEEN 0 AND 5");
    // No factor data: nothing that could hold a secret or a code.
    expect(table).not.toMatch(/secret|code\b|totp/iu);
  });

  it("leave every earlier migration as it was", () => {
    expect(migrations.map((migration) => migration.version)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]);
  });
});

describe("second-factor tickets", () => {
  it("are 32 random bytes in base64url, stored as a domain-separated digest", () => {
    const ticket = generateSecondFactorTicket();
    expect(ticket).toMatch(/^[A-Za-z0-9_-]{43}$/u);
    expect(generateSecondFactorTicket()).not.toBe(ticket);
    const digest = hashSecondFactorTicket("example.identity", ticket);
    expect(digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(digest).not.toBe(hashSessionToken(ticket));
    expect(digest).not.toBe(hashSecondFactorTicket("other.identity", ticket));
  });
});

describe("error codes", () => {
  it("give the new refusals their statuses", () => {
    expect(identityErrorStatus("account-has-sessions")).toBe(409);
    expect(identityErrorStatus("second-factor-invalid")).toBe(401);
    expect(identityErrorStatus("second-factor-locked")).toBe(423);
    expect(identityErrorStatus("second-factor-ticket-invalid")).toBe(401);
  });
});

describe("the router's second-factor wiring", () => {
  const at = new Date("2026-10-23T12:00:00.000Z");
  const issued: IssuedSession = {
    token: "token-issued",
    session: { id: "0b6a7d8e-1c2f-4a3b-8c9d-0e1f2a3b4c5d", accountId: "a", issuedAt: at, expiresAt: at, lastSeenAt: at },
  };

  function stub(withFactor: boolean, calls: string[]): IdentityService<boolean> {
    return {
      config: resolveIdentityServiceConfig(withFactor ? { ...minimal, secondFactor: factor } : minimal),
      async login() {
        calls.push("login");
        return withFactor
          ? { account: { id: "a" }, secondFactor: "totp", ticket: "t".repeat(43), expiresAt: at }
          : { account: { id: "a" }, session: issued };
      },
      async completeSecondFactor(input: unknown) {
        calls.push(`complete:${JSON.stringify(input)}`);
        return { account: { id: "a" }, session: issued, purpose: "login" };
      },
      async revokeSessionById() {
        calls.push("revokeSessionById");
        return { revoked: false };
      },
    } as unknown as IdentityService<boolean>;
  }

  const post = (router: (request: Request) => Promise<Response>, path: string, body: unknown) =>
    router(
      new Request(`https://id.example/identity${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
    );

  it("answers a pending login with the ticket only, and no cookie", async () => {
    const calls: string[] = [];
    const response = await post(createIdentityRouter(stub(true, calls)), "/sessions", { username: "u", challengeId: "c", signature: "s" });
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(await response.json()).toEqual({ secondFactor: "totp", ticket: "t".repeat(43), expiresAt: at.toISOString() });
  });

  it("mounts POST /sessions/second-factor only with the option, and passes exactly ticket and code", async () => {
    const calls: string[] = [];
    const response = await post(createIdentityRouter(stub(true, calls)), "/sessions/second-factor", { ticket: "x", code: "123456" });
    expect(response.status).toBe(200);
    expect(response.headers.get("set-cookie")).toMatch(/^__Host-w2sc_session=token-issued;/u);
    expect(calls).toEqual([`complete:${JSON.stringify({ ticket: "x", code: "123456" })}`]);

    const without: string[] = [];
    const plain = await post(createIdentityRouter(stub(false, without)), "/sessions/second-factor", { ticket: "x", code: "1" });
    expect(plain.status).toBe(404);
    expect(without).toEqual([]);
  });

  it("leaves /sessions/{id} as it was on a router without the option", async () => {
    const calls: string[] = [];
    const router = createIdentityRouter(stub(false, calls), { accountSecurityRoutes: true, useCookies: false });
    const response = await router(
      new Request("https://id.example/identity/sessions/second-factor", {
        method: "DELETE",
        headers: { authorization: "Bearer token" },
      }),
    );
    expect(response.status).toBe(200);
    expect(calls).toEqual(["revokeSessionById"]);
  });
});
