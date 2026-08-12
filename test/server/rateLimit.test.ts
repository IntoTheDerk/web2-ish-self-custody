import { describe, expect, it } from "vitest";
import { zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import { IdentityError } from "../../src/server/errors.js";
import { createIdentityService } from "../../src/server/service.js";
import type { SqlDriver, SqlParameter, SqlRow } from "../../src/server/sql.js";

const username = "Jesse@Example.com";
const publicKeyBytes = new Uint8Array(32).fill(7);
const codec = zeraEd25519ExternalSalt.codec;

type RateLimitCall = Readonly<{
  rule: string;
  bucket: string;
  parameters: readonly SqlParameter[];
}>;

function rateLimitedDriver(calls: RateLimitCall[]): SqlDriver {
  return {
    kind: "rate-limit-test",
    async query<T extends SqlRow = SqlRow>(
      text: string,
      parameters: readonly SqlParameter[] = [],
    ): Promise<T[]> {
      expect(text).toContain("_rate_limits AS rl");
      calls.push({
        bucket: String(parameters[0]),
        rule: String(parameters[1]),
        parameters,
      });
      return [
        {
          count: 100,
          window_start: new Date("2026-08-12T00:00:00.000Z"),
        } as unknown as T,
      ];
    },
  };
}

async function expectRateLimited(run: () => Promise<unknown>): Promise<void> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    expect((error as IdentityError).code).toBe("rate-limited");
    return;
  }
  throw new Error("Expected request to be rate limited.");
}

describe("identity service rate-limit buckets", () => {
  it("isolates challenge, registration, and login budgets by pre-hashed IP", async () => {
    const calls: RateLimitCall[] = [];
    const service = createIdentityService(rateLimitedDriver(calls), {
      serviceProfileId: "rate-limit-test",
      profile: zeraEd25519ExternalSalt,
      applicationId: "knight-armor",
      networkId: "zera-mainnet",
      tablePrefix: "rate_limit_test",
    });
    const contexts = [
      { ipHash: "hashed-ip-a", now: new Date("2026-08-12T00:00:01.000Z") },
      { ipHash: "hashed-ip-a", now: new Date("2026-08-12T00:00:01.000Z") },
      { ipHash: "hashed-ip-b", now: new Date("2026-08-12T00:00:01.000Z") },
    ] as const;
    const registration = {
      username,
      address: codec.encodeAddress(publicKeyBytes),
      publicKey: codec.encodePublicKey(publicKeyBytes),
      challengeId: "not-reached",
      signature: "not-reached",
    };

    for (const context of contexts) {
      await expectRateLimited(() =>
        service.createChallenge(username, "login", context),
      );
    }
    for (const context of contexts) {
      await expectRateLimited(() => service.register(registration, context));
    }
    for (const context of contexts) {
      await expectRateLimited(() =>
        service.login(
          { username, challengeId: "not-reached", signature: "not-reached" },
          context,
        ),
      );
    }

    expect(calls.map((call) => call.rule)).toEqual([
      "challenge",
      "challenge",
      "challenge",
      "register",
      "register",
      "register",
      "login",
      "login",
      "login",
    ]);
    for (let offset = 0; offset < calls.length; offset += 3) {
      expect(calls[offset]?.bucket).toBe(calls[offset + 1]?.bucket);
      expect(calls[offset]?.bucket).not.toBe(calls[offset + 2]?.bucket);
    }
    for (const call of calls) {
      expect(call.bucket).toMatch(/^[0-9a-f]{64}$/u);
      expect(call.parameters).not.toContain(username);
      expect(call.parameters).not.toContain("hashed-ip-a");
      expect(call.parameters).not.toContain("hashed-ip-b");
    }
  });

  it("uses one conservative bucket when the host supplies no usable IP hash", async () => {
    const calls: RateLimitCall[] = [];
    const service = createIdentityService(rateLimitedDriver(calls), {
      serviceProfileId: "rate-limit-test",
      profile: zeraEd25519ExternalSalt,
      applicationId: "knight-armor",
      networkId: "zera-mainnet",
      tablePrefix: "rate_limit_test",
    });

    await expectRateLimited(() => service.createChallenge(username, "login"));
    await expectRateLimited(() =>
      service.createChallenge(username.toLowerCase(), "login", { ipHash: " " }),
    );

    expect(calls[0]?.bucket).toBe(calls[1]?.bucket);
  });
});
