import { describe, expect, it } from "vitest";
import { signInEd25519ExternalSalt } from "../../src/index.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import type { IdentityService } from "../../src/server/contract.js";
import { IdentityError } from "../../src/server/errors.js";
import { createIdentityRouter, type IdentityRouterOptions } from "../../src/server/router.js";
import type { IssuedSession, ListedSession, RequestContext } from "../../src/server/types.js";

/**
 * The session routes and the client-label hook, against a recording stub
 * service: no database, so this runs in the default `npm test`. The behavior
 * over real PostgreSQL is in sessions.integration.test.ts.
 */

type Call = Readonly<{ method: string; args: readonly unknown[] }>;

const accountId = "6f0d4f7e-8f53-4a9b-9a8e-2f1b0c3d4e5f";
const currentId = "0b6a7d8e-1c2f-4a3b-8c9d-0e1f2a3b4c5d";
const otherId = "9c8b7a6f-5e4d-4c3b-8a2f-1e0d9c8b7a6f";
const at = new Date("2026-10-18T12:00:00.000Z");

const issued: IssuedSession = Object.freeze({
  token: "token-issued",
  session: Object.freeze({ id: currentId, accountId, issuedAt: at, expiresAt: at, lastSeenAt: at }),
});

const listed: readonly ListedSession[] = Object.freeze([
  Object.freeze({ id: currentId, issuedAt: at, lastSeenAt: at, expiresAt: at, clientLabel: "Firefox on macOS", current: true }),
  Object.freeze({ id: otherId, issuedAt: at, lastSeenAt: at, expiresAt: at, clientLabel: null, current: false }),
]);

function stubService(calls: Call[]): IdentityService {
  const record = (method: string) => (...args: readonly unknown[]) => {
    calls.push({ method, args });
  };
  const stub = {
    config: resolveIdentityServiceConfig({
      serviceProfileId: "example.identity",
      profile: signInEd25519ExternalSalt,
      applicationId: "example-app",
      networkId: "example-network",
    }),
    async register(...args: readonly unknown[]) {
      record("register")(...args);
      return { account: { id: accountId }, wallet: { id: "wallet" }, session: issued };
    },
    async login(...args: readonly unknown[]) {
      record("login")(...args);
      return { account: { id: accountId }, session: issued };
    },
    async authenticate(...args: readonly unknown[]) {
      record("authenticate")(...args);
      return { account: { id: accountId }, wallets: [], session: issued.session };
    },
    async listSessions(...args: readonly unknown[]) {
      record("listSessions")(...args);
      return listed;
    },
    async liveSessionIds(...args: readonly unknown[]) {
      record("liveSessionIds")(...args);
      return [currentId, otherId];
    },
    async revokeSessionById(...args: readonly unknown[]) {
      record("revokeSessionById")(...args);
      if (args[1] === currentId) {
        throw new IdentityError("That is the calling session.", "invalid-request");
      }
      return { revoked: args[1] === otherId };
    },
    async revokeOtherSessions(...args: readonly unknown[]) {
      record("revokeOtherSessions")(...args);
      return { revokedSessionIds: [otherId] };
    },
    async revokeSession(...args: readonly unknown[]) {
      record("revokeSession")(...args);
    },
  };
  return stub as unknown as IdentityService;
}

const base = "https://example.test/identity";
const bearer = { Authorization: "Bearer token-caller" };

function routerWith(options: IdentityRouterOptions = {}): Readonly<{
  router: (request: Request) => Promise<Response>;
  calls: Call[];
}> {
  const calls: Call[] = [];
  return { router: createIdentityRouter(stubService(calls), { useCookies: false, ...options }), calls };
}

const signInBody = JSON.stringify({ username: "ada@example.org", challengeId: currentId, signature: "00" });
const registerBody = JSON.stringify({
  username: "ada@example.org", address: "S_x", publicKey: "S_x", challengeId: currentId, signature: "00",
});

function post(path: string, body: string, userAgent = "Mozilla/5.0 Firefox/131.0"): Request {
  return new Request(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "User-Agent": userAgent },
    body,
  });
}

function contextOf(calls: readonly Call[], method: string): RequestContext {
  const call = calls.find((entry) => entry.method === method);
  if (call === undefined) {
    throw new Error(`${method} was not called.`);
  }
  return call.args[call.args.length - 1] as RequestContext;
}

describe("router option validation", () => {
  it("refuses a non-boolean accountSecurityRoutes and a non-function clientLabel", () => {
    const service = stubService([]);
    for (const accountSecurityRoutes of ["true", 1, null]) {
      expect(() => createIdentityRouter(service, { accountSecurityRoutes } as never)).toThrow(TypeError);
    }
    for (const clientLabel of ["Firefox on macOS", 1, null]) {
      expect(() => createIdentityRouter(service, { clientLabel } as never)).toThrow(TypeError);
    }
    expect(() => createIdentityRouter(service, { accountSecurityRoutes: false })).not.toThrow();
  });
});

describe("account session routes", () => {
  it("are absent by default and reach no session-management method", async () => {
    const { router, calls } = routerWith();
    const list = await router(new Request(`${base}/sessions`, { headers: bearer }));
    expect(list.status).toBe(405);
    expect(list.headers.get("allow")).toBe("POST");
    const others = await router(new Request(`${base}/sessions`, { method: "DELETE", headers: bearer }));
    expect(others.status).toBe(405);
    for (const method of ["DELETE", "GET", "POST"]) {
      const one = await router(new Request(`${base}/sessions/${otherId}`, { method, headers: bearer }));
      expect(one.status).toBe(404);
    }
    // Explicitly off is the same as the default.
    const off = routerWith({ accountSecurityRoutes: false });
    expect((await off.router(new Request(`${base}/sessions/${otherId}`, { method: "DELETE", headers: bearer }))).status).toBe(404);
    expect([...calls, ...off.calls]).toEqual([]);
  });

  it("route list, revoke-one and revoke-others to the service with the caller's token", async () => {
    const { router, calls } = routerWith({ accountSecurityRoutes: true });

    const list = await router(new Request(`${base}/sessions`, { headers: bearer }));
    expect(list.status).toBe(200);
    expect(await list.json()).toEqual({ sessions: JSON.parse(JSON.stringify(listed)) });

    const one = await router(new Request(`${base}/sessions/${otherId}`, { method: "DELETE", headers: bearer }));
    expect(await one.json()).toEqual({ revoked: true });
    const unknown = await router(new Request(`${base}/sessions/${accountId}`, { method: "DELETE", headers: bearer }));
    expect(await unknown.json()).toEqual({ revoked: false });
    const self = await router(new Request(`${base}/sessions/${currentId}`, { method: "DELETE", headers: bearer }));
    expect(self.status).toBe(400);

    const others = await router(new Request(`${base}/sessions`, { method: "DELETE", headers: bearer }));
    expect(await others.json()).toEqual({ revokedSessionIds: [otherId] });

    // Login still answers on /sessions, and sign-out on /sessions/current.
    expect((await router(post("/sessions", signInBody))).status).toBe(200);
    const signOut = await router(new Request(`${base}/sessions/current`, { method: "DELETE", headers: bearer }));
    expect(await signOut.json()).toEqual({ revoked: true });

    // A nested path is no session id.
    expect((await router(new Request(`${base}/sessions/${otherId}/x`, { method: "DELETE", headers: bearer }))).status).toBe(404);

    expect(calls.map((call) => [call.method, call.args.slice(0, -1)])).toEqual([
      ["listSessions", ["token-caller"]],
      ["revokeSessionById", ["token-caller", otherId]],
      ["revokeSessionById", ["token-caller", accountId]],
      ["revokeSessionById", ["token-caller", currentId]],
      ["revokeOtherSessions", ["token-caller"]],
      ["login", [{ username: "ada@example.org", challengeId: currentId, signature: "00" }]],
      ["revokeSession", ["token-caller"]],
    ]);
  });

  it("answer 401 without a token and never call the service", async () => {
    const { router, calls } = routerWith({ accountSecurityRoutes: true });
    for (const [method, path] of [["GET", "/sessions"], ["DELETE", "/sessions"], ["DELETE", `/sessions/${otherId}`]] as const) {
      const response = await router(new Request(`${base}${path}`, { method }));
      expect(response.status).toBe(401);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe("session-not-found");
    }
    expect(calls).toEqual([]);
  });
});

describe("clientLabel hook", () => {
  it("passes a valid label to register and login, and only to them", async () => {
    let hookCalls = 0;
    const { router, calls } = routerWith({
      accountSecurityRoutes: true,
      clientLabel: () => {
        hookCalls += 1;
        return "Firefox on macOS";
      },
    });
    expect((await router(post("/accounts", registerBody))).status).toBe(201);
    expect((await router(post("/sessions", signInBody))).status).toBe(200);
    expect(contextOf(calls, "register").clientLabel).toBe("Firefox on macOS");
    expect(contextOf(calls, "login").clientLabel).toBe("Firefox on macOS");
    expect(hookCalls).toBe(2);

    await router(new Request(`${base}/sessions`, { headers: bearer }));
    await router(new Request(`${base}/sessions/current`, { headers: bearer }));
    await router(new Request(`${base}/sessions/${otherId}`, { method: "DELETE", headers: bearer }));
    expect(hookCalls).toBe(2);
    for (const method of ["listSessions", "authenticate", "revokeSessionById"]) {
      expect(contextOf(calls, method)).not.toHaveProperty("clientLabel");
    }
  });

  it("drops an invalid label and survives a throwing hook without failing the sign-in", async () => {
    const results: readonly unknown[] = [
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      "a".repeat(65),
      "",
      "Firefox on macOS\n",
      42,
      null,
      undefined,
    ];
    for (const result of results) {
      const { router, calls } = routerWith({ clientLabel: () => result as string | undefined });
      expect((await router(post("/sessions", signInBody))).status).toBe(200);
      expect(contextOf(calls, "login")).not.toHaveProperty("clientLabel");
    }
    const { router, calls } = routerWith({
      clientLabel: () => {
        throw new Error("parser bug");
      },
    });
    expect((await router(post("/accounts", registerBody))).status).toBe(201);
    expect((await router(post("/sessions", signInBody))).status).toBe(200);
    expect(contextOf(calls, "register")).not.toHaveProperty("clientLabel");
    expect(contextOf(calls, "login")).not.toHaveProperty("clientLabel");
  });

  it("passes no label at all when no hook is configured", async () => {
    const { router, calls } = routerWith();
    expect((await router(post("/sessions", signInBody))).status).toBe(200);
    const context = contextOf(calls, "login");
    expect(context).not.toHaveProperty("clientLabel");
    // The user-agent hash is unchanged by this option.
    expect(context.userAgentHash).toMatch(/^[0-9a-f]{64}$/u);
  });
});
