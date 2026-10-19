import { describe, expect, it } from "vitest";
import { signInEd25519ExternalSalt } from "../../src/index.js";
import { resolveIdentityServiceConfig } from "../../src/server/config.js";
import type { IdentityService } from "../../src/server/contract.js";
import {
  createIdentityRouter,
  createSessionResponder,
  type IdentityRouterOptions,
} from "../../src/server/index.js";
import type { IssuedSession } from "../../src/server/types.js";

/**
 * `createSessionResponder` answers exactly as the router's login route does,
 * in cookie mode and in bearer mode, so a host route that issues a session
 * around its own statements (a recovery completion) cannot drift from it.
 */

const at = new Date("2026-10-18T12:00:00.000Z");
const issued: IssuedSession = Object.freeze({
  token: "token-with/odd+chars=",
  session: Object.freeze({
    id: "0b6a7d8e-1c2f-4a3b-8c9d-0e1f2a3b4c5d",
    accountId: "6f0d4f7e-8f53-4a9b-9a8e-2f1b0c3d4e5f",
    issuedAt: at,
    expiresAt: new Date(at.getTime() + 7_200_000),
    lastSeenAt: at,
  }),
});
const account = Object.freeze({ id: issued.session.accountId, usernameNormalized: "ada@example.org" });

function stubService(): IdentityService {
  return {
    config: resolveIdentityServiceConfig({
      serviceProfileId: "example.identity",
      profile: signInEd25519ExternalSalt,
      applicationId: "example-app",
      networkId: "example-network",
      sessionTtlSeconds: 7_200,
    }),
    async login() {
      return { account, session: issued };
    },
  } as unknown as IdentityService;
}

async function viaRouter(options: IdentityRouterOptions): Promise<Response> {
  const router = createIdentityRouter(stubService(), options);
  return router(
    new Request("https://example.test/identity/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "ada@example.org", challengeId: "c", signature: "s" }),
    }),
  );
}

async function snapshot(response: Response): Promise<unknown> {
  const headers: string[] = [];
  response.headers.forEach((value, name) => {
    headers.push(`${name}: ${value}`);
  });
  return { status: response.status, headers: headers.sort(), body: await response.json() };
}

describe("createSessionResponder", () => {
  const variants: readonly IdentityRouterOptions[] = [
    {},
    { useCookies: false },
    { cookieName: "example_session", cookieDomain: "example.test" },
    { cookieName: "__Host-example", basePath: "/api/identity" },
  ];

  it("answers byte for byte as the router's login does, cookie and bearer", async () => {
    for (const options of variants) {
      const responder = createSessionResponder(stubService(), options);
      const expected = await snapshot(await viaRouter({ ...options, basePath: "/identity" }));
      expect(await snapshot(responder({ account }, issued, 200))).toEqual(expected);
      // 200 is the default status, as the router's login answers.
      expect(await snapshot(responder({ account }, issued))).toEqual(expected);
    }
  });

  it("sets the cookie with the service's session lifetime and withholds the token", async () => {
    const response = createSessionResponder(stubService())({ account, committed: true }, issued, 200);
    expect(response.headers.get("set-cookie")).toBe(
      "__Host-w2sc_session=token-with%2Fodd%2Bchars%3D; Path=/; Max-Age=7200; HttpOnly; Secure; SameSite=Lax",
    );
    const body = (await response.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(["account", "committed", "session"]);
    expect(JSON.stringify(body)).not.toContain(issued.token);
  });

  it("puts the token in the body and sets no cookie in bearer mode", async () => {
    const response = createSessionResponder(stubService(), { useCookies: false })(
      { account, committed: false },
      issued,
      201,
    );
    expect(response.status).toBe(201);
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(((await response.json()) as Record<string, unknown>)["token"]).toBe(issued.token);
  });

  it("refuses the cookie options the router refuses", () => {
    expect(() => createSessionResponder(stubService(), { cookieName: "bad name" })).toThrow(TypeError);
    expect(() =>
      createSessionResponder(stubService(), { cookieName: "__Host-x", cookieDomain: "example.test" }),
    ).toThrow(TypeError);
    expect(() => createIdentityRouter(stubService(), { cookieName: "bad name" })).toThrow(TypeError);
  });
});
