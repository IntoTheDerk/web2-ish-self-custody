import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { kalvoraEd25519ExternalSalt } from "../../src/chains/kalvora.js";
import { normalizeUsername, withDerivedWallet } from "../../src/index.js";
import { CHALLENGE_DOMAIN } from "../../src/server/challenge.js";
import { createIdentityRouter } from "../../src/server/router.js";
import { createIdentityService } from "../../src/server/service.js";
import {
  neonDriver,
  pgDriver,
  type NeonQueryable,
  type SqlDriver,
} from "../../src/server/sql.js";
import type { IdentityServiceConfig } from "../../src/server/types.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * Real-PostgreSQL coverage of the HTTP surface. The default `npm test` must
 * never need a database, so the whole suite is gated on an explicit connection
 * string.
 *
 * The router is exercised as what it actually is — a
 * `(Request) => Promise<Response>` function — rather than through `node:http`.
 * That keeps this file free of Node type dependencies and, more importantly,
 * tests the same handler object that a Vercel Function and a self-hosted
 * `node:http` server both wrap.
 */
const connectionString = process.env["W2SC_TEST_DATABASE_URL"];

const encoder = new TextEncoder();
const derivationProfile = kalvoraEd25519ExternalSalt;
const profileId = derivationProfile.id;
const codecId = derivationProfile.codec.id;
const applicationId = "example-app";
const networkId = "kalvora-testnet";

const basePath = "/identity";
const trustedOrigin = "https://identity.example";
const foreignOrigin = "https://evil.example";

const derivationTimeoutMs = 120_000;
const databaseTimeoutMs = 60_000;

/** The exact bytes every enumeration-sensitive failure must collapse into. */
const authenticationFailureBody =
  '{"error":{"code":"invalid-signature","message":"Authentication failed."}}';

type Router = (request: Request) => Promise<Response>;

type PgLikeClient = Readonly<{
  query: (
    text: string,
    params?: readonly unknown[],
  ) => Promise<{ rows: Record<string, unknown>[] }>;
  connect?: () => Promise<unknown>;
  end?: () => Promise<unknown>;
}>;

type PgLikeConstructor = new (options: { connectionString: string }) => PgLikeClient;

type DriverHandle = Readonly<{
  driver: SqlDriver;
  close: () => Promise<void>;
}>;

async function importOptional(specifier: string): Promise<Record<string, unknown> | null> {
  try {
    const loaded: unknown = await import(/* @vite-ignore */ specifier);
    return loaded as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** CJS packages surface their exports on `default` under some loaders. */
function namedExport(loaded: Record<string, unknown>, name: string): unknown {
  const direct = loaded[name];
  if (direct !== undefined) {
    return direct;
  }
  const fallback = loaded["default"];
  if (typeof fallback === "object" && fallback !== null) {
    return (fallback as Record<string, unknown>)[name];
  }
  return undefined;
}

async function openDriver(url: string): Promise<DriverHandle | null> {
  // `pg` is not a dependency of this package. W2SC_TEST_PG_MODULE lets a CI job
  // or a developer point at a client that lives elsewhere on disk.
  const specifiers = [process.env["W2SC_TEST_PG_MODULE"], "pg"].filter(
    (specifier): specifier is string => specifier !== undefined && specifier.length > 0,
  );

  for (const specifier of specifiers) {
    const pg = await importOptional(specifier);
    if (pg === null) {
      continue;
    }
    const clientCtor = namedExport(pg, "Client");
    if (typeof clientCtor === "function") {
      const client = new (clientCtor as PgLikeConstructor)({ connectionString: url });
      await client.connect?.();
      return Object.freeze({
        driver: pgDriver(client),
        close: async () => {
          await client.end?.();
        },
      });
    }
  }

  const neonPackage = await importOptional("@neondatabase/serverless");
  if (neonPackage !== null) {
    const neon = namedExport(neonPackage, "neon");
    if (typeof neon === "function") {
      const client = (neon as (value: string) => NeonQueryable)(url);
      return Object.freeze({
        driver: neonDriver(client),
        close: async () => {},
      });
    }
    const poolCtor = namedExport(neonPackage, "Pool");
    if (typeof poolCtor === "function") {
      const pool = new (poolCtor as PgLikeConstructor)({ connectionString: url });
      return Object.freeze({
        driver: pgDriver(pool),
        close: async () => {
          await pool.end?.();
        },
      });
    }
  }

  return null;
}

const driverHandle =
  connectionString === undefined || connectionString.length === 0
    ? null
    : await openDriver(connectionString);

if (connectionString !== undefined && connectionString.length > 0 && driverHandle === null) {
  console.warn(
    "W2SC_TEST_DATABASE_URL is set but no PostgreSQL client could be loaded. " +
      "Install `pg` or `@neondatabase/serverless`, or set W2SC_TEST_PG_MODULE to a client module path, " +
      "to run the identity router integration suite.",
  );
}

function randomSuffix(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function routeUrl(path: string): string {
  return `${trustedOrigin}${basePath}${path}`;
}

function buildRequest(
  path: string,
  method: string,
  headers: Record<string, string>,
  body?: string,
): Request {
  const init: RequestInit =
    body === undefined ? { method, headers } : { method, headers, body };
  return new Request(routeUrl(path), init);
}

function getRequest(path: string, headers: Record<string, string> = {}): Request {
  return buildRequest(path, "GET", headers);
}

function jsonRequest(
  path: string,
  method: string,
  body: unknown,
  headers: Record<string, string> = {},
): Request {
  return buildRequest(
    path,
    method,
    { "content-type": "application/json", origin: trustedOrigin, ...headers },
    JSON.stringify(body),
  );
}

async function readJson(response: Response): Promise<Record<string, unknown>> {
  const parsed: unknown = await response.json();
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Expected a JSON object response body.");
  }
  return parsed as Record<string, unknown>;
}

function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new Error(`Expected "${field}" to be a string in the response body.`);
  }
  return value;
}

function requireObject(
  body: Record<string, unknown>,
  field: string,
): Record<string, unknown> {
  const value = body[field];
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Expected "${field}" to be a JSON object in the response body.`);
  }
  return value as Record<string, unknown>;
}

function requireArray(body: Record<string, unknown>, field: string): readonly unknown[] {
  const value = body[field];
  if (!Array.isArray(value)) {
    throw new Error(`Expected "${field}" to be a JSON array in the response body.`);
  }
  return value;
}

function walletAddresses(body: Record<string, unknown>): readonly unknown[] {
  return requireArray(body, "wallets").map((entry) =>
    typeof entry === "object" && entry !== null
      ? (entry as Record<string, unknown>)["address"]
      : undefined,
  );
}

/** Every property name in a JSON document, however deeply nested. */
function collectKeys(value: unknown, into: string[]): string[] {
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectKeys(entry, into);
    }
  } else if (typeof value === "object" && value !== null) {
    for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
      into.push(key);
      collectKeys(nested, into);
    }
  }
  return into;
}

/** The first cookie-pair of a Set-Cookie header, i.e. what a browser echoes. */
function cookiePair(setCookie: string): string {
  const pair = setCookie.split(";")[0];
  if (pair === undefined || pair.trim() === "") {
    throw new Error("Set-Cookie carried no cookie-pair.");
  }
  return pair.trim();
}

type CapturedResponse = Readonly<{
  status: number;
  headers: Headers;
  body: Record<string, unknown>;
}>;

async function capture(response: Response): Promise<CapturedResponse> {
  return Object.freeze({
    status: response.status,
    headers: response.headers,
    body: await readJson(response),
  });
}

type Harness = Readonly<{
  cookieRouter: Router;
  bearerRouter: Router;
  username: string;
  publicSaltHex: string;
  profile: CapturedResponse;
  challenge: CapturedResponse;
  wallet: Readonly<{ address: string; publicKey: string }>;
  registration: CapturedResponse;
  sessionCookie: string;
  bearerLogin: Readonly<{ challengeId: string; signature: string }>;
}>;

const suffix = randomSuffix();
const tablePrefix = `w2scr${suffix}`;
const serviceProfileId = `w2sc-router-${suffix}`;

const baseConfig: IdentityServiceConfig = {
  serviceProfileId,
  profile: derivationProfile,
  applicationId,
  networkId,
  tablePrefix,
  sessionTtlSeconds: 3_600,
  challengeTtlSeconds: 300,
};

let harness: Harness | undefined;

function h(): Harness {
  if (harness === undefined) {
    throw new Error("The identity router integration harness was not initialized.");
  }
  return harness;
}

describe.skipIf(driverHandle === null)("identity router over PostgreSQL", () => {
  beforeAll(async () => {
    if (driverHandle === null) {
      return;
    }
    const service = createIdentityService(driverHandle.driver, baseConfig);
    await service.migrate();

    const cookieRouter = createIdentityRouter(service, {
      basePath,
      useCookies: true,
      trustedOrigins: [trustedOrigin],
    });
    // Same service, bearer-only transport. `trustedOrigins` is deliberately
    // still set: with no cookie to forge there is nothing for the CSRF gate to
    // protect, so it must not gate these requests at all.
    const bearerRouter = createIdentityRouter(service, {
      basePath,
      useCookies: false,
      trustedOrigins: [trustedOrigin],
    });

    const username = `router-alice-${suffix}@example.com`;
    const password = `router correct horse battery staple ${suffix}`;

    const profile = await capture(await cookieRouter(getRequest("/profile")));
    const publicSaltHex = requireString(profile.body, "publicSaltHex");

    const challenge = await capture(
      await cookieRouter(
        jsonRequest("/challenges", "POST", { username, purpose: "registration" }),
      ),
    );
    // Minted before the single derivation below so both messages can be signed
    // in one pass; scrypt at N=65536 is far too costly to repeat per case.
    const loginChallenge = await capture(
      await cookieRouter(jsonRequest("/challenges", "POST", { username, purpose: "login" })),
    );

    const proof = await withDerivedWallet(
      {
        profile: derivationProfile,
        username,
        password: encoder.encode(password),
        context: { applicationId, networkId },
        salt: hexToBytes(publicSaltHex),
      },
      (wallet) =>
        Object.freeze({
          address: wallet.identity.address,
          publicKey: wallet.identity.publicKey,
          registrationSignature: bytesToHex(
            wallet.signExactMessageUnsafe(
              encoder.encode(requireString(challenge.body, "message")),
            ),
          ),
          loginSignature: bytesToHex(
            wallet.signExactMessageUnsafe(
              encoder.encode(requireString(loginChallenge.body, "message")),
            ),
          ),
        }),
    );

    const registration = await capture(
      await cookieRouter(
        jsonRequest("/accounts", "POST", {
          username,
          displayName: "Router Alice",
          address: proof.address,
          publicKey: proof.publicKey,
          challengeId: requireString(challenge.body, "id"),
          signature: proof.registrationSignature,
        }),
      ),
    );
    const setCookie = registration.headers.get("set-cookie");
    if (setCookie === null) {
      throw new Error("Registration in cookie mode did not issue a Set-Cookie header.");
    }

    harness = Object.freeze({
      cookieRouter,
      bearerRouter,
      username,
      publicSaltHex,
      profile,
      challenge,
      wallet: Object.freeze({ address: proof.address, publicKey: proof.publicKey }),
      registration,
      sessionCookie: cookiePair(setCookie),
      bearerLogin: Object.freeze({
        challengeId: requireString(loginChallenge.body, "id"),
        signature: proof.loginSignature,
      }),
    });
  }, derivationTimeoutMs);

  afterAll(async () => {
    if (driverHandle === null) {
      return;
    }
    // `tablePrefix` is generated here and matches the migration identifier
    // allowlist, so interpolating it into teardown DDL is safe.
    await driverHandle.driver.query(
      `DROP TABLE IF EXISTS
         ${tablePrefix}_wallet_setups,
         ${tablePrefix}_wallet_policy,
         ${tablePrefix}_audit_events,
         ${tablePrefix}_rate_limits,
         ${tablePrefix}_email_verifications,
         ${tablePrefix}_sessions,
         ${tablePrefix}_auth_challenges,
         ${tablePrefix}_account_wallets,
         ${tablePrefix}_accounts,
         ${tablePrefix}_service_profile_bootstrap,
         ${tablePrefix}_service_profiles,
         ${tablePrefix}_schema_migrations
       CASCADE`,
    );
    await driverHandle.driver.query(
      `DROP FUNCTION IF EXISTS ${tablePrefix}_reject_immutable_mutation() CASCADE`,
    );
    await driverHandle.close();
  }, databaseTimeoutMs);

  it("serves the public derivation profile with hardened headers and no secrets", () => {
    const { profile } = h();

    expect(profile.status).toBe(200);
    expect(profile.headers.get("content-type")).toBe("application/json; charset=utf-8");
    // A cached or sniffed identity response is a credential leak waiting to
    // happen, so both headers are part of the contract, not a nicety.
    expect(profile.headers.get("cache-control")).toBe("no-store");
    expect(profile.headers.get("x-content-type-options")).toBe("nosniff");

    expect(profile.body["serviceProfileId"]).toBe(serviceProfileId);
    expect(profile.body["profileId"]).toBe(profileId);
    // A client has to know the address encoding before it enrolls a wallet.
    expect(profile.body["codecId"]).toBe(codecId);
    expect(profile.body["applicationId"]).toBe(applicationId);
    expect(profile.body["networkId"]).toBe(networkId);
    expect(profile.body["curve"]).toBe("ed25519");
    expect(requireString(profile.body, "publicSaltHex")).toMatch(/^[0-9a-f]{64}$/u);
    expect(profile.body["publicSaltHex"]).not.toBe("00".repeat(32));
    expect(requireObject(profile.body, "kdf")).toEqual({ N: 65_536, r: 8, p: 1, dkLen: 32 });

    // Everything published here is public by design; nothing that reads as
    // credential material may ride along.
    const suspicious = collectKeys(profile.body, []).filter((key) =>
      /secret|password|seed|private|token/iu.test(key),
    );
    expect(suspicious).toEqual([]);
    expect(JSON.stringify(profile.body)).not.toMatch(/secret|password|seed/iu);
  });

  it("issues a canonical eight-line challenge over HTTP", () => {
    const { challenge, username } = h();
    expect(challenge.status).toBe(200);

    const lines = requireString(challenge.body, "message").split("\n");
    expect(lines).toHaveLength(8);
    expect(lines[0]).toBe(CHALLENGE_DOMAIN);
    expect(lines[1]).toBe(serviceProfileId);
    expect(lines[2]).toBe(applicationId);
    expect(lines[3]).toBe(networkId);
    expect(lines[4]).toBe("registration");
    expect(lines[5]).toBe(normalizeUsername(username));
    expect(lines[6]).toMatch(/^[0-9a-f]{64}$/u);
    expect(requireString(challenge.body, "id").length).toBeGreaterThan(0);
    expect(challenge.body["purpose"]).toBe("registration");
  });

  it("registers a derived wallet and issues a hardened session cookie", () => {
    const { registration, wallet, username } = h();

    expect(registration.status).toBe(201);
    expect(requireObject(registration.body, "account")["usernameNormalized"]).toBe(
      normalizeUsername(username),
    );
    expect(requireObject(registration.body, "account")["displayName"]).toBe("Router Alice");
    expect(requireObject(registration.body, "wallet")["address"]).toBe(wallet.address);
    expect(requireObject(registration.body, "wallet")["publicKey"]).toBe(wallet.publicKey);
    expect(requireObject(registration.body, "wallet")["codecId"]).toBe(codecId);
    expect(requireObject(registration.body, "wallet")["isPrimary"]).toBe(true);
    expect(requireObject(registration.body, "session")["id"]).toBeTypeOf("string");

    // In cookie mode the raw token must never be echoed: the cookie is
    // HttpOnly precisely so page scripts cannot read it.
    expect(registration.body["token"]).toBeUndefined();
    expect(JSON.stringify(registration.body)).not.toMatch(/seed|password|privateKey/iu);

    const setCookie = registration.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/^__Host-w2sc_session=/u);
    expect(setCookie).toMatch(/HttpOnly/iu);
    expect(setCookie).toMatch(/Secure/iu);
    expect(setCookie).toMatch(/SameSite=Lax/iu);
    expect(setCookie).toMatch(/Path=\//u);
    expect(setCookie).toMatch(/Max-Age=3600/u);
    // `__Host-` is only honored by browsers when no Domain is present.
    expect(setCookie).not.toMatch(/Domain=/iu);
  });

  it("authenticates GET /sessions/current with the session cookie", async () => {
    const { cookieRouter, sessionCookie, wallet, registration } = h();

    const response = await cookieRouter(
      getRequest("/sessions/current", { cookie: sessionCookie }),
    );
    const body = await readJson(response);

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(walletAddresses(body)).toContain(wallet.address);
    expect(requireObject(body, "account")["id"]).toBe(
      requireObject(registration.body, "account")["id"],
    );
    expect(requireObject(body, "session")["id"]).toBe(
      requireObject(registration.body, "session")["id"],
    );
  }, databaseTimeoutMs);

  it("rejects a cookie-authenticated mutation from an untrusted origin", async () => {
    const { cookieRouter, sessionCookie } = h();

    const response = await cookieRouter(
      buildRequest("/sessions/current", "DELETE", {
        cookie: sessionCookie,
        origin: foreignOrigin,
      }),
    );
    const body = await readJson(response);

    expect(response.status).toBe(403);
    expect(requireObject(body, "error")["code"]).toBe("forbidden-origin");
    // The gate must run before the handler, so the session survives untouched.
    expect(response.headers.get("set-cookie")).toBeNull();
    const stillValid = await cookieRouter(
      getRequest("/sessions/current", { cookie: sessionCookie }),
    );
    expect(stillValid.status).toBe(200);
  }, databaseTimeoutMs);

  it("fails an unknown username byte-for-byte like a wrong signature", async () => {
    const { cookieRouter, username } = h();
    const unknownUsername = `router-ghost-${randomSuffix()}@example.com`;

    const unknownChallenge = await readJson(
      await cookieRouter(
        jsonRequest("/challenges", "POST", {
          username: unknownUsername,
          purpose: "login",
        }),
      ),
    );
    const unknownLogin = await cookieRouter(
      jsonRequest("/sessions", "POST", {
        username: unknownUsername,
        challengeId: requireString(unknownChallenge, "id"),
        signature: "ab".repeat(64),
      }),
    );
    const unknownText = await unknownLogin.text();

    const knownChallenge = await readJson(
      await cookieRouter(jsonRequest("/challenges", "POST", { username, purpose: "login" })),
    );
    const wrongSignature = await cookieRouter(
      jsonRequest("/sessions", "POST", {
        username,
        challengeId: requireString(knownChallenge, "id"),
        signature: "cd".repeat(64),
      }),
    );
    const wrongSignatureText = await wrongSignature.text();

    // Any observable difference here — status, code, wording, whitespace —
    // turns login into an account-existence oracle.
    expect(unknownLogin.status).toBe(401);
    expect(wrongSignature.status).toBe(401);
    expect(unknownText).toBe(authenticationFailureBody);
    expect(wrongSignatureText).toBe(authenticationFailureBody);
    expect(unknownText).toBe(wrongSignatureText);
    expect(unknownLogin.headers.get("set-cookie")).toBeNull();
    expect(wrongSignature.headers.get("set-cookie")).toBeNull();
  }, databaseTimeoutMs);

  it("rejects a non-JSON content type with 415", async () => {
    const { cookieRouter } = h();

    const response = await cookieRouter(
      buildRequest(
        "/challenges",
        "POST",
        { "content-type": "text/plain", origin: trustedOrigin },
        "nope",
      ),
    );
    const body = await readJson(response);

    expect(response.status).toBe(415);
    expect(requireObject(body, "error")["code"]).toBe("unsupported-media-type");
  });

  it("rejects an unknown top-level field with 400", async () => {
    const { cookieRouter, username } = h();

    const response = await cookieRouter(
      jsonRequest("/challenges", "POST", { username, purpose: "login", isAdmin: true }),
    );
    const body = await readJson(response);

    // Unknown fields are refused rather than ignored, so a mistyped field is
    // never silently dropped.
    expect(response.status).toBe(400);
    expect(requireObject(body, "error")["code"]).toBe("invalid-request");
    expect(requireObject(body, "error")["message"]).toBe(
      'Unknown field "isAdmin" in request body.',
    );
  });

  it("answers an unknown route with JSON 404", async () => {
    const { cookieRouter } = h();

    const response = await cookieRouter(getRequest("/nope"));
    const body = await readJson(response);

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(requireObject(body, "error")["code"]).toBe("not-found");
  });

  it("answers a wrong method with 405 and an Allow header", async () => {
    const { cookieRouter } = h();

    const response = await cookieRouter(
      buildRequest("/profile", "DELETE", { origin: trustedOrigin }),
    );
    const body = await readJson(response);

    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
    expect(requireObject(body, "error")["code"]).toBe("method-not-allowed");

    const sessionRoute = await cookieRouter(
      buildRequest("/sessions/current", "PATCH", { origin: trustedOrigin }),
    );
    expect(sessionRoute.status).toBe(405);
    expect(sessionRoute.headers.get("allow")).toBe("GET, DELETE");
  });

  it("returns a bearer token and no cookie when useCookies is false", async () => {
    const { bearerRouter, bearerLogin, username, wallet, sessionCookie } = h();

    // No Origin header at all: a bearer-only deployment has no ambient
    // credential to forge, so the CSRF gate must not apply.
    const login = await bearerRouter(
      buildRequest(
        "/sessions",
        "POST",
        { "content-type": "application/json" },
        JSON.stringify({
          username,
          challengeId: bearerLogin.challengeId,
          signature: bearerLogin.signature,
        }),
      ),
    );
    const body = await readJson(login);

    expect(login.status).toBe(200);
    expect(login.headers.get("set-cookie")).toBeNull();
    const token = requireString(body, "token");
    expect(token).toMatch(/^[\x21-\x7e]{22,}$/u);

    const authenticated = await bearerRouter(
      getRequest("/sessions/current", { authorization: `Bearer ${token}` }),
    );
    const identity = await readJson(authenticated);
    expect(authenticated.status).toBe(200);
    expect(walletAddresses(identity)).toContain(wallet.address);

    // The cookie transport is genuinely off, not merely unused: a valid
    // session cookie must not authenticate against this router.
    const cookieAttempt = await bearerRouter(
      getRequest("/sessions/current", { cookie: sessionCookie }),
    );
    const rejected = await readJson(cookieAttempt);
    expect(cookieAttempt.status).toBe(401);
    expect(requireObject(rejected, "error")["code"]).toBe("session-not-found");
  }, databaseTimeoutMs);
});
