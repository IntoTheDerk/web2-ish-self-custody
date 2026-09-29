/**
 * The HTTP surface, expressed only in Web Fetch primitives.
 *
 * Nothing here touches a framework, a Node global, or a runtime-specific
 * request object. The same handler therefore serves a Vercel Function today and
 * a `node:http` server on self-hosted infrastructure later (see
 * `adapters/node.ts`), which is the whole point: lifting the deployment must
 * not change observable behavior.
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { utf8 } from "../encoding.js";
import type { IdentityService } from "./contract.js";
import {
  EmailDeliveryError,
  assertEmailVerificationDelivery,
  deliverEmailVerification,
  type EmailDeliveryFailure,
  type EmailVerificationDelivery,
} from "./email.js";
import { IdentityError, enumerationSensitiveCodes } from "./errors.js";
import {
  challengePurposes,
  type AuthenticatedIdentity,
  type ChallengePurpose,
  type IssuedSession,
  type LoginInput,
  type RegistrationInput,
  type RequestContext,
} from "./types.js";

export type IdentityRouterOptions = Readonly<{
  /** Path all routes hang off. Default `/identity`. */
  basePath?: string;
  /** Default `__Host-w2sc_session`. */
  cookieName?: string;
  /** Set false for pure-bearer clients (native apps, server-to-server). */
  useCookies?: boolean;
  cookieDomain?: string;
  /**
   * When set, cookie-authenticated unsafe requests must carry a matching
   * `Origin`. Leaving it unset disables the check, which is only safe when the
   * deployment has no browser clients.
   */
  trustedOrigins?: readonly string[];
  /** The service never sees a raw IP; the host decides how to hash one. */
  hashRequestIp?: (request: Request) => string | undefined;
  /**
   * Sends the code minted by `POST /email-verifications`. Without it the route
   * still mints and stores a code but nobody receives it, which only suits a
   * host that calls `service.startEmailVerification` itself.
   */
  emailVerification?: EmailVerificationDelivery;
}>;

/** 64 KiB. Every accepted body here is a handful of short strings. */
const maxBodyBytes = 64 * 1024;

const cookieNamePattern = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/u;
const safeFieldName = /^[A-Za-z0-9_]{1,40}$/u;
const unsafeMethods: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

type RouterContext = Readonly<{
  service: IdentityService;
  basePath: string;
  cookieName: string;
  cookieDomain: string | undefined;
  useCookies: boolean;
  trustedOrigins: ReadonlySet<string> | null;
  hashRequestIp: ((request: Request) => string | undefined) | null;
  emailVerification: EmailVerificationDelivery | null;
}>;

type RouteHandler = (ctx: RouterContext, request: Request) => Promise<Response>;

/**
 * Transport-level failures that predate the service call. Kept separate from
 * `IdentityError` so the service's stable code union stays exactly that.
 */
class RouterError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "RouterError";
  }
}

export function jsonResponse(
  body: unknown,
  status = 200,
  headers: Readonly<Record<string, string>> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...headers,
    },
  });
}

export function createIdentityRouter(
  service: IdentityService,
  options: IdentityRouterOptions = {},
): (request: Request) => Promise<Response> {
  const cookieName = options.cookieName ?? "__Host-w2sc_session";
  if (!cookieNamePattern.test(cookieName)) {
    throw new TypeError("cookieName must be a valid cookie token.");
  }
  // `__Host-` is only honored by browsers when the cookie carries no Domain;
  // silently dropping the prefix's guarantees would be worse than refusing to
  // boot.
  if (cookieName.startsWith("__Host-") && options.cookieDomain !== undefined) {
    throw new TypeError("A __Host- prefixed cookie cannot declare a Domain attribute.");
  }
  if (options.emailVerification !== undefined) {
    assertEmailVerificationDelivery(options.emailVerification);
  }

  const ctx: RouterContext = Object.freeze({
    service,
    basePath: normalizeBasePath(options.basePath ?? "/identity"),
    cookieName,
    cookieDomain: options.cookieDomain,
    useCookies: options.useCookies ?? true,
    trustedOrigins:
      options.trustedOrigins === undefined
        ? null
        : new Set(options.trustedOrigins.map(normalizeOrigin)),
    hashRequestIp: options.hashRequestIp ?? null,
    emailVerification: options.emailVerification ?? null,
  });

  return async function handleIdentityRequest(request: Request): Promise<Response> {
    try {
      return await dispatch(ctx, request);
    } catch (error) {
      return errorResponse(error);
    }
  };
}

async function dispatch(ctx: RouterContext, request: Request): Promise<Response> {
  const route = resolveRoutePath(ctx.basePath, request.url);
  if (route === null) {
    return notFound();
  }
  const methods = routes.get(route);
  if (methods === undefined) {
    return notFound();
  }
  const handler = methods.get(request.method);
  if (handler === undefined) {
    return jsonResponse(
      { error: { code: "method-not-allowed", message: "Method not allowed for this route." } },
      405,
      { Allow: [...methods.keys()].join(", ") },
    );
  }
  assertOriginAllowed(ctx, request);
  return handler(ctx, request);
}

function notFound(): Response {
  return jsonResponse(
    { error: { code: "not-found", message: "No such identity route." } },
    404,
  );
}

function normalizeBasePath(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "" || trimmed === "/") {
    return "";
  }
  const leading = trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  return leading.endsWith("/") ? leading.slice(0, -1) : leading;
}

/** Returns the route path relative to `basePath`, or null when out of scope. */
function resolveRoutePath(basePath: string, requestUrl: string): string | null {
  let pathname: string;
  try {
    pathname = new URL(requestUrl).pathname;
  } catch {
    return null;
  }
  let route: string;
  if (basePath === "") {
    route = pathname;
  } else if (pathname === basePath) {
    route = "/";
  } else if (pathname.startsWith(`${basePath}/`)) {
    route = pathname.slice(basePath.length);
  } else {
    return null;
  }
  return route.length > 1 && route.endsWith("/") ? route.slice(0, -1) : route;
}

function normalizeOrigin(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return value.trim();
  }
}

/**
 * CSRF gate.
 *
 * Only ambient credentials are forgeable, so a request that presents an
 * explicit `Authorization` header is exempt, and a deployment that never sets
 * cookies has nothing to forge in the first place.
 */
function assertOriginAllowed(ctx: RouterContext, request: Request): void {
  if (ctx.trustedOrigins === null || !ctx.useCookies) {
    return;
  }
  if (!unsafeMethods.has(request.method)) {
    return;
  }
  if (bearerFromHeader(request) !== null) {
    return;
  }
  const origin = request.headers.get("origin");
  if (origin === null || !ctx.trustedOrigins.has(normalizeOrigin(origin))) {
    throw new RouterError(403, "forbidden-origin", "Request origin is not allowed.");
  }
}

function bearerFromHeader(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (header === null) {
    return null;
  }
  const match = /^Bearer[ \t]+(\S+)$/u.exec(header.trim());
  return match?.[1] ?? null;
}

function cookieValue(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (header === null) {
    return null;
  }
  for (const pair of header.split(";")) {
    const separator = pair.indexOf("=");
    if (separator < 0) {
      continue;
    }
    if (pair.slice(0, separator).trim() !== name) {
      continue;
    }
    const raw = pair.slice(separator + 1).trim();
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }
  return null;
}

function tokenFromRequest(ctx: RouterContext, request: Request): string | null {
  const bearer = bearerFromHeader(request);
  if (bearer !== null) {
    return bearer;
  }
  return ctx.useCookies ? cookieValue(request, ctx.cookieName) : null;
}

function serializeSessionCookie(ctx: RouterContext, token: string): string {
  const parts = [
    `${ctx.cookieName}=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${ctx.service.config.sessionTtlSeconds}`,
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ];
  if (ctx.cookieDomain !== undefined) {
    parts.push(`Domain=${ctx.cookieDomain}`);
  }
  return parts.join("; ");
}

function clearSessionCookie(ctx: RouterContext): string {
  const parts = [
    `${ctx.cookieName}=`,
    "Path=/",
    "Max-Age=0",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ];
  if (ctx.cookieDomain !== undefined) {
    parts.push(`Domain=${ctx.cookieDomain}`);
  }
  return parts.join("; ");
}

function requestContext(ctx: RouterContext, request: Request): RequestContext {
  const ipHash = ctx.hashRequestIp?.(request);
  const userAgent = request.headers.get("user-agent");
  return {
    ...(ipHash !== undefined && ipHash !== "" ? { ipHash } : {}),
    ...(userAgent !== null && userAgent !== ""
      ? { userAgentHash: bytesToHex(sha256(utf8(userAgent))) }
      : {}),
  };
}

async function readBodyBytes(request: Request): Promise<Uint8Array> {
  const declared = request.headers.get("content-length");
  if (declared !== null) {
    const length = Number(declared);
    if (Number.isFinite(length) && length > maxBodyBytes) {
      throw bodyTooLarge();
    }
  }

  const stream = request.body;
  if (stream === null) {
    const buffer = await request.arrayBuffer();
    if (buffer.byteLength > maxBodyBytes) {
      throw bodyTooLarge();
    }
    return new Uint8Array(buffer);
  }

  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    if (value === undefined) {
      continue;
    }
    total += value.byteLength;
    // Bail before buffering an unbounded body, not after.
    if (total > maxBodyBytes) {
      await reader.cancel().catch(() => undefined);
      throw bodyTooLarge();
    }
    chunks.push(value);
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged;
}

function bodyTooLarge(): RouterError {
  return new RouterError(
    413,
    "payload-too-large",
    `Request bodies are limited to ${maxBodyBytes} bytes.`,
  );
}

async function readJsonObject(
  request: Request,
  allowedFields: readonly string[],
): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type") ?? "";
  const mediaType = contentType.split(";")[0]?.trim().toLowerCase() ?? "";
  if (mediaType !== "application/json") {
    throw new RouterError(
      415,
      "unsupported-media-type",
      "Request bodies must be application/json.",
    );
  }

  const bytes = await readBodyBytes(request);
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new IdentityError("Request body is not valid UTF-8.", "invalid-request");
  }
  if (text.trim() === "") {
    throw new IdentityError("Request body must be a JSON object.", "invalid-request");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new IdentityError("Request body is not valid JSON.", "invalid-request");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new IdentityError("Request body must be a JSON object.", "invalid-request");
  }

  const body = parsed as Record<string, unknown>;
  for (const key of Object.keys(body)) {
    if (!allowedFields.includes(key)) {
      // Unknown fields are rejected rather than ignored so a client that
      // mistypes a field never silently loses it. The name is only echoed when
      // it is plainly inert.
      throw new IdentityError(
        safeFieldName.test(key)
          ? `Unknown field "${key}" in request body.`
          : "Unknown field in request body.",
        "invalid-request",
      );
    }
  }
  return body;
}

function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field];
  if (typeof value !== "string") {
    throw new IdentityError(`Field "${field}" must be a string.`, "invalid-request");
  }
  return value;
}

function optionalString(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new IdentityError(`Field "${field}" must be a string.`, "invalid-request");
  }
  return value;
}

function requirePurpose(body: Record<string, unknown>): ChallengePurpose {
  const value = body["purpose"];
  const match = challengePurposes.find((purpose) => purpose === value);
  if (match === undefined) {
    throw new IdentityError(
      `Field "purpose" must be one of: ${challengePurposes.join(", ")}.`,
      "invalid-purpose",
    );
  }
  return match;
}

async function authenticateRequest(
  ctx: RouterContext,
  request: Request,
): Promise<AuthenticatedIdentity> {
  const token = tokenFromRequest(ctx, request);
  if (token === null) {
    throw new IdentityError("Request carries no session token.", "session-not-found");
  }
  return ctx.service.authenticate(token, requestContext(ctx, request));
}

/**
 * In cookie mode the raw token is deliberately withheld from the response
 * body: the cookie is HttpOnly precisely so page scripts cannot read it, and
 * echoing it would hand it straight back.
 */
function sessionResponse(
  ctx: RouterContext,
  payload: Readonly<Record<string, unknown>>,
  issued: IssuedSession,
  status: number,
): Response {
  const headers: Record<string, string> = {};
  if (ctx.useCookies) {
    headers["Set-Cookie"] = serializeSessionCookie(ctx, issued.token);
  }
  return jsonResponse(
    {
      ...payload,
      session: issued.session,
      ...(ctx.useCookies ? {} : { token: issued.token }),
    },
    status,
    headers,
  );
}

const registrationFields: readonly string[] = [
  "username",
  "displayName",
  "email",
  "address",
  "publicKey",
  "challengeId",
  "signature",
];

async function handleProfile(ctx: RouterContext, _request: Request): Promise<Response> {
  return jsonResponse(await ctx.service.derivationProfile());
}

async function handleCreateChallenge(
  ctx: RouterContext,
  request: Request,
): Promise<Response> {
  const body = await readJsonObject(request, ["username", "purpose"]);
  const challenge = await ctx.service.createChallenge(
    requireString(body, "username"),
    requirePurpose(body),
    requestContext(ctx, request),
  );
  return jsonResponse(challenge);
}

async function handleRegister(ctx: RouterContext, request: Request): Promise<Response> {
  const body = await readJsonObject(request, registrationFields);
  const displayName = optionalString(body, "displayName");
  const email = optionalString(body, "email");
  const input: RegistrationInput = {
    username: requireString(body, "username"),
    address: requireString(body, "address"),
    publicKey: requireString(body, "publicKey"),
    challengeId: requireString(body, "challengeId"),
    signature: requireString(body, "signature"),
    ...(displayName !== undefined ? { displayName } : {}),
    ...(email !== undefined ? { email } : {}),
  };
  const result = await ctx.service.register(input, requestContext(ctx, request));
  return sessionResponse(
    ctx,
    { account: result.account, wallet: result.wallet },
    result.session,
    201,
  );
}

async function handleLogin(ctx: RouterContext, request: Request): Promise<Response> {
  const body = await readJsonObject(request, ["username", "challengeId", "signature"]);
  const input: LoginInput = {
    username: requireString(body, "username"),
    challengeId: requireString(body, "challengeId"),
    signature: requireString(body, "signature"),
  };
  const result = await ctx.service.login(input, requestContext(ctx, request));
  return sessionResponse(ctx, { account: result.account }, result.session, 200);
}

async function handleCurrentSession(
  ctx: RouterContext,
  request: Request,
): Promise<Response> {
  const identity = await authenticateRequest(ctx, request);
  return jsonResponse({
    account: identity.account,
    wallets: identity.wallets,
    session: identity.session,
  });
}

async function handleRevokeSession(
  ctx: RouterContext,
  request: Request,
): Promise<Response> {
  // A token that is missing, unknown, or expired still reports 401 — the caller
  // learns the session is not usable — but the cookie is cleared alongside it,
  // because in those three cases the session is definitively gone and leaving
  // the browser holding it only produces another failing request. An
  // unexpected failure clears nothing: the session may well still be alive.
  const headers: Record<string, string> = {};
  if (ctx.useCookies) {
    headers["Set-Cookie"] = clearSessionCookie(ctx);
  }

  const token = tokenFromRequest(ctx, request);
  if (token === null) {
    return jsonResponse(
      { error: { code: "session-not-found", message: "Request carries no session token." } },
      401,
      headers,
    );
  }
  try {
    await ctx.service.revokeSession(token, requestContext(ctx, request));
  } catch (error) {
    if (
      error instanceof IdentityError &&
      (error.code === "session-not-found" || error.code === "session-expired")
    ) {
      return jsonResponse(
        { error: { code: error.code, message: error.message } },
        error.status,
        headers,
      );
    }
    throw error;
  }
  return jsonResponse({ revoked: true }, 200, headers);
}

async function handleGetAccount(ctx: RouterContext, request: Request): Promise<Response> {
  const identity = await authenticateRequest(ctx, request);
  return jsonResponse({ account: identity.account, wallets: identity.wallets });
}

async function handleUpdateAccount(
  ctx: RouterContext,
  request: Request,
): Promise<Response> {
  const identity = await authenticateRequest(ctx, request);
  const body = await readJsonObject(request, ["displayName", "email"]);
  const displayName = optionalString(body, "displayName");
  const email = optionalString(body, "email");
  const account = await ctx.service.updateAccount(
    identity.account.id,
    {
      ...(displayName !== undefined ? { displayName } : {}),
      ...(email !== undefined ? { email } : {}),
    },
    requestContext(ctx, request),
  );
  return jsonResponse({ account });
}

/**
 * The minted code is never in the response: returning it to the requester
 * would let anyone who can name an address verify it. It reaches the address
 * only through the host's configured `emailVerification` sender.
 *
 * A failed send is reported as `email-delivery-failed` so the client can offer
 * a retry; the stored code is left to expire, since nobody holds it.
 */
async function handleStartEmailVerification(
  ctx: RouterContext,
  request: Request,
): Promise<Response> {
  const body = await readJsonObject(request, ["username", "email"]);
  const issued = await ctx.service.startEmailVerification(
    { username: requireString(body, "username"), email: requireString(body, "email") },
    requestContext(ctx, request),
  );
  if (ctx.emailVerification !== null) {
    await sendVerificationEmail(ctx.emailVerification, issued);
  }
  return jsonResponse({
    verificationId: issued.verificationId,
    email: issued.email,
    expiresAt: issued.expiresAt,
  });
}

async function sendVerificationEmail(
  delivery: EmailVerificationDelivery,
  issued: Readonly<{ verificationId: string; code: string; email: string; expiresAt: Date }>,
): Promise<void> {
  try {
    await deliverEmailVerification(delivery, issued);
  } catch (error) {
    const failure: EmailDeliveryFailure =
      error instanceof EmailDeliveryError
        ? { provider: error.provider, reason: error.reason, status: error.status }
        : { provider: delivery.sender.provider, reason: "network", status: null };
    try {
      delivery.onFailure?.(Object.freeze(failure));
    } catch {
      // A broken reporter must not change the caller's response.
    }
    throw new IdentityError(
      "The verification email could not be sent; try again shortly.",
      "email-delivery-failed",
    );
  }
}

async function handleConfirmEmailVerification(
  ctx: RouterContext,
  request: Request,
): Promise<Response> {
  const body = await readJsonObject(request, ["verificationId", "code"]);
  const result = await ctx.service.confirmEmailVerification(
    requireString(body, "verificationId"),
    requireString(body, "code"),
    requestContext(ctx, request),
  );
  return jsonResponse(result);
}

const routes: ReadonlyMap<string, ReadonlyMap<string, RouteHandler>> = new Map<
  string,
  ReadonlyMap<string, RouteHandler>
>([
  ["/profile", new Map<string, RouteHandler>([["GET", handleProfile]])],
  ["/challenges", new Map<string, RouteHandler>([["POST", handleCreateChallenge]])],
  ["/accounts", new Map<string, RouteHandler>([["POST", handleRegister]])],
  [
    "/accounts/me",
    new Map<string, RouteHandler>([
      ["GET", handleGetAccount],
      ["PATCH", handleUpdateAccount],
    ]),
  ],
  ["/sessions", new Map<string, RouteHandler>([["POST", handleLogin]])],
  [
    "/sessions/current",
    new Map<string, RouteHandler>([
      ["GET", handleCurrentSession],
      ["DELETE", handleRevokeSession],
    ]),
  ],
  [
    "/email-verifications",
    new Map<string, RouteHandler>([["POST", handleStartEmailVerification]]),
  ],
  [
    "/email-verifications/confirm",
    new Map<string, RouteHandler>([["POST", handleConfirmEmailVerification]]),
  ],
]);

/**
 * Error mapping.
 *
 * Two invariants: enumeration-sensitive failures collapse into one
 * indistinguishable 401 so a caller cannot probe for account existence, and an
 * unexpected throw never reaches the client in any form.
 */
function errorResponse(error: unknown): Response {
  if (error instanceof IdentityError) {
    if (enumerationSensitiveCodes.has(error.code)) {
      return jsonResponse(
        { error: { code: "invalid-signature", message: "Authentication failed." } },
        401,
      );
    }
    const headers: Record<string, string> = {};
    const retryAfter = error.details?.["retryAfterSeconds"];
    if (typeof retryAfter === "number" && Number.isFinite(retryAfter)) {
      headers["Retry-After"] = String(Math.max(0, Math.ceil(retryAfter)));
    }
    return jsonResponse(
      { error: { code: error.code, message: error.message } },
      error.status,
      headers,
    );
  }
  if (error instanceof RouterError) {
    return jsonResponse({ error: { code: error.code, message: error.message } }, error.status);
  }
  return jsonResponse(
    { error: { code: "internal-error", message: "Internal server error." } },
    500,
  );
}
