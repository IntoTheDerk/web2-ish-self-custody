/**
 * Self-hosted wiring: a `pg` pool and a `node:http` bridge.
 *
 * Node's types are described structurally rather than imported, so this module
 * type-checks in a DOM-only build and adds no dependency on `@types/node`. A
 * real `IncomingMessage`/`ServerResponse` pair satisfies these shapes.
 */

import { utf8 } from "../../encoding.js";
import type { IdentityService } from "../contract.js";
import { createIdentityService } from "../service.js";
import { pgDriver, type PgQueryable } from "../sql.js";
import type { IdentityServiceConfig } from "../types.js";

export type PgIdentityServiceOptions = Readonly<{
  pool: PgQueryable;
  config: IdentityServiceConfig;
}>;

export function createPgIdentityService(options: PgIdentityServiceOptions): IdentityService {
  return createIdentityService(pgDriver(options.pool), options.config);
}

export type NodeHeaders = Readonly<Record<string, string | string[] | undefined>>;

export interface NodeRequestLike extends AsyncIterable<unknown> {
  readonly method?: string | undefined;
  readonly url?: string | undefined;
  readonly headers: NodeHeaders;
  /** `net.Socket` or `tls.TLSSocket`; probed at runtime for `encrypted`. */
  readonly socket?: unknown;
}

export interface NodeResponseLike {
  statusCode: number;
  setHeader(name: string, value: string | readonly string[], ...rest: readonly unknown[]): unknown;
  end(chunk?: unknown, ...rest: readonly unknown[]): unknown;
}

export type NodeRequestListener = (
  request: NodeRequestLike,
  response: NodeResponseLike,
) => void;

export type NodeRequestListenerOptions = Readonly<{
  /** Buffered request-body ceiling. Default 64 KiB, matching the router. */
  maxBodyBytes?: number;
}>;

const defaultMaxBodyBytes = 64 * 1024;
const bodylessMethods: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);

/**
 * Adapts a Web Fetch handler to Node's request listener signature, so the exact
 * router that runs on Vercel also serves from `http.createServer(...)`.
 */
export function nodeRequestListener(
  handler: (request: Request) => Promise<Response>,
  options: NodeRequestListenerOptions = {},
): NodeRequestListener {
  const maxBodyBytes = options.maxBodyBytes ?? defaultMaxBodyBytes;

  return (nodeRequest, nodeResponse): void => {
    void serve(handler, nodeRequest, nodeResponse, maxBodyBytes).catch(() => {
      writeFallback(nodeResponse, 500, "internal-error", "Internal server error.");
    });
  };
}

async function serve(
  handler: (request: Request) => Promise<Response>,
  nodeRequest: NodeRequestLike,
  nodeResponse: NodeResponseLike,
  maxBodyBytes: number,
): Promise<void> {
  let request: Request;
  try {
    request = await toWebRequest(nodeRequest, maxBodyBytes);
  } catch (error) {
    const tooLarge = error instanceof RangeError;
    writeFallback(
      nodeResponse,
      tooLarge ? 413 : 400,
      tooLarge ? "payload-too-large" : "invalid-request",
      tooLarge ? "Request body is too large." : "Request could not be read.",
    );
    return;
  }

  const response = await handler(request);
  await writeWebResponse(nodeResponse, response, request.method === "HEAD");
}

async function toWebRequest(
  nodeRequest: NodeRequestLike,
  maxBodyBytes: number,
): Promise<Request> {
  const method = (nodeRequest.method ?? "GET").toUpperCase();
  const headers = webHeaders(nodeRequest.headers);
  const url = requestUrl(nodeRequest);

  if (bodylessMethods.has(method)) {
    return new Request(url, { method, headers });
  }
  const body = await readNodeBody(nodeRequest, maxBodyBytes);
  return new Request(url, { method, headers, body });
}

function requestUrl(nodeRequest: NodeRequestLike): string {
  const authority =
    headerValue(nodeRequest.headers, ":authority") ??
    headerValue(nodeRequest.headers, "host") ??
    "localhost";
  const forwarded = headerValue(nodeRequest.headers, "x-forwarded-proto");
  const forwardedProtocol = forwarded?.split(",")[0]?.trim();
  const protocol =
    forwardedProtocol !== undefined && forwardedProtocol !== ""
      ? forwardedProtocol
      : socketIsEncrypted(nodeRequest.socket)
        ? "https"
        : "http";
  const target = nodeRequest.url ?? "/";
  return `${protocol}://${authority}${target.startsWith("/") ? target : `/${target}`}`;
}

function socketIsEncrypted(socket: unknown): boolean {
  return (
    typeof socket === "object" &&
    socket !== null &&
    "encrypted" in socket &&
    (socket as { encrypted?: unknown }).encrypted === true
  );
}

function headerValue(headers: NodeHeaders, name: string): string | undefined {
  const value = headers[name];
  if (value === undefined) {
    return undefined;
  }
  return Array.isArray(value) ? value[0] : value;
}

function webHeaders(source: NodeHeaders): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(source)) {
    // HTTP/2 pseudo-headers are not legal Fetch header names.
    if (value === undefined || name.startsWith(":")) {
      continue;
    }
    for (const item of Array.isArray(value) ? value : [value]) {
      try {
        headers.append(name, item);
      } catch {
        // A header Node accepted but Fetch rejects is dropped rather than
        // failing the whole request.
      }
    }
  }
  return headers;
}

async function readNodeBody(
  nodeRequest: NodeRequestLike,
  maxBodyBytes: number,
): Promise<ArrayBuffer> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of nodeRequest) {
    const bytes = toBytes(chunk);
    total += bytes.byteLength;
    if (total > maxBodyBytes) {
      throw new RangeError("Request body exceeds the configured limit.");
    }
    chunks.push(bytes);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return merged.buffer;
}

function toBytes(chunk: unknown): Uint8Array {
  if (chunk instanceof Uint8Array) {
    return chunk;
  }
  if (typeof chunk === "string") {
    return utf8(chunk);
  }
  throw new TypeError("Unsupported request body chunk.");
}

async function writeWebResponse(
  nodeResponse: NodeResponseLike,
  response: Response,
  omitBody: boolean,
): Promise<void> {
  nodeResponse.statusCode = response.status;

  // `Headers.forEach` folds repeated Set-Cookie values into one comma-joined
  // string, which is not a valid cookie header. Prefer `getSetCookie` where the
  // runtime provides it.
  const setCookies: string[] = [];
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headers.getSetCookie === "function") {
    setCookies.push(...headers.getSetCookie());
  }
  headers.forEach((value, name) => {
    if (name.toLowerCase() === "set-cookie") {
      if (setCookies.length === 0) {
        setCookies.push(value);
      }
      return;
    }
    nodeResponse.setHeader(name, value);
  });
  if (setCookies.length > 0) {
    nodeResponse.setHeader("set-cookie", setCookies);
  }

  if (omitBody) {
    nodeResponse.end();
    return;
  }
  nodeResponse.end(new Uint8Array(await response.arrayBuffer()));
}

function writeFallback(
  nodeResponse: NodeResponseLike,
  status: number,
  code: string,
  message: string,
): void {
  try {
    nodeResponse.statusCode = status;
    nodeResponse.setHeader("content-type", "application/json; charset=utf-8");
    nodeResponse.setHeader("cache-control", "no-store");
    nodeResponse.setHeader("x-content-type-options", "nosniff");
    nodeResponse.end(utf8(JSON.stringify({ error: { code, message } })));
  } catch {
    // The socket is already gone; there is nothing left to report to.
  }
}
