/**
 * HTTPS email providers.
 *
 * Each is one JSON POST over `fetch`, so none adds a dependency and all run the
 * same on Vercel Functions, edge runtimes, and `node:http`. The credential is
 * held in a closure and never placed on the returned object, so logging or
 * serializing a sender cannot print it; failures surface as
 * `EmailDeliveryError`, which carries only the provider, a reason, and the HTTP
 * status, never a response body (providers echo addresses there).
 */

import {
  EmailDeliveryError,
  parseMailbox,
  type EmailDeliveryReceipt,
  type EmailMessage,
  type EmailSender,
} from "./email.js";

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

type CommonOptions = Readonly<{
  /** Override for tests or a regional endpoint. Must be `https:`. */
  baseUrl?: string;
  fetch?: FetchLike;
  /** Default 10 000 ms. */
  timeoutMs?: number;
}>;

export type ResendEmailSenderOptions = CommonOptions &
  Readonly<{
    apiKey: string;
  }>;

export type PostmarkEmailSenderOptions = CommonOptions &
  Readonly<{
    serverToken: string;
    /** Default `outbound`, Postmark's transactional stream. */
    messageStream?: string;
  }>;

export type SendGridEmailSenderOptions = CommonOptions &
  Readonly<{
    apiKey: string;
  }>;

export type EmailProviderConfig =
  | (Readonly<{ provider: "resend" }> & ResendEmailSenderOptions)
  | (Readonly<{ provider: "postmark" }> & PostmarkEmailSenderOptions)
  | (Readonly<{ provider: "sendgrid" }> & SendGridEmailSenderOptions);

export const emailProviders = Object.freeze(["resend", "postmark", "sendgrid"] as const);
export type EmailProviderName = (typeof emailProviders)[number];

/** Picks a provider from configuration, e.g. an environment variable. */
export function createEmailSender(config: EmailProviderConfig): EmailSender {
  switch (config.provider) {
    case "resend":
      return createResendEmailSender(config);
    case "postmark":
      return createPostmarkEmailSender(config);
    case "sendgrid":
      return createSendGridEmailSender(config);
    default:
      throw new TypeError(
        `Unknown email provider; expected one of ${emailProviders.join(", ")}.`,
      );
  }
}

/** https://resend.com/docs/api-reference/emails/send-email */
export function createResendEmailSender(options: ResendEmailSenderOptions): EmailSender {
  const provider = "resend";
  const apiKey = requireSecret(options.apiKey, "Resend apiKey");
  const endpoint = endpointUrl(options.baseUrl ?? "https://api.resend.com", "/emails");
  const post = poster(provider, options);
  return Object.freeze({
    provider,
    async send(message: EmailMessage): Promise<EmailDeliveryReceipt> {
      const { body } = await post(
        endpoint,
        {
          Authorization: `Bearer ${apiKey}`,
          ...(message.idempotencyKey === undefined
            ? {}
            : { "Idempotency-Key": message.idempotencyKey }),
        },
        {
          from: message.from,
          to: [message.to],
          subject: message.subject,
          text: message.text,
          html: message.html,
          ...(message.replyTo === undefined ? {} : { reply_to: message.replyTo }),
        },
      );
      return receipt(provider, stringField(body, "id"));
    },
  });
}

/** https://postmarkapp.com/developer/api/email-api */
export function createPostmarkEmailSender(options: PostmarkEmailSenderOptions): EmailSender {
  const provider = "postmark";
  const serverToken = requireSecret(options.serverToken, "Postmark serverToken");
  const endpoint = endpointUrl(options.baseUrl ?? "https://api.postmarkapp.com", "/email");
  const messageStream = options.messageStream ?? "outbound";
  const post = poster(provider, options);
  return Object.freeze({
    provider,
    async send(message: EmailMessage): Promise<EmailDeliveryReceipt> {
      const { body, status } = await post(
        endpoint,
        { "X-Postmark-Server-Token": serverToken },
        {
          From: message.from,
          To: message.to,
          Subject: message.subject,
          TextBody: message.text,
          HtmlBody: message.html,
          MessageStream: messageStream,
          ...(message.replyTo === undefined ? {} : { ReplyTo: message.replyTo }),
        },
      );
      // Postmark reports some refusals as ErrorCode on an otherwise 2xx reply.
      const errorCode = isRecord(body) ? body["ErrorCode"] : undefined;
      if (typeof errorCode === "number" && errorCode !== 0) {
        throw new EmailDeliveryError(provider, "rejected", status);
      }
      return receipt(provider, stringField(body, "MessageID"));
    },
  });
}

/** https://www.twilio.com/docs/sendgrid/api-reference/mail-send/mail-send */
export function createSendGridEmailSender(options: SendGridEmailSenderOptions): EmailSender {
  const provider = "sendgrid";
  const apiKey = requireSecret(options.apiKey, "SendGrid apiKey");
  const endpoint = endpointUrl(options.baseUrl ?? "https://api.sendgrid.com", "/v3/mail/send");
  const post = poster(provider, options);
  const mailbox = (value: string): Record<string, string> => {
    const parsed = parseMailbox(value);
    return parsed.name === null ? { email: parsed.email } : { email: parsed.email, name: parsed.name };
  };
  return Object.freeze({
    provider,
    async send(message: EmailMessage): Promise<EmailDeliveryReceipt> {
      const { headers } = await post(
        endpoint,
        { Authorization: `Bearer ${apiKey}` },
        {
          personalizations: [{ to: [mailbox(message.to)] }],
          from: mailbox(message.from),
          ...(message.replyTo === undefined ? {} : { reply_to: mailbox(message.replyTo) }),
          subject: message.subject,
          content: [
            { type: "text/plain", value: message.text },
            { type: "text/html", value: message.html },
          ],
        },
        // SendGrid answers 202 with an empty body.
        false,
      );
      return receipt(provider, headers.get("x-message-id"));
    },
  });
}

type Posted = Readonly<{ status: number; body: unknown; headers: Headers }>;

function poster(
  provider: string,
  options: CommonOptions,
): (
  url: string,
  headers: Readonly<Record<string, string>>,
  payload: unknown,
  expectJson?: boolean,
) => Promise<Posted> {
  const fetchImpl: FetchLike =
    options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const timeoutMs = options.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new TypeError("timeoutMs must be an integer from 1 to 60000.");
  }
  return async (url, headers, payload, expectJson = true) => {
    let response: Response;
    try {
      response = await fetchImpl(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          ...headers,
        },
        body: JSON.stringify(payload),
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      const name = error instanceof Error ? error.name : "";
      throw new EmailDeliveryError(
        provider,
        name === "TimeoutError" || name === "AbortError" ? "timeout" : "network",
      );
    }
    if (!response.ok) {
      // Drain without reading into anything that could be logged.
      await response.body?.cancel().catch(() => undefined);
      throw new EmailDeliveryError(provider, "rejected", response.status);
    }
    if (!expectJson) {
      await response.body?.cancel().catch(() => undefined);
      return { status: response.status, body: null, headers: response.headers };
    }
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new EmailDeliveryError(provider, "invalid-response", response.status);
    }
    return { status: response.status, body, headers: response.headers };
  };
}

function receipt(provider: string, messageId: string | null): EmailDeliveryReceipt {
  return Object.freeze({ provider, messageId });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(body: unknown, field: string): string | null {
  const value = isRecord(body) ? body[field] : undefined;
  return typeof value === "string" && value !== "" ? value : null;
}

function requireSecret(value: unknown, field: string): string {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (trimmed === "" || /\s/u.test(trimmed)) {
    // Name the field, never echo the value.
    throw new TypeError(`${field} is missing or malformed.`);
  }
  return trimmed;
}

function endpointUrl(base: string, path: string): string {
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    throw new TypeError("baseUrl must be an absolute https: URL.");
  }
  if (url.protocol !== "https:") {
    throw new TypeError("baseUrl must be an absolute https: URL.");
  }
  return `${url.origin}${url.pathname.replace(/\/+$/u, "")}${path}`;
}
