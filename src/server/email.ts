/**
 * Email delivery for verification codes.
 *
 * The service mints a code and never sends it. This module is the optional
 * bridge a host hands the router so that `POST /email-verifications` actually
 * reaches an inbox. It stays transport-agnostic: an `EmailSender` is anything
 * that can post one message, and `emailProviders.ts` ships the HTTPS ones.
 *
 * Content and design belong to the host. It either themes the built-in
 * template or supplies its own `render`. Whichever it picks, the rendered
 * message must actually carry the code; a template that loses it would mint
 * codes nobody can ever enter, so that is refused rather than sent.
 *
 * Nothing here logs, and no error raised here carries the code, the recipient,
 * a provider credential, or a provider response body.
 */

export type EmailMessage = Readonly<{
  /** `addr@example.com` or `Display Name <addr@example.com>`. */
  from: string;
  to: string;
  replyTo?: string;
  subject: string;
  text: string;
  html: string;
  /** Lets a provider that supports it collapse a retried send into one message. */
  idempotencyKey?: string;
}>;

export type EmailDeliveryReceipt = Readonly<{
  provider: string;
  /** The provider's id for the accepted message, when it returns one. */
  messageId: string | null;
}>;

export interface EmailSender {
  /** A short, stable label such as `resend`; safe to log. */
  readonly provider: string;
  send(message: EmailMessage): Promise<EmailDeliveryReceipt>;
}

export type EmailDeliveryFailureReason =
  | "timeout"
  | "network"
  | "rejected"
  | "invalid-response"
  | "render";

/**
 * A send that did not go through. Every field is safe to log: the message is
 * built only from the provider label, the reason, and the HTTP status.
 */
export class EmailDeliveryError extends Error {
  constructor(
    readonly provider: string,
    readonly reason: EmailDeliveryFailureReason,
    readonly status: number | null = null,
  ) {
    super(
      `${provider} did not deliver the message (${reason}` +
        `${status === null ? "" : `, HTTP ${String(status)}`}).`,
    );
    this.name = "EmailDeliveryError";
  }
}

export type EmailDeliveryFailure = Readonly<{
  provider: string;
  reason: EmailDeliveryFailureReason;
  status: number | null;
}>;

export type VerificationEmailInput = Readonly<{
  /** The raw code, e.g. `ABCD2345`. */
  code: string;
  /** The same code split for reading, e.g. `ABCD-2345`; either form is accepted on confirm. */
  formattedCode: string;
  email: string;
  expiresAt: Date;
  /** Whole minutes until `expiresAt`, rounded up, never below 1. */
  expiresInMinutes: number;
}>;

export type VerificationEmailContent = Readonly<{
  subject: string;
  text: string;
  html: string;
}>;

/**
 * Knobs for the built-in template. Colors are `#rgb` or `#rrggbb`; font
 * families are CSS font-family lists. Everything but `productName` has a
 * neutral default.
 */
export type VerificationEmailTheme = Readonly<{
  productName: string;
  /** Defaults to `Your <productName> verification code`. */
  subject?: string;
  /** Defaults to `Confirm your email`. */
  heading?: string;
  /** One paragraph above the code. */
  intro?: string;
  /** Shown under the code, before the expiry note. */
  ignoreNotice?: string;
  footerText?: string;
  /** An `https:` page for help; rendered as a link in the footer. */
  supportUrl?: string;
  /** An `https:` image. Omit it to keep the message free of remote loads. */
  logoUrl?: string;
  logoAlt?: string;
  logoWidth?: number;
  backgroundColor?: string;
  cardColor?: string;
  borderColor?: string;
  textColor?: string;
  mutedTextColor?: string;
  accentColor?: string;
  codeBackgroundColor?: string;
  codeTextColor?: string;
  headingFontFamily?: string;
  bodyFontFamily?: string;
  codeFontFamily?: string;
}>;

export type EmailVerificationDelivery = Readonly<{
  sender: EmailSender;
  from: string;
  replyTo?: string;
  /** Theme the built-in template. Ignored when `render` is set. */
  theme?: VerificationEmailTheme;
  /** Replace the template entirely. */
  render?: (
    input: VerificationEmailInput,
  ) => VerificationEmailContent | Promise<VerificationEmailContent>;
  /**
   * Called once per failed send with log-safe fields only. It must not throw;
   * if it does, the throw is swallowed so the caller still gets its response.
   */
  onFailure?: (failure: EmailDeliveryFailure) => void;
}>;

const hexColor = /^#(?:[0-9a-f]{3}|[0-9a-f]{6})$/iu;
const fontFamilyList = /^[A-Za-z0-9 ,'"-]{1,200}$/u;
const lineBreak = /[\r\n]/u;
const addrSpec = /^[^\s<>@",;]+@[^\s<>@",;]+\.[^\s<>@",;]+$/u;
const mailboxWithName = /^(?:"([^"\r\n]*)"|([^"<>\r\n]*?))\s*<([^<>\s]+)>$/u;

export function escapeHtml(value: string): string {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&#39;");
}

/** Splits an address into `{ name, email }`; throws on anything malformed. */
export function parseMailbox(value: string, field = "mailbox"): { name: string | null; email: string } {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (trimmed === "" || lineBreak.test(trimmed)) {
    throw new TypeError(`${field} must be a single email address.`);
  }
  if (addrSpec.test(trimmed)) {
    return { name: null, email: trimmed };
  }
  const match = mailboxWithName.exec(trimmed);
  const email = match?.[3];
  if (match === null || email === undefined || !addrSpec.test(email)) {
    throw new TypeError(`${field} must look like addr@example.com or Name <addr@example.com>.`);
  }
  const name = (match[1] ?? match[2] ?? "").trim();
  return { name: name === "" ? null : name, email };
}

/** `ABCD2345` → `ABCD-2345`; codes of other lengths are returned unchanged. */
export function formatVerificationCode(code: string): string {
  return code.length === 8 ? `${code.slice(0, 4)}-${code.slice(4)}` : code;
}

type ResolvedTheme = Readonly<{
  productName: string;
  subject: string;
  heading: string;
  intro: string;
  ignoreNotice: string;
  footerText: string | null;
  supportUrl: string | null;
  logoUrl: string | null;
  logoAlt: string;
  logoWidth: number;
  backgroundColor: string;
  cardColor: string;
  borderColor: string;
  textColor: string;
  mutedTextColor: string;
  accentColor: string;
  codeBackgroundColor: string;
  codeTextColor: string;
  headingFontFamily: string;
  bodyFontFamily: string;
  codeFontFamily: string;
}>;

/** Validates a theme once so a bad value fails at startup, not at first send. */
export function resolveVerificationEmailTheme(theme: VerificationEmailTheme): ResolvedTheme {
  const productName = requireLine(theme.productName, "theme.productName");
  const color = (value: string | undefined, fallback: string, field: string): string => {
    if (value === undefined) return fallback;
    if (!hexColor.test(value)) throw new TypeError(`${field} must be #rgb or #rrggbb.`);
    return value;
  };
  const font = (value: string | undefined, fallback: string, field: string): string => {
    if (value === undefined) return fallback;
    if (!fontFamilyList.test(value)) throw new TypeError(`${field} is not a plain font-family list.`);
    return value;
  };
  const logoWidth = theme.logoWidth ?? 48;
  if (!Number.isInteger(logoWidth) || logoWidth < 16 || logoWidth > 600) {
    throw new TypeError("theme.logoWidth must be an integer from 16 to 600.");
  }
  return Object.freeze({
    productName,
    subject:
      theme.subject === undefined
        ? `Your ${productName} verification code`
        : requireLine(theme.subject, "theme.subject"),
    heading:
      theme.heading === undefined ? "Confirm your email" : requireLine(theme.heading, "theme.heading"),
    intro:
      theme.intro ??
      `Enter this code in ${productName} to confirm that this address belongs to you.`,
    ignoreNotice:
      theme.ignoreNotice ??
      "If you did not ask for this, you can ignore this email; nothing changes without the code.",
    footerText: theme.footerText ?? null,
    supportUrl: theme.supportUrl === undefined ? null : requireHttpsUrl(theme.supportUrl, "theme.supportUrl"),
    logoUrl: theme.logoUrl === undefined ? null : requireHttpsUrl(theme.logoUrl, "theme.logoUrl"),
    logoAlt: theme.logoAlt ?? productName,
    logoWidth,
    backgroundColor: color(theme.backgroundColor, "#f4f4f5", "theme.backgroundColor"),
    cardColor: color(theme.cardColor, "#ffffff", "theme.cardColor"),
    borderColor: color(theme.borderColor, "#e4e4e7", "theme.borderColor"),
    textColor: color(theme.textColor, "#18181b", "theme.textColor"),
    mutedTextColor: color(theme.mutedTextColor, "#52525b", "theme.mutedTextColor"),
    accentColor: color(theme.accentColor, "#18181b", "theme.accentColor"),
    codeBackgroundColor: color(theme.codeBackgroundColor, "#f4f4f5", "theme.codeBackgroundColor"),
    codeTextColor: color(theme.codeTextColor, "#18181b", "theme.codeTextColor"),
    headingFontFamily: font(
      theme.headingFontFamily,
      "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
      "theme.headingFontFamily",
    ),
    bodyFontFamily: font(
      theme.bodyFontFamily,
      "-apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
      "theme.bodyFontFamily",
    ),
    codeFontFamily: font(
      theme.codeFontFamily,
      "'SFMono-Regular', Menlo, Consolas, 'Liberation Mono', monospace",
      "theme.codeFontFamily",
    ),
  });
}

/**
 * The built-in template: a single table-laid card with inline styles, which is
 * what renders consistently across mail clients. No remote resource is loaded
 * unless the theme names a logo.
 */
export function renderVerificationEmail(
  input: VerificationEmailInput,
  theme: VerificationEmailTheme,
): VerificationEmailContent {
  const t = resolveVerificationEmailTheme(theme);
  const minutes = `${String(input.expiresInMinutes)} minute${input.expiresInMinutes === 1 ? "" : "s"}`;
  const expiry = `This code expires in ${minutes}.`;

  const text = [
    t.productName,
    "",
    t.heading,
    "",
    t.intro,
    "",
    `    ${input.formattedCode}`,
    "",
    expiry,
    t.ignoreNotice,
    ...(t.footerText === null ? [] : ["", t.footerText]),
    ...(t.supportUrl === null ? [] : [t.supportUrl]),
    "",
  ].join("\n");

  const e = escapeHtml;
  const logo =
    t.logoUrl === null
      ? ""
      : `<img src="${e(t.logoUrl)}" width="${String(t.logoWidth)}" alt="${e(t.logoAlt)}" style="display:block;border:0;outline:none;text-decoration:none;height:auto;margin:0 0 16px 0;">`;
  const footer = [
    t.footerText === null ? "" : e(t.footerText),
    t.supportUrl === null
      ? ""
      : `<a href="${e(t.supportUrl)}" style="color:${t.mutedTextColor};text-decoration:underline;">${e(t.supportUrl)}</a>`,
  ]
    .filter((part) => part !== "")
    .join("<br>");

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>${e(t.subject)}</title>
</head>
<body style="margin:0;padding:0;background-color:${t.backgroundColor};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">${e(`${input.formattedCode} is your ${t.productName} code. ${expiry}`)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:${t.backgroundColor};">
<tr><td align="center" style="padding:40px 16px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;background-color:${t.cardColor};border:1px solid ${t.borderColor};border-radius:6px;">
<tr><td style="padding:36px 36px 12px 36px;font-family:${t.bodyFontFamily};color:${t.textColor};">
${logo}<div style="font-family:${t.headingFontFamily};font-size:15px;letter-spacing:0.08em;text-transform:uppercase;color:${t.accentColor};">${e(t.productName)}</div>
<h1 style="margin:14px 0 0 0;font-family:${t.headingFontFamily};font-size:28px;line-height:1.2;font-weight:600;color:${t.textColor};">${e(t.heading)}</h1>
<p style="margin:16px 0 0 0;font-size:16px;line-height:1.55;color:${t.textColor};">${e(t.intro)}</p>
</td></tr>
<tr><td style="padding:12px 36px;">
<div style="font-family:${t.codeFontFamily};font-size:30px;line-height:1;letter-spacing:0.18em;font-weight:600;text-align:center;color:${t.codeTextColor};background-color:${t.codeBackgroundColor};border:1px solid ${t.accentColor};border-radius:4px;padding:20px 12px;">${e(input.formattedCode)}</div>
</td></tr>
<tr><td style="padding:12px 36px 36px 36px;font-family:${t.bodyFontFamily};font-size:14px;line-height:1.55;color:${t.mutedTextColor};">
<p style="margin:0;">${e(expiry)}</p>
<p style="margin:8px 0 0 0;">${e(t.ignoreNotice)}</p>
</td></tr>
</table>
${footer === "" ? "" : `<p style="max-width:520px;margin:20px auto 0 auto;font-family:${t.bodyFontFamily};font-size:12px;line-height:1.5;color:${t.mutedTextColor};text-align:center;">${footer}</p>`}
</td></tr>
</table>
</body>
</html>
`;

  return Object.freeze({ subject: t.subject, text, html });
}

/**
 * Checks a delivery config once, when the router is built, so a missing sender
 * or a malformed `from` fails at boot rather than on a user's first request.
 */
export function assertEmailVerificationDelivery(delivery: EmailVerificationDelivery): void {
  if (
    delivery === null ||
    typeof delivery !== "object" ||
    delivery.sender === null ||
    typeof delivery.sender !== "object" ||
    typeof delivery.sender.send !== "function" ||
    typeof delivery.sender.provider !== "string"
  ) {
    throw new TypeError("emailVerification.sender must be an EmailSender.");
  }
  parseMailbox(delivery.from, "emailVerification.from");
  if (delivery.replyTo !== undefined) {
    parseMailbox(delivery.replyTo, "emailVerification.replyTo");
  }
  if (delivery.render === undefined) {
    if (delivery.theme === undefined) {
      throw new TypeError("emailVerification needs a theme or a render function.");
    }
    resolveVerificationEmailTheme(delivery.theme);
  } else if (typeof delivery.render !== "function") {
    throw new TypeError("emailVerification.render must be a function.");
  }
}

/**
 * Renders and sends one verification email. Throws `EmailDeliveryError` on any
 * failure, including a template that throws or drops the code.
 */
export async function deliverEmailVerification(
  delivery: EmailVerificationDelivery,
  issued: Readonly<{ verificationId: string; code: string; email: string; expiresAt: Date }>,
  now: Date = new Date(),
): Promise<EmailDeliveryReceipt> {
  const input: VerificationEmailInput = Object.freeze({
    code: issued.code,
    formattedCode: formatVerificationCode(issued.code),
    email: issued.email,
    expiresAt: issued.expiresAt,
    expiresInMinutes: Math.max(1, Math.ceil((issued.expiresAt.getTime() - now.getTime()) / 60_000)),
  });

  let content: VerificationEmailContent;
  try {
    content =
      delivery.render === undefined
        ? renderVerificationEmail(input, delivery.theme ?? { productName: "" })
        : await delivery.render(input);
    requireLine(content.subject, "subject");
    if (typeof content.text !== "string" || typeof content.html !== "string") {
      throw new TypeError("Rendered email needs text and html.");
    }
    const carriesCode = (body: string): boolean =>
      body.includes(input.code) || body.includes(input.formattedCode);
    if (!carriesCode(content.text) || !carriesCode(content.html)) {
      throw new TypeError("Rendered email does not contain the verification code.");
    }
  } catch {
    throw new EmailDeliveryError(delivery.sender.provider, "render");
  }

  return delivery.sender.send({
    from: delivery.from,
    to: issued.email,
    ...(delivery.replyTo === undefined ? {} : { replyTo: delivery.replyTo }),
    subject: content.subject,
    text: content.text,
    html: content.html,
    idempotencyKey: `email-verification/${issued.verificationId}`,
  });
}

function requireLine(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "" || lineBreak.test(value)) {
    throw new TypeError(`${field} must be a non-empty single line.`);
  }
  return value.trim();
}

function requireHttpsUrl(value: string, field: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${field} must be an absolute https: URL.`);
  }
  if (url.protocol !== "https:") {
    throw new TypeError(`${field} must be an absolute https: URL.`);
  }
  return url.href;
}
