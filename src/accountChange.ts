import { DerivationError } from "./errors.js";
import { normalizeUsername } from "./normalization.js";

/**
 * The account-change message: the exact bytes a client signs to authorize a
 * change to its own identity-service account, such as rotating its enrolled
 * key or enrolling a recovery key.
 *
 * It lives in the core entry, with no server import, so that a browser worker
 * builds the bytes it signs from typed fields instead of signing text a server
 * sent it. The identity service builds the same bytes from its own records and
 * verifies the signatures over them (docs/PROTOCOL.md#account-change-message).
 *
 * Ten lines joined by `\n` (U+000A), UTF-8, no trailing newline:
 *
 * ```text
 * web2-ish-self-custody account change v1
 * <serviceProfileId>
 * <applicationId>
 * <networkId>
 * <action>
 * <usernameNormalized>
 * <nonceHex>        the `rotation` challenge's 32-byte nonce, 64 lowercase hex
 * <expiresAt>       the challenge's expiry, ISO-8601 UTC with milliseconds
 * <authorizer>      "key:" + codec.encodePublicKey | "recovery-key:" + 64 hex
 *                   | "email:" + resetId | "session-reset:" + resetId
 * <subject>         "key:" + codec.encodePublicKey | "recovery-key:" + 64 hex
 *                   | "email:" + normalizeEmail(address) | "setting:on" | "setting:off"
 *                   | "host:" + label | "none"
 * ```
 *
 * Fixed wire surface: a change to the domain, the layout, an action or a
 * principal form is a new domain string (`… v2`) with its own vector, never an
 * edit (docs/PROTOCOL.md#versioning).
 */
export const ACCOUNT_CHANGE_DOMAIN = "web2-ish-self-custody account change v1";

/**
 * The actions this release signs, each with one authorizer and one subject
 * form. The first six arrived with account changes and recovery keys; the
 * last five with account resets. An existing action's forms never change
 * (docs/PROTOCOL.md#versioning).
 */
export type AccountChangeAction =
  | "sign-in-key-rotation"
  | "email-change"
  | "recovery-key-enrollment"
  | "recovery-key-removal"
  | "recovery-begin"
  | "recovery-reset"
  | "reauthentication"
  | "email-reset-setting"
  | "signed-in-reset-setting"
  | "email-reset"
  | "signed-in-reset";

/**
 * `email` is an `email:` address subject; `email-reset` is the `email:`
 * authorizer of an emailed reset, which names the reset's id, never an
 * address. Each action allows exactly one of the two, and a reset id (a UUID)
 * is never a valid address, so the shared prefix cannot be confused.
 */
type PrincipalForm =
  | "key"
  | "recovery-key"
  | "email"
  | "none"
  | "host"
  | "setting"
  | "email-reset"
  | "session-reset";

const actionRules: Readonly<
  Record<AccountChangeAction, Readonly<{ authorizer: PrincipalForm; subject: PrincipalForm }>>
> = Object.freeze({
  "sign-in-key-rotation": Object.freeze({ authorizer: "key", subject: "key" }),
  "email-change": Object.freeze({ authorizer: "key", subject: "email" }),
  "recovery-key-enrollment": Object.freeze({ authorizer: "key", subject: "recovery-key" }),
  "recovery-key-removal": Object.freeze({ authorizer: "key", subject: "none" }),
  "recovery-begin": Object.freeze({ authorizer: "recovery-key", subject: "none" }),
  "recovery-reset": Object.freeze({ authorizer: "recovery-key", subject: "key" }),
  reauthentication: Object.freeze({ authorizer: "key", subject: "host" }),
  "email-reset-setting": Object.freeze({ authorizer: "key", subject: "setting" }),
  "signed-in-reset-setting": Object.freeze({ authorizer: "key", subject: "setting" }),
  "email-reset": Object.freeze({ authorizer: "email-reset", subject: "key" }),
  "signed-in-reset": Object.freeze({ authorizer: "session-reset", subject: "key" }),
});

export const accountChangeActions: readonly AccountChangeAction[] = Object.freeze(
  Object.keys(actionRules) as AccountChangeAction[],
);

export type AccountChangeMessageInput = Readonly<{
  serviceProfileId: string;
  applicationId: string;
  networkId: string;
  action: AccountChangeAction;
  /** Already normalized: the challenge's `usernameNormalized`. */
  usernameNormalized: string;
  /** The `rotation` challenge's nonce: line 7 of its `message`. */
  nonceHex: string;
  /** The challenge's `expiresAt`. */
  expiresAt: Date;
  /** The principal that authorizes the change, in the action's authorizer form. */
  authorizer: string;
  /** What the change is about, in the action's subject form. */
  subject: string;
}>;

const MAX_EMAIL_LENGTH = 254;
/**
 * The local part refuses whitespace, the C0 and C1 controls (NUL and NEL among
 * them) and DEL, so every address `normalizeEmail` returns is a subject that
 * `buildAccountChangeMessage` accepts.
 */
const emailPattern =
  /^[^\s@<>"',;:\\\u0000-\u001f\u007f-\u009f]{1,64}@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/u;
/** A Unicode line break (LF, CR, VT, FF, NEL, LS, PS) anywhere in a field. */
const lineBreak = /[\n\r\u000b\u000c\u0085\u2028\u2029]/u;
/** The identity service's literal rule for its profile, application and network ids. */
const contextLiteral = /^[a-z0-9][a-z0-9._:-]{0,79}$/u;
const nonceHexPattern = /^[0-9a-f]{64}$/u;
/** `key:` and a printable-ASCII public-key identifier of at most 160 characters. */
const keyPrincipal = /^key:[\x21-\x7e]{1,160}$/u;
const recoveryKeyPrincipal = /^recovery-key:[0-9a-f]{64}$/u;
const EMAIL_PREFIX = "email:";
/** A reset id as the service issues it: a UUID in lowercase hex. */
const resetIdText = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
const emailResetPrincipal = new RegExp(`^email:${resetIdText}$`, "u");
const sessionResetPrincipal = new RegExp(`^session-reset:${resetIdText}$`, "u");
const settingPrincipal = /^setting:(on|off)$/u;

/**
 * A host's reauthentication label: 3 to 80 characters from `[a-z0-9._:-]`,
 * starting with a letter or digit. It is a constant the host chooses to name
 * what the reauthentication unlocks, never user data. Package-internal: the
 * identity service checks `verifyReauthentication`'s label with it.
 */
export const hostLabelPattern = /^[a-z0-9][a-z0-9._:-]{2,79}$/u;

/**
 * The service's email normalization: trim, lowercase, and refuse anything that
 * is not a plain `local@domain` address of at most 254 characters with an ASCII
 * DNS-style domain. Exported so that a client builds exactly the `email:`
 * subject the service verifies. Throws `invalid-email`.
 */
export function normalizeEmail(value: string): string {
  if (typeof value !== "string") {
    throw new DerivationError("email must be a string.", "invalid-email");
  }
  const normalized = value.trim().toLowerCase();
  if (normalized.length > MAX_EMAIL_LENGTH || !emailPattern.test(normalized)) {
    throw new DerivationError("email is not a valid address.", "invalid-email");
  }
  return normalized;
}

function refuse(message: string): never {
  throw new DerivationError(message, "invalid-message");
}

function textField(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    refuse(`${field} must be a non-empty string.`);
  }
  if (lineBreak.test(value)) {
    refuse(`${field} must not contain a line break.`);
  }
  return value;
}

function assertPrincipal(value: string, form: PrincipalForm, field: string): void {
  switch (form) {
    case "key":
      if (!keyPrincipal.test(value)) {
        refuse(`${field} must be "key:" followed by the codec's public-key identifier.`);
      }
      return;
    case "recovery-key":
      if (!recoveryKeyPrincipal.test(value)) {
        refuse(`${field} must be "recovery-key:" followed by 64 lowercase hex characters.`);
      }
      return;
    case "email": {
      const address = value.startsWith(EMAIL_PREFIX) ? value.slice(EMAIL_PREFIX.length) : null;
      let canonical: string | null = null;
      try {
        canonical = address === null ? null : normalizeEmail(address);
      } catch {
        canonical = null;
      }
      if (canonical === null || canonical !== address) {
        refuse(`${field} must be "email:" followed by a normalized email address.`);
      }
      return;
    }
    case "none":
      if (value !== "none") {
        refuse(`${field} must be "none" for this action.`);
      }
      return;
    case "host": {
      const label = value.startsWith("host:") ? value.slice("host:".length) : "";
      if (!hostLabelPattern.test(label)) {
        refuse(`${field} must be "host:" followed by a 3-80 character label from [a-z0-9._:-].`);
      }
      return;
    }
    case "setting":
      if (!settingPrincipal.test(value)) {
        refuse(`${field} must be "setting:on" or "setting:off".`);
      }
      return;
    case "email-reset":
      if (!emailResetPrincipal.test(value)) {
        refuse(`${field} must be "email:" followed by the reset id, a lowercase UUID.`);
      }
      return;
    case "session-reset":
      if (!sessionResetPrincipal.test(value)) {
        refuse(`${field} must be "session-reset:" followed by the reset id, a lowercase UUID.`);
      }
      return;
  }
}

/**
 * Builds the account-change message (see `ACCOUNT_CHANGE_DOMAIN`). It refuses,
 * with `invalid-message`, a line break in any field, an action this release
 * does not define, a username that is not already normalized, a nonce that is
 * not 64 lowercase hex characters, an invalid expiry, and an authorizer or
 * subject in any form other than the action's own.
 */
export function buildAccountChangeMessage(input: AccountChangeMessageInput): string {
  if (typeof input !== "object" || input === null) {
    refuse("The account-change input must be an object.");
  }
  const serviceProfileId = textField(input.serviceProfileId, "serviceProfileId");
  const applicationId = textField(input.applicationId, "applicationId");
  const networkId = textField(input.networkId, "networkId");
  for (const [field, value] of [
    ["serviceProfileId", serviceProfileId],
    ["applicationId", applicationId],
    ["networkId", networkId],
  ] as const) {
    if (!contextLiteral.test(value)) {
      refuse(`${field} must be 1-80 characters from [a-z0-9._:-].`);
    }
  }

  const action = textField(input.action, "action");
  const rule = Object.prototype.hasOwnProperty.call(actionRules, action)
    ? actionRules[action as AccountChangeAction]
    : undefined;
  if (rule === undefined) {
    refuse(`action must be one of: ${accountChangeActions.join(", ")}.`);
  }

  const usernameNormalized = textField(input.usernameNormalized, "usernameNormalized");
  let canonicalUsername: string | null;
  try {
    canonicalUsername = normalizeUsername(usernameNormalized);
  } catch {
    canonicalUsername = null;
  }
  if (canonicalUsername !== usernameNormalized) {
    refuse("usernameNormalized must already be a normalized username.");
  }

  const nonceHex = textField(input.nonceHex, "nonceHex");
  if (!nonceHexPattern.test(nonceHex)) {
    refuse("nonceHex must be 32 bytes as 64 lowercase hex characters.");
  }

  const expiresAt = input.expiresAt;
  if (!(expiresAt instanceof Date) || Number.isNaN(expiresAt.getTime())) {
    refuse("expiresAt must be a valid Date.");
  }

  const authorizer = textField(input.authorizer, "authorizer");
  const subject = textField(input.subject, "subject");
  assertPrincipal(authorizer, rule.authorizer, "authorizer");
  assertPrincipal(subject, rule.subject, "subject");

  return [
    ACCOUNT_CHANGE_DOMAIN,
    serviceProfileId,
    applicationId,
    networkId,
    action,
    usernameNormalized,
    nonceHex,
    expiresAt.toISOString(),
    authorizer,
    subject,
  ].join("\n");
}
