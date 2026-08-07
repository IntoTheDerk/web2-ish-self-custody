import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { fingerprint, utf8 } from "../encoding.js";
import { normalizeUsername as normalizeSdkUsername } from "../normalization.js";
import {
  buildChallengeMessage,
  canonicalWalletIdentity,
  verifyChallengeSignature,
} from "./challenge.js";
import { resolveIdentityServiceConfig } from "./config.js";
import type { IdentityService } from "./contract.js";
import { IdentityError } from "./errors.js";
import { runIdentityMigrations } from "./migrations.js";
import {
  instantColumn,
  integerColumn,
  optionalInstantColumn,
  optionalRow,
  optionalTextColumn,
  requireSingleRow,
  textColumn,
  type SqlDriver,
  type SqlParameter,
  type SqlRow,
} from "./sql.js";
import {
  constantTimeEqualHex,
  generateSessionToken,
  generateVerificationCode,
  hashSessionToken,
  hashVerificationCode,
  randomNonceHex,
} from "./tokens.js";
import {
  challengePurposes,
  serverProfileIds,
  type AuthenticatedIdentity,
  type ChallengePurpose,
  type EmailVerificationRequest,
  type IdentityAccount,
  type IdentityChallenge,
  type IdentityServiceConfig,
  type IdentitySession,
  type IdentityWallet,
  type IssuedEmailVerification,
  type IssuedSession,
  type LoginInput,
  type PublishedDerivationProfile,
  type RegistrationInput,
  type RequestContext,
  type ResolvedIdentityServiceConfig,
  type ServerProfileId,
} from "./types.js";

const tablePrefixPattern = /^[a-z][a-z0-9_]{0,31}$/u;
const uuidPattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const controlCharacters = /[\u0000-\u001f\u007f]/u;
const emailPattern =
  /^[^\s@<>"',;:\\]{1,64}@[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/u;
const nonAlphanumeric = /[^A-Z0-9]/gu;

const MIN_USERNAME_LENGTH = 3;
const MAX_USERNAME_LENGTH = 320;
const MAX_DISPLAY_NAME_LENGTH = 120;
const MAX_EMAIL_LENGTH = 254;
const MAX_CONTEXT_HASH_LENGTH = 128;

/** Rate-limit rows outlive their window only long enough to stay auditable. */
const RATE_LIMIT_RETENTION_SECONDS = 86_400;

const RATE_LIMIT_BUCKET_DOMAIN = "web2-ish-self-custody rate limit bucket v1";

type RateLimitRule = Readonly<{
  id: string;
  limit: number;
  windowSeconds: number;
}>;

const rateLimitRules: Readonly<Record<string, RateLimitRule>> = Object.freeze({
  challenge: Object.freeze({ id: "challenge", limit: 20, windowSeconds: 300 }),
  register: Object.freeze({ id: "register", limit: 10, windowSeconds: 3_600 }),
  login: Object.freeze({ id: "login", limit: 15, windowSeconds: 300 }),
  emailVerification: Object.freeze({
    id: "email-verification",
    limit: 5,
    windowSeconds: 3_600,
  }),
});

function requireRule(name: string): RateLimitRule {
  const rule = rateLimitRules[name];
  if (rule === undefined) {
    throw new IdentityError("Unknown rate limit rule.", "invalid-request");
  }
  return rule;
}

/**
 * The table prefix is the only caller-supplied value that reaches SQL text
 * rather than a bind parameter, so it is held to a strict identifier shape.
 */
function assertTablePrefix(value: string): string {
  if (!tablePrefixPattern.test(value)) {
    throw new IdentityError(
      "tablePrefix must be lowercase snake_case, 1-32 characters.",
      "invalid-service-profile",
    );
  }
  return value;
}

type MissingIdentifierCode =
  | "account-not-found"
  | "challenge-not-found"
  | "email-verification-failed";

/**
 * Identifiers are shape-checked before reaching a `::uuid` cast, so a
 * malformed id surfaces as its caller's own "not found" rather than as a
 * PostgreSQL 22P02 leaking out of the driver.
 */
function assertUuid(value: string, code: MissingIdentifierCode): string {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (!uuidPattern.test(normalized)) {
    throw new IdentityError("Malformed identifier.", code);
  }
  return normalized;
}

function booleanColumn(row: SqlRow, column: string): boolean {
  const value = row[column];
  if (typeof value === "boolean") {
    return value;
  }
  if (value === "t" || value === "true") {
    return true;
  }
  if (value === "f" || value === "false") {
    return false;
  }
  throw new TypeError(`Expected boolean column "${column}".`);
}

function accountStatus(value: string): "active" | "suspended" {
  if (value === "active" || value === "suspended") {
    return value;
  }
  throw new IdentityError("Unknown account status.", "invalid-service-profile");
}

function walletCurve(value: string): "ed25519" {
  if (value === "ed25519") {
    return value;
  }
  throw new IdentityError("Unknown wallet curve.", "invalid-service-profile");
}

function assertServerProfileId(value: string): ServerProfileId {
  const match = serverProfileIds.find((id) => id === value);
  if (match === undefined) {
    throw new IdentityError(
      "Stored profile id is not serviceable.",
      "invalid-service-profile",
    );
  }
  return match;
}

function assertChallengePurpose(value: string): ChallengePurpose {
  const match = challengePurposes.find((purpose) => purpose === value);
  if (match === undefined) {
    throw new IdentityError(
      `purpose must be one of: ${challengePurposes.join(", ")}.`,
      "invalid-purpose",
    );
  }
  return match;
}

function normalizeDisplayName(value: string): string {
  const candidate = value.trim();
  if (
    candidate.length === 0 ||
    candidate.length > MAX_DISPLAY_NAME_LENGTH ||
    controlCharacters.test(candidate)
  ) {
    throw new IdentityError(
      "displayName must be 1-120 characters and contain no control characters.",
      "invalid-display-name",
    );
  }
  return candidate;
}

function normalizeEmail(value: string): string {
  const normalized = value.trim().toLowerCase();
  if (normalized.length > MAX_EMAIL_LENGTH || !emailPattern.test(normalized)) {
    throw new IdentityError("email is not a valid address.", "invalid-email");
  }
  return normalized;
}

/** Context hashes arrive pre-hashed; the service never sees a raw IP. */
function sanitizeContextHash(value: string | undefined): string | null {
  if (value === undefined) {
    return null;
  }
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_CONTEXT_HASH_LENGTH) {
    return null;
  }
  return trimmed;
}

function requestNow(context: RequestContext | undefined): string | null {
  const now = context?.now;
  return now === undefined ? null : now.toISOString();
}

function metadataJson(
  metadata: Readonly<Record<string, string | number | boolean | null>>,
): string {
  return JSON.stringify(metadata);
}

function sqlStateOf(error: unknown): string | null {
  if (typeof error !== "object" || error === null) {
    return null;
  }
  const code = (error as { code?: unknown }).code;
  return typeof code === "string" ? code : null;
}

function mapAccount(row: SqlRow, prefix: string): IdentityAccount {
  return Object.freeze({
    id: textColumn(row, `${prefix}id`),
    serviceProfileId: textColumn(row, `${prefix}service_profile_id`),
    usernameNormalized: textColumn(row, `${prefix}username_normalized`),
    displayName: textColumn(row, `${prefix}display_name`),
    email: optionalTextColumn(row, `${prefix}email`),
    emailVerifiedAt: optionalInstantColumn(row, `${prefix}email_verified_at`),
    status: accountStatus(textColumn(row, `${prefix}status`)),
    createdAt: instantColumn(row, `${prefix}created_at`),
    updatedAt: instantColumn(row, `${prefix}updated_at`),
  });
}

function mapWallet(row: SqlRow, prefix: string): IdentityWallet {
  return Object.freeze({
    id: textColumn(row, `${prefix}id`),
    accountId: textColumn(row, `${prefix}account_id`),
    serviceProfileId: textColumn(row, `${prefix}service_profile_id`),
    profileId: assertServerProfileId(textColumn(row, `${prefix}profile_id`)),
    curve: walletCurve(textColumn(row, `${prefix}curve`)),
    applicationId: textColumn(row, `${prefix}application_id`),
    networkId: textColumn(row, `${prefix}network_id`),
    address: textColumn(row, `${prefix}address`),
    addressNormalized: textColumn(row, `${prefix}address_normalized`),
    publicKey: textColumn(row, `${prefix}public_key`),
    fingerprint: textColumn(row, `${prefix}fingerprint`),
    isPrimary: booleanColumn(row, `${prefix}is_primary`),
    createdAt: instantColumn(row, `${prefix}created_at`),
  });
}

function mapSession(row: SqlRow, prefix: string): IdentitySession {
  return Object.freeze({
    id: textColumn(row, `${prefix}id`),
    accountId: textColumn(row, `${prefix}account_id`),
    issuedAt: instantColumn(row, `${prefix}issued_at`),
    expiresAt: instantColumn(row, `${prefix}expires_at`),
    lastSeenAt: instantColumn(row, `${prefix}last_seen_at`),
  });
}

type ConsumedChallenge = Readonly<{
  id: string;
  purpose: ChallengePurpose;
  usernameNormalized: string;
  nonceHex: string;
  expiresAt: Date;
}>;

export function createIdentityService(
  sql: SqlDriver,
  config: IdentityServiceConfig,
): IdentityService {
  const resolved: ResolvedIdentityServiceConfig =
    resolveIdentityServiceConfig(config);
  const p = assertTablePrefix(resolved.tablePrefix);
  const serviceProfileId = resolved.serviceProfileId;

  const normalizeUsername = (username: string): string => {
    let normalized: string;
    try {
      normalized = normalizeSdkUsername(username);
    } catch {
      throw new IdentityError(
        "username failed normalization for this service profile.",
        "invalid-username",
      );
    }
    // The accounts table constrains the stored username to 3-320 characters;
    // enforcing it here keeps challenges from being minted for usernames that
    // could never register.
    if (
      normalized.length < MIN_USERNAME_LENGTH ||
      normalized.length > MAX_USERNAME_LENGTH
    ) {
      throw new IdentityError(
        "username must be 3-320 characters after normalization.",
        "invalid-username",
      );
    }
    return normalized;
  };

  /**
   * One statement: insert-or-bump, resetting the window when it has elapsed.
   * The bucket is hashed so unregistered usernames probed by an attacker are
   * not persisted in the clear.
   */
  const enforceRateLimit = async (
    rule: RateLimitRule,
    subject: readonly string[],
    context: RequestContext | undefined,
  ): Promise<void> => {
    const bucket = bytesToHex(
      sha256(
        utf8(
          [RATE_LIMIT_BUCKET_DOMAIN, serviceProfileId, rule.id, ...subject].join(
            "\n",
          ),
        ),
      ),
    );
    const rows = await sql.query(
      `WITH clock AS (SELECT COALESCE($4::timestamptz, now()) AS at)
       INSERT INTO ${p}_rate_limits AS rl (bucket, rule_id, count, window_start, updated_at)
       SELECT $1::text, $2::text, 1, clock.at, clock.at FROM clock
       ON CONFLICT (bucket) DO UPDATE
         SET count = CASE
               WHEN rl.window_start + (interval '1 second' * $3::double precision) <= excluded.updated_at
               THEN 1
               ELSE rl.count + 1
             END,
             window_start = CASE
               WHEN rl.window_start + (interval '1 second' * $3::double precision) <= excluded.updated_at
               THEN excluded.window_start
               ELSE rl.window_start
             END,
             updated_at = excluded.updated_at
       RETURNING count, window_start`,
      [bucket, rule.id, rule.windowSeconds, requestNow(context)],
    );
    const row = requireSingleRow(
      rows,
      () => new IdentityError("Rate limit bookkeeping failed.", "invalid-request"),
    );
    if (integerColumn(row, "count") > rule.limit) {
      const windowStart = instantColumn(row, "window_start");
      const reference = context?.now ?? new Date();
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil(
          (windowStart.getTime() +
            rule.windowSeconds * 1_000 -
            reference.getTime()) /
            1_000,
        ),
      );
      throw new IdentityError("Too many requests; retry later.", "rate-limited", {
        rule: rule.id,
        retryAfterSeconds,
      });
    }
  };

  /**
   * Atomic consumption. The single UPDATE is the authorization gate: if it
   * returns no row the challenge was already spent or has expired, and no
   * signature verification may happen against it.
   */
  const consumeChallenge = async (
    challengeId: string,
    purpose: ChallengePurpose,
    context: RequestContext | undefined,
  ): Promise<ConsumedChallenge> => {
    const id = assertUuid(challengeId, "challenge-not-found");
    const nowParam = requestNow(context);
    const rows = await sql.query(
      `UPDATE ${p}_auth_challenges
         SET consumed_at = COALESCE($4::timestamptz, now())
       WHERE id = $1::uuid
         AND service_profile_id = $2::text
         AND purpose = $3::text
         AND consumed_at IS NULL
         AND expires_at > COALESCE($4::timestamptz, now())
       RETURNING id, purpose, username_normalized,
                 encode(nonce, 'hex') AS nonce_hex, expires_at`,
      [id, serviceProfileId, purpose, nowParam],
    );
    const row = optionalRow(rows);
    if (row === null) {
      throw await classifyChallengeFailure(id, purpose, nowParam);
    }
    return Object.freeze({
      id: textColumn(row, "id"),
      purpose: assertChallengePurpose(textColumn(row, "purpose")),
      usernameNormalized: textColumn(row, "username_normalized"),
      nonceHex: textColumn(row, "nonce_hex"),
      expiresAt: instantColumn(row, "expires_at"),
    });
  };

  const classifyChallengeFailure = async (
    id: string,
    purpose: ChallengePurpose,
    nowParam: string | null,
  ): Promise<IdentityError> => {
    const rows = await sql.query(
      `SELECT purpose, consumed_at, expires_at,
              expires_at <= COALESCE($3::timestamptz, now()) AS is_expired
         FROM ${p}_auth_challenges
        WHERE id = $1::uuid AND service_profile_id = $2::text`,
      [id, serviceProfileId, nowParam],
    );
    const row = optionalRow(rows);
    if (row === null) {
      return new IdentityError("Challenge does not exist.", "challenge-not-found");
    }
    if (textColumn(row, "purpose") !== purpose) {
      return new IdentityError(
        "Challenge was issued for a different purpose.",
        "invalid-purpose",
      );
    }
    if (optionalInstantColumn(row, "consumed_at") !== null) {
      return new IdentityError(
        "Challenge has already been used.",
        "challenge-consumed",
      );
    }
    if (booleanColumn(row, "is_expired")) {
      return new IdentityError("Challenge has expired.", "challenge-expired");
    }
    return new IdentityError("Challenge is no longer usable.", "challenge-not-found");
  };

  const challengeMessageFor = (challenge: ConsumedChallenge): string =>
    buildChallengeMessage({
      serviceProfileId,
      applicationId: resolved.applicationId,
      networkId: resolved.networkId,
      purpose: challenge.purpose,
      usernameNormalized: challenge.usernameNormalized,
      nonceHex: challenge.nonceHex,
      expiresAt: challenge.expiresAt,
    });

  const issueSession = async (
    accountId: string,
    action: string,
    metadata: Readonly<Record<string, string | number | boolean | null>>,
    context: RequestContext | undefined,
  ): Promise<IssuedSession> => {
    const token = generateSessionToken();
    const rows = await sql.query(
      `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
            new_session AS (
              INSERT INTO ${p}_sessions (
                account_id, token_hash, issued_at, expires_at, last_seen_at,
                ip_hash, user_agent_hash
              )
              SELECT $2::uuid, $3::text, clock.at,
                     date_trunc('milliseconds', clock.at + (interval '1 second' * $4::double precision)),
                     clock.at, $5::text, $6::text
              FROM clock
              RETURNING id, account_id, issued_at, expires_at, last_seen_at
            ),
            logged AS (
              INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
              SELECT $2::uuid, $7::text, $8::jsonb, clock.at FROM clock
              RETURNING 1
            )
       SELECT id, account_id, issued_at, expires_at, last_seen_at FROM new_session`,
      [
        requestNow(context),
        accountId,
        hashSessionToken(token),
        resolved.sessionTtlSeconds,
        sanitizeContextHash(context?.ipHash),
        sanitizeContextHash(context?.userAgentHash),
        action,
        metadataJson(metadata),
      ],
    );
    const row = requireSingleRow(
      rows,
      () => new IdentityError("Session could not be issued.", "account-not-found"),
    );
    return Object.freeze({ session: mapSession(row, ""), token });
  };

  const loadAccount = async (accountId: string): Promise<IdentityAccount> => {
    const id = assertUuid(accountId, "account-not-found");
    const rows = await sql.query(
      `SELECT id, service_profile_id, username_normalized, display_name, email,
              email_verified_at, status, created_at, updated_at
         FROM ${p}_accounts
        WHERE id = $1::uuid AND service_profile_id = $2::text`,
      [id, serviceProfileId],
    );
    return mapAccount(
      requireSingleRow(
        rows,
        () => new IdentityError("Account does not exist.", "account-not-found"),
      ),
      "",
    );
  };

  const listWalletsForAccount = async (
    accountId: string,
  ): Promise<readonly IdentityWallet[]> => {
    const id = assertUuid(accountId, "account-not-found");
    const rows = await sql.query(
      `SELECT w.id, w.account_id, w.service_profile_id, w.profile_id, w.curve,
              w.application_id, w.network_id, w.address, w.address_normalized,
              w.public_key, w.fingerprint, w.is_primary, w.created_at
         FROM ${p}_accounts a
         LEFT JOIN ${p}_account_wallets w ON w.account_id = a.id
        WHERE a.id = $1::uuid AND a.service_profile_id = $2::text
        ORDER BY w.is_primary DESC NULLS LAST, w.created_at ASC`,
      [id, serviceProfileId],
    );
    if (rows.length === 0) {
      throw new IdentityError("Account does not exist.", "account-not-found");
    }
    return Object.freeze(
      rows
        .filter((row) => row["id"] !== null && row["id"] !== undefined)
        .map((row) => mapWallet(row, "")),
    );
  };

  /**
   * Most recent consumed, still-unexpired verification for this address. Used
   * only to decide whether registration may proceed; it never unlocks
   * anything else.
   */
  const findVerifiedEmailStamp = async (
    usernameNormalized: string,
    email: string,
    nowParam: string | null,
  ): Promise<string | null> => {
    const rows = await sql.query(
      `SELECT consumed_at
         FROM ${p}_email_verifications
        WHERE service_profile_id = $1::text
          AND username_normalized = $2::text
          AND email = $3::text
          AND consumed_at IS NOT NULL
          AND expires_at > COALESCE($4::timestamptz, now())
        ORDER BY consumed_at DESC
        LIMIT 1`,
      [serviceProfileId, usernameNormalized, email, nowParam],
    );
    const row = optionalRow(rows);
    if (row === null) {
      return null;
    }
    return instantColumn(row, "consumed_at").toISOString();
  };

  const registrationConflict = async (
    usernameNormalized: string,
    addressNormalized: string,
  ): Promise<IdentityError> => {
    const rows = await sql.query(
      `SELECT
         EXISTS (
           SELECT 1 FROM ${p}_accounts
            WHERE service_profile_id = $1::text AND username_normalized = $2::text
         ) AS username_taken,
         EXISTS (
           SELECT 1 FROM ${p}_account_wallets
            WHERE service_profile_id = $1::text AND address_normalized = $3::text
         ) AS address_taken`,
      [serviceProfileId, usernameNormalized, addressNormalized],
    );
    const row = optionalRow(rows);
    if (row !== null && booleanColumn(row, "username_taken")) {
      return new IdentityError(
        "That username is already registered.",
        "account-exists",
      );
    }
    if (row !== null && booleanColumn(row, "address_taken")) {
      return new IdentityError(
        "That wallet address is already registered.",
        "wallet-registered",
      );
    }
    return new IdentityError(
      "Registration conflicted with an existing record.",
      "account-exists",
    );
  };

  let cachedDerivationProfile: PublishedDerivationProfile | null = null;

  return Object.freeze({
    config: resolved,

    async migrate(): Promise<readonly number[]> {
      return runIdentityMigrations(sql, resolved);
    },

    async derivationProfile(): Promise<PublishedDerivationProfile> {
      if (cachedDerivationProfile !== null) {
        return cachedDerivationProfile;
      }
      const rows = await sql.query(
        `SELECT service_profile_id, profile_id, algorithm, curve, application_id,
                network_id, encode(public_salt, 'hex') AS public_salt_hex,
                kdf_n, kdf_r, kdf_p, kdf_dk_len
           FROM ${p}_service_profiles
          WHERE service_profile_id = $1::text`,
        [serviceProfileId],
      );
      const row = requireSingleRow(
        rows,
        () =>
          new IdentityError(
            "Service derivation profile has not been provisioned; run migrations.",
            "service-profile-missing",
          ),
      );
      const profile: PublishedDerivationProfile = Object.freeze({
        serviceProfileId: textColumn(row, "service_profile_id"),
        profileId: assertServerProfileId(textColumn(row, "profile_id")),
        algorithm: textColumn(row, "algorithm"),
        curve: walletCurve(textColumn(row, "curve")),
        applicationId: textColumn(row, "application_id"),
        networkId: textColumn(row, "network_id"),
        publicSaltHex: textColumn(row, "public_salt_hex"),
        kdf: Object.freeze({
          N: integerColumn(row, "kdf_n"),
          r: integerColumn(row, "kdf_r"),
          p: integerColumn(row, "kdf_p"),
          dkLen: integerColumn(row, "kdf_dk_len"),
        }),
      });
      if (
        profile.profileId !== resolved.profileId ||
        profile.applicationId !== resolved.applicationId ||
        profile.networkId !== resolved.networkId
      ) {
        throw new IdentityError(
          "Stored derivation profile does not match this service configuration; every wallet in this namespace depends on it.",
          "invalid-service-profile",
        );
      }
      // Immutable by construction (triggers reject UPDATE/DELETE/TRUNCATE),
      // so a process-lifetime cache can never go stale.
      cachedDerivationProfile = profile;
      return profile;
    },

    async createChallenge(
      username: string,
      purpose: ChallengePurpose,
      context?: RequestContext,
    ): Promise<IdentityChallenge> {
      const usernameNormalized = normalizeUsername(username);
      const checkedPurpose = assertChallengePurpose(purpose);
      await enforceRateLimit(
        requireRule("challenge"),
        [usernameNormalized, checkedPurpose],
        context,
      );

      // Deliberately no account lookup: an unknown username must produce a
      // challenge indistinguishable from a known one.
      const nonceHex = randomNonceHex();
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($5::timestamptz, now()) AS at)
         INSERT INTO ${p}_auth_challenges (
           service_profile_id, username_normalized, purpose, nonce, expires_at, created_at
         )
         SELECT $1::text, $2::text, $3::text, decode($4::text, 'hex'),
                date_trunc('milliseconds', clock.at + (interval '1 second' * $6::double precision)),
                clock.at
         FROM clock
         RETURNING id, expires_at`,
        [
          serviceProfileId,
          usernameNormalized,
          checkedPurpose,
          nonceHex,
          requestNow(context),
          resolved.challengeTtlSeconds,
        ],
      );
      const row = requireSingleRow(
        rows,
        () =>
          new IdentityError("Challenge could not be issued.", "invalid-request"),
      );
      const expiresAt = instantColumn(row, "expires_at");
      return Object.freeze({
        id: textColumn(row, "id"),
        purpose: checkedPurpose,
        usernameNormalized,
        message: buildChallengeMessage({
          serviceProfileId,
          applicationId: resolved.applicationId,
          networkId: resolved.networkId,
          purpose: checkedPurpose,
          usernameNormalized,
          nonceHex,
          expiresAt,
        }),
        expiresAt,
      });
    },

    async register(
      input: RegistrationInput,
      context?: RequestContext,
    ): Promise<{
      account: IdentityAccount;
      wallet: IdentityWallet;
      session: IssuedSession;
    }> {
      const usernameNormalized = normalizeUsername(input.username);
      const wallet = canonicalWalletIdentity({
        publicKey: input.publicKey,
        address: input.address,
      });
      const displayName = normalizeDisplayName(
        input.displayName ?? usernameNormalized.slice(0, MAX_DISPLAY_NAME_LENGTH),
      );
      const email = input.email === undefined ? null : normalizeEmail(input.email);
      const nowParam = requestNow(context);

      await enforceRateLimit(
        requireRule("register"),
        [usernameNormalized],
        context,
      );

      const emailVerifiedAt =
        email === null
          ? null
          : await findVerifiedEmailStamp(usernameNormalized, email, nowParam);
      if (resolved.requireVerifiedEmail && emailVerifiedAt === null) {
        throw new IdentityError(
          "This service requires a verified email address before registration.",
          email === null ? "invalid-email" : "email-verification-failed",
        );
      }

      const challenge = await consumeChallenge(
        input.challengeId,
        "registration",
        context,
      );
      if (challenge.usernameNormalized !== usernameNormalized) {
        throw new IdentityError(
          "Challenge was issued for a different username.",
          "wallet-mismatch",
        );
      }
      if (
        !verifyChallengeSignature(
          wallet,
          challengeMessageFor(challenge),
          input.signature,
        )
      ) {
        throw new IdentityError(
          "Challenge signature did not verify against the submitted wallet.",
          "invalid-signature",
        );
      }

      const token = generateSessionToken();
      const parameters: readonly SqlParameter[] = [
        nowParam,
        serviceProfileId,
        usernameNormalized,
        displayName,
        email,
        emailVerifiedAt,
        resolved.profileId,
        wallet.curve,
        resolved.applicationId,
        resolved.networkId,
        wallet.address,
        wallet.addressNormalized,
        wallet.publicKey,
        fingerprint(wallet.address),
        hashSessionToken(token),
        resolved.sessionTtlSeconds,
        sanitizeContextHash(context?.ipHash),
        sanitizeContextHash(context?.userAgentHash),
        metadataJson({
          profileId: resolved.profileId,
          curve: wallet.curve,
          walletFingerprint: fingerprint(wallet.address),
          emailProvided: email !== null,
          emailVerified: emailVerifiedAt !== null,
        }),
      ];

      // Account, primary wallet, session, and audit row land in ONE statement:
      // Neon's HTTP transport has no interactive transactions, so atomicity has
      // to come from the statement itself.
      let rows: SqlRow[];
      try {
        rows = await sql.query(
          `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
                new_account AS (
                  INSERT INTO ${p}_accounts (
                    service_profile_id, username_normalized, display_name, email,
                    email_verified_at, created_at, updated_at
                  )
                  SELECT $2::text, $3::text, $4::text, $5::text, $6::timestamptz,
                         clock.at, clock.at
                  FROM clock
                  RETURNING id, service_profile_id, username_normalized, display_name,
                            email, email_verified_at, status, created_at, updated_at
                ),
                new_wallet AS (
                  INSERT INTO ${p}_account_wallets (
                    account_id, service_profile_id, profile_id, curve, application_id,
                    network_id, address, address_normalized, public_key, fingerprint,
                    is_primary, created_at
                  )
                  SELECT new_account.id, $2::text, $7::text, $8::text, $9::text,
                         $10::text, $11::text, $12::text, $13::text, $14::text,
                         true, clock.at
                  FROM new_account, clock
                  RETURNING id, account_id, service_profile_id, profile_id, curve,
                            application_id, network_id, address, address_normalized,
                            public_key, fingerprint, is_primary, created_at
                ),
                new_session AS (
                  INSERT INTO ${p}_sessions (
                    account_id, token_hash, issued_at, expires_at, last_seen_at,
                    ip_hash, user_agent_hash
                  )
                  SELECT new_account.id, $15::text, clock.at,
                         date_trunc('milliseconds', clock.at + (interval '1 second' * $16::double precision)),
                         clock.at, $17::text, $18::text
                  FROM new_account, clock
                  RETURNING id, account_id, issued_at, expires_at, last_seen_at
                ),
                logged AS (
                  INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                  SELECT new_account.id, 'account.register', $19::jsonb, clock.at
                  FROM new_account, clock
                  RETURNING 1
                )
           SELECT a.id AS account_id,
                  a.service_profile_id AS account_service_profile_id,
                  a.username_normalized AS account_username_normalized,
                  a.display_name AS account_display_name,
                  a.email AS account_email,
                  a.email_verified_at AS account_email_verified_at,
                  a.status AS account_status,
                  a.created_at AS account_created_at,
                  a.updated_at AS account_updated_at,
                  w.id AS wallet_id,
                  w.account_id AS wallet_account_id,
                  w.service_profile_id AS wallet_service_profile_id,
                  w.profile_id AS wallet_profile_id,
                  w.curve AS wallet_curve,
                  w.application_id AS wallet_application_id,
                  w.network_id AS wallet_network_id,
                  w.address AS wallet_address,
                  w.address_normalized AS wallet_address_normalized,
                  w.public_key AS wallet_public_key,
                  w.fingerprint AS wallet_fingerprint,
                  w.is_primary AS wallet_is_primary,
                  w.created_at AS wallet_created_at,
                  s.id AS session_id,
                  s.account_id AS session_account_id,
                  s.issued_at AS session_issued_at,
                  s.expires_at AS session_expires_at,
                  s.last_seen_at AS session_last_seen_at
             FROM new_account a, new_wallet w, new_session s`,
          parameters,
        );
      } catch (error) {
        if (sqlStateOf(error) === "23505") {
          throw await registrationConflict(
            usernameNormalized,
            wallet.addressNormalized,
          );
        }
        if (sqlStateOf(error) === "23503") {
          throw new IdentityError(
            "Service derivation profile has not been provisioned; run migrations.",
            "service-profile-missing",
          );
        }
        throw error;
      }

      const row = requireSingleRow(
        rows,
        () =>
          new IdentityError("Registration did not produce an account.", "invalid-request"),
      );
      return Object.freeze({
        account: mapAccount(row, "account_"),
        wallet: mapWallet(row, "wallet_"),
        session: Object.freeze({ session: mapSession(row, "session_"), token }),
      });
    },

    async login(
      input: LoginInput,
      context?: RequestContext,
    ): Promise<{ account: IdentityAccount; session: IssuedSession }> {
      const usernameNormalized = normalizeUsername(input.username);
      await enforceRateLimit(requireRule("login"), [usernameNormalized], context);

      const challenge = await consumeChallenge(input.challengeId, "login", context);
      if (challenge.usernameNormalized !== usernameNormalized) {
        throw new IdentityError(
          "Challenge was issued for a different username.",
          "wallet-mismatch",
        );
      }

      const rows = await sql.query(
        `SELECT a.id AS account_id,
                a.service_profile_id AS account_service_profile_id,
                a.username_normalized AS account_username_normalized,
                a.display_name AS account_display_name,
                a.email AS account_email,
                a.email_verified_at AS account_email_verified_at,
                a.status AS account_status,
                a.created_at AS account_created_at,
                a.updated_at AS account_updated_at,
                w.public_key AS wallet_public_key,
                w.address AS wallet_address
           FROM ${p}_accounts a
           LEFT JOIN ${p}_account_wallets w ON w.account_id = a.id
          WHERE a.service_profile_id = $1::text AND a.username_normalized = $2::text
          ORDER BY w.is_primary DESC NULLS LAST, w.created_at ASC`,
        [serviceProfileId, usernameNormalized],
      );

      // An unknown account and a bad signature must be one outcome: anything
      // else turns login into an account-existence oracle.
      const invalidSignature = new IdentityError(
        "Challenge signature did not verify against any registered wallet.",
        "invalid-signature",
      );
      const first = optionalRow(rows);
      if (first === null) {
        throw invalidSignature;
      }
      const account = mapAccount(first, "account_");
      if (account.status !== "active") {
        // Suspension takes effect at the next login; existing sessions are cut
        // with `revokeAllSessions`, which is the operator-facing control.
        throw new IdentityError("Account is not active.", "invalid-signature");
      }

      const message = challengeMessageFor(challenge);
      let verified = false;
      for (const row of rows) {
        const publicKey = optionalTextColumn(row, "wallet_public_key");
        const address = optionalTextColumn(row, "wallet_address");
        if (publicKey === null || address === null) {
          continue;
        }
        try {
          const identity = canonicalWalletIdentity({
            publicKey,
            address,
          });
          if (verifyChallengeSignature(identity, message, input.signature)) {
            verified = true;
            break;
          }
        } catch {
          // A stored wallet row that no longer canonicalizes cannot authorize
          // anyone; skip it rather than failing the whole login.
          continue;
        }
      }
      if (!verified) {
        throw invalidSignature;
      }

      const session = await issueSession(
        account.id,
        "account.login",
        { profileId: resolved.profileId, challengePurpose: challenge.purpose },
        context,
      );
      return Object.freeze({ account, session });
    },

    async authenticate(
      token: string,
      context?: RequestContext,
    ): Promise<AuthenticatedIdentity> {
      if (typeof token !== "string" || token.trim().length === 0) {
        throw new IdentityError("Session token is missing.", "session-not-found");
      }
      const tokenHash = hashSessionToken(token);
      const nowParam = requestNow(context);
      const rows = await sql.query(
        `WITH touched AS (
           UPDATE ${p}_sessions
              SET last_seen_at = COALESCE($2::timestamptz, now())
            WHERE token_hash = $1::text
              AND revoked_at IS NULL
              AND expires_at > COALESCE($2::timestamptz, now())
            RETURNING id, account_id, issued_at, expires_at, last_seen_at
         )
         SELECT t.id AS session_id,
                t.account_id AS session_account_id,
                t.issued_at AS session_issued_at,
                t.expires_at AS session_expires_at,
                t.last_seen_at AS session_last_seen_at,
                a.id AS account_id,
                a.service_profile_id AS account_service_profile_id,
                a.username_normalized AS account_username_normalized,
                a.display_name AS account_display_name,
                a.email AS account_email,
                a.email_verified_at AS account_email_verified_at,
                a.status AS account_status,
                a.created_at AS account_created_at,
                a.updated_at AS account_updated_at
           FROM touched t
           JOIN ${p}_accounts a
             ON a.id = t.account_id AND a.service_profile_id = $3::text`,
        [tokenHash, nowParam, serviceProfileId],
      );
      const row = optionalRow(rows);
      if (row === null) {
        const existing = await sql.query(
          `SELECT revoked_at,
                  expires_at <= COALESCE($2::timestamptz, now()) AS is_expired
             FROM ${p}_sessions
            WHERE token_hash = $1::text`,
          [tokenHash, nowParam],
        );
        const session = optionalRow(existing);
        if (session === null || optionalInstantColumn(session, "revoked_at") !== null) {
          throw new IdentityError("Session is not valid.", "session-not-found");
        }
        if (booleanColumn(session, "is_expired")) {
          throw new IdentityError("Session has expired.", "session-expired");
        }
        throw new IdentityError("Session is not valid.", "session-not-found");
      }

      const account = mapAccount(row, "account_");
      return Object.freeze({
        account,
        wallets: await listWalletsForAccount(account.id),
        session: mapSession(row, "session_"),
      });
    },

    async revokeSession(token: string, context?: RequestContext): Promise<void> {
      if (typeof token !== "string" || token.trim().length === 0) {
        throw new IdentityError("Session token is missing.", "session-not-found");
      }
      const tokenHash = hashSessionToken(token);
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($2::timestamptz, now()) AS at),
              revoked AS (
                UPDATE ${p}_sessions
                   SET revoked_at = (SELECT at FROM clock)
                 WHERE token_hash = $1::text AND revoked_at IS NULL
                 RETURNING id, account_id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT revoked.account_id, 'session.revoke', $3::jsonb, (SELECT at FROM clock)
                FROM revoked
                RETURNING 1
              )
         SELECT id FROM revoked`,
        [
          tokenHash,
          requestNow(context),
          metadataJson({ scope: "single" }),
        ],
      );
      if (optionalRow(rows) !== null) {
        return;
      }
      // Already revoked is a success; unknown token is not.
      const existing = await sql.query(
        `SELECT 1 AS present FROM ${p}_sessions WHERE token_hash = $1::text`,
        [tokenHash],
      );
      if (optionalRow(existing) === null) {
        throw new IdentityError("Session is not valid.", "session-not-found");
      }
    },

    async revokeAllSessions(
      accountId: string,
      context?: RequestContext,
    ): Promise<number> {
      const id = assertUuid(accountId, "account-not-found");
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($3::timestamptz, now()) AS at),
              acct AS (
                SELECT id FROM ${p}_accounts
                 WHERE id = $1::uuid AND service_profile_id = $2::text
              ),
              revoked AS (
                UPDATE ${p}_sessions
                   SET revoked_at = (SELECT at FROM clock)
                 WHERE account_id IN (SELECT id FROM acct)
                   AND revoked_at IS NULL
                   AND expires_at > (SELECT at FROM clock)
                 RETURNING id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT acct.id, 'session.revoke-all',
                       jsonb_build_object('scope', 'all', 'revoked', (SELECT count(*) FROM revoked)),
                       (SELECT at FROM clock)
                FROM acct
                RETURNING 1
              )
         SELECT (SELECT count(*) FROM acct)::int AS account_found,
                (SELECT count(*) FROM revoked)::int AS revoked`,
        [id, serviceProfileId, requestNow(context)],
      );
      const row = requireSingleRow(
        rows,
        () => new IdentityError("Account does not exist.", "account-not-found"),
      );
      if (integerColumn(row, "account_found") === 0) {
        throw new IdentityError("Account does not exist.", "account-not-found");
      }
      return integerColumn(row, "revoked");
    },

    async getAccount(accountId: string): Promise<IdentityAccount> {
      return loadAccount(accountId);
    },

    async updateAccount(
      accountId: string,
      changes: Readonly<{ displayName?: string; email?: string }>,
      context?: RequestContext,
    ): Promise<IdentityAccount> {
      const id = assertUuid(accountId, "account-not-found");
      const displayName =
        changes.displayName === undefined
          ? null
          : normalizeDisplayName(changes.displayName);
      const email =
        changes.email === undefined ? null : normalizeEmail(changes.email);
      if (displayName === null && email === null) {
        return loadAccount(id);
      }

      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($5::timestamptz, now()) AS at),
              updated AS (
                UPDATE ${p}_accounts
                   SET display_name = COALESCE($3::text, display_name),
                       email = COALESCE($4::text, email),
                       email_verified_at = CASE
                         WHEN $4::text IS NOT NULL AND $4::text IS DISTINCT FROM email
                         THEN NULL
                         ELSE email_verified_at
                       END,
                       updated_at = (SELECT at FROM clock)
                 WHERE id = $1::uuid AND service_profile_id = $2::text
                 RETURNING id, service_profile_id, username_normalized, display_name,
                           email, email_verified_at, status, created_at, updated_at
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT updated.id, 'account.update', $6::jsonb, (SELECT at FROM clock)
                FROM updated
                RETURNING 1
              )
         SELECT id, service_profile_id, username_normalized, display_name, email,
                email_verified_at, status, created_at, updated_at
           FROM updated`,
        [
          id,
          serviceProfileId,
          displayName,
          email,
          requestNow(context),
          // Field names only. The values themselves (display name, address)
          // are user data and have no business in an audit trail.
          metadataJson({
            displayNameChanged: displayName !== null,
            emailChanged: email !== null,
          }),
        ],
      );
      return mapAccount(
        requireSingleRow(
          rows,
          () => new IdentityError("Account does not exist.", "account-not-found"),
        ),
        "",
      );
    },

    async listWallets(accountId: string): Promise<readonly IdentityWallet[]> {
      return listWalletsForAccount(accountId);
    },

    async startEmailVerification(
      input: EmailVerificationRequest,
      context?: RequestContext,
    ): Promise<IssuedEmailVerification> {
      const usernameNormalized = normalizeUsername(input.username);
      const email = normalizeEmail(input.email);
      await enforceRateLimit(
        requireRule("emailVerification"),
        [usernameNormalized, email],
        context,
      );

      // The id is minted client-side so the code hash can bind to it before
      // the row exists.
      const verificationId = globalThis.crypto.randomUUID();
      const code = generateVerificationCode();
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($7::timestamptz, now()) AS at),
              superseded AS (
                UPDATE ${p}_email_verifications
                   SET expires_at = (SELECT at FROM clock)
                 WHERE service_profile_id = $2::text
                   AND username_normalized = $3::text
                   AND consumed_at IS NULL
                   AND expires_at > (SELECT at FROM clock)
                 RETURNING 1
              ),
              issued AS (
                INSERT INTO ${p}_email_verifications (
                  id, service_profile_id, username_normalized, email, code_hash,
                  expires_at, created_at
                )
                SELECT $1::uuid, $2::text, $3::text, $4::text, $5::text,
                       date_trunc('milliseconds', clock.at + (interval '1 second' * $6::double precision)),
                       clock.at
                FROM clock
                RETURNING id, email, expires_at
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT (
                         SELECT id FROM ${p}_accounts
                          WHERE service_profile_id = $2::text
                            AND username_normalized = $3::text
                       ),
                       'email.verification-start', $8::jsonb, clock.at
                FROM clock
                RETURNING 1
              )
         SELECT id, email, expires_at FROM issued`,
        [
          verificationId,
          serviceProfileId,
          usernameNormalized,
          email,
          hashVerificationCode(serviceProfileId, verificationId, code),
          resolved.emailVerificationTtlSeconds,
          requestNow(context),
          metadataJson({ emailDomain: email.slice(email.lastIndexOf("@") + 1) }),
        ],
      );
      const row = requireSingleRow(
        rows,
        () =>
          new IdentityError(
            "Email verification could not be issued.",
            "email-verification-failed",
          ),
      );
      return Object.freeze({
        verificationId: textColumn(row, "id"),
        code,
        email: textColumn(row, "email"),
        expiresAt: instantColumn(row, "expires_at"),
      });
    },

    async confirmEmailVerification(
      verificationId: string,
      code: string,
      context?: RequestContext,
    ): Promise<{ email: string; usernameNormalized: string; verifiedAt: Date }> {
      const id = assertUuid(verificationId, "email-verification-failed");
      const submitted =
        typeof code === "string"
          ? code.toUpperCase().replace(nonAlphanumeric, "")
          : "";
      const nowParam = requestNow(context);

      // The attempt counter increments in the same statement that reads the
      // row, so a burst of parallel guesses cannot share one attempt.
      const attemptRows = await sql.query(
        `UPDATE ${p}_email_verifications
            SET attempts = attempts + 1
          WHERE id = $1::uuid
            AND service_profile_id = $2::text
            AND consumed_at IS NULL
            AND expires_at > COALESCE($4::timestamptz, now())
            AND attempts < $3::integer
          RETURNING id, username_normalized, email, code_hash, attempts`,
        [id, serviceProfileId, resolved.emailVerificationMaxAttempts, nowParam],
      );
      const attempt = optionalRow(attemptRows);
      if (attempt === null) {
        const existing = await sql.query(
          `SELECT consumed_at, attempts,
                  expires_at <= COALESCE($3::timestamptz, now()) AS is_expired
             FROM ${p}_email_verifications
            WHERE id = $1::uuid AND service_profile_id = $2::text`,
          [id, serviceProfileId, nowParam],
        );
        const row = optionalRow(existing);
        if (row !== null && booleanColumn(row, "is_expired")) {
          throw new IdentityError(
            "Verification code has expired.",
            "email-verification-expired",
          );
        }
        throw new IdentityError(
          "Verification code is not valid.",
          "email-verification-failed",
        );
      }

      const expected = textColumn(attempt, "code_hash");
      const provided = hashVerificationCode(serviceProfileId, id, submitted);
      if (!constantTimeEqualHex(expected, provided)) {
        throw new IdentityError(
          "Verification code is not valid.",
          "email-verification-failed",
        );
      }

      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($3::timestamptz, now()) AS at),
              consumed AS (
                UPDATE ${p}_email_verifications
                   SET consumed_at = (SELECT at FROM clock)
                 WHERE id = $1::uuid
                   AND service_profile_id = $2::text
                   AND consumed_at IS NULL
                   AND expires_at > (SELECT at FROM clock)
                 RETURNING id, username_normalized, email, consumed_at
              ),
              acct AS (
                UPDATE ${p}_accounts
                   SET email_verified_at = (SELECT consumed_at FROM consumed),
                       updated_at = (SELECT consumed_at FROM consumed)
                 WHERE service_profile_id = $2::text
                   AND username_normalized = (SELECT username_normalized FROM consumed)
                   AND email = (SELECT email FROM consumed)
                 RETURNING id
              ),
              logged AS (
                INSERT INTO ${p}_audit_events (account_id, action, metadata, created_at)
                SELECT (SELECT id FROM acct), 'email.verified', $4::jsonb, consumed.consumed_at
                FROM consumed
                RETURNING 1
              )
         SELECT username_normalized, email, consumed_at FROM consumed`,
        [
          id,
          serviceProfileId,
          nowParam,
          metadataJson({ accountStamped: true }),
        ],
      );
      const row = requireSingleRow(
        rows,
        () =>
          new IdentityError(
            "Verification code is not valid.",
            "email-verification-failed",
          ),
      );
      return Object.freeze({
        email: textColumn(row, "email"),
        usernameNormalized: textColumn(row, "username_normalized"),
        verifiedAt: instantColumn(row, "consumed_at"),
      });
    },

    async pruneExpired(context?: RequestContext): Promise<{
      challenges: number;
      sessions: number;
      emailVerifications: number;
      rateLimits: number;
    }> {
      const rows = await sql.query(
        `WITH clock AS (SELECT COALESCE($1::timestamptz, now()) AS at),
              expired_challenges AS (
                DELETE FROM ${p}_auth_challenges
                 WHERE service_profile_id = $2::text
                   AND expires_at <= (SELECT at FROM clock)
                 RETURNING 1
              ),
              dead_sessions AS (
                DELETE FROM ${p}_sessions
                 WHERE (expires_at <= (SELECT at FROM clock) OR revoked_at IS NOT NULL)
                   AND account_id IN (
                     SELECT id FROM ${p}_accounts WHERE service_profile_id = $2::text
                   )
                 RETURNING 1
              ),
              expired_verifications AS (
                DELETE FROM ${p}_email_verifications
                 WHERE service_profile_id = $2::text
                   AND expires_at <= (SELECT at FROM clock)
                 RETURNING 1
              ),
              stale_rate_limits AS (
                DELETE FROM ${p}_rate_limits
                 WHERE updated_at <= (SELECT at FROM clock) - (interval '1 second' * $3::double precision)
                 RETURNING 1
              )
         SELECT (SELECT count(*) FROM expired_challenges)::int AS challenges,
                (SELECT count(*) FROM dead_sessions)::int AS sessions,
                (SELECT count(*) FROM expired_verifications)::int AS email_verifications,
                (SELECT count(*) FROM stale_rate_limits)::int AS rate_limits`,
        [requestNow(context), serviceProfileId, RATE_LIMIT_RETENTION_SECONDS],
      );
      const row = requireSingleRow(
        rows,
        () => new IdentityError("Prune did not report counts.", "invalid-request"),
      );
      return {
        challenges: integerColumn(row, "challenges"),
        sessions: integerColumn(row, "sessions"),
        emailVerifications: integerColumn(row, "email_verifications"),
        rateLimits: integerColumn(row, "rate_limits"),
      };
    },
  });
}
