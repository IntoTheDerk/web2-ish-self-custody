import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { signInEd25519ExternalSalt } from "../../src/index.js";
import { IdentityError, type IdentityErrorCode } from "../../src/server/errors.js";
import {
  createIdentityService,
  formatVerificationCode,
  pgDriver,
  type EmailVerificationCodeFormat,
  type IdentityService,
  type IdentityServiceConfig,
  type RequestContext,
  type SqlRow,
} from "../../src/server/index.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * Email verification codes over real PostgreSQL: the `digits6` format, the
 * normalization confirm applies to each format, and the per-username daily
 * wrong-code budget (`email-verification-account-failures`, 20 per 24 hours)
 * that applies to both. Gated on W2SC_TEST_DATABASE_URL like the other
 * server suites.
 */
const url = process.env["W2SC_TEST_DATABASE_URL"];

type Client = {
  connect(): Promise<void>;
  end(): Promise<void>;
  query(text: string, parameters?: readonly unknown[]): Promise<{ rows: SqlRow[] }>;
};

const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
const prefix = `wev_${suffix}`;
const serviceProfileId = `w2sc-codes-${suffix}`;
const tables = [
  "second_factor_tickets", "account_resets", "account_recoveries", "account_recovery_keys", "wallet_setups",
  "wallet_policy", "audit_events", "rate_limits", "email_verifications", "sessions", "auth_challenges",
  "account_wallets", "accounts", "service_profile_bootstrap", "service_profiles", "schema_migrations",
];

const config = (overrides: Partial<IdentityServiceConfig> = {}): IdentityServiceConfig => ({
  serviceProfileId,
  profile: signInEd25519ExternalSalt,
  applicationId: "example-app",
  networkId: "kalvora-testnet",
  tablePrefix: prefix,
  ...overrides,
});

let ipCounter = 0;
function ctx(extra: Omit<RequestContext, "ipHash"> = {}): RequestContext {
  ipCounter += 1;
  return { ipHash: `ip-${suffix}-${String(ipCounter)}`, ...extra };
}

function username(label: string): string {
  return `${label}-${crypto.randomUUID().slice(0, 8)}@example.com`;
}

function mailbox(label: string): string {
  return `${label}-${crypto.randomUUID().slice(0, 8)}@example.org`;
}

async function captureError(run: () => Promise<unknown>): Promise<IdentityError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    return error as IdentityError;
  }
  throw new Error("Expected an IdentityError.");
}

async function expectCode(run: () => Promise<unknown>, code: IdentityErrorCode): Promise<IdentityError> {
  const error = await captureError(run);
  expect(error.code).toBe(code);
  return error;
}

/** A code of the same format that is certainly not `code`. */
function wrongCode(code: string, format: EmailVerificationCodeFormat): string {
  if (format === "digits6") {
    return code === "000000" ? "000001" : "000000";
  }
  return code === "AAAAAAAA" ? "BBBBBBBB" : "AAAAAAAA";
}

let first: Client;
/** Real concurrency for the burst: one client would serialize it. */
let pool: Client & { query: Client["query"] };
let symbols: IdentityService;
let digits: IdentityService;

/** `enforceRateLimit`'s bucket for a budget, as the service computes it. */
function budgetBucket(ruleId: string, subject: string): string {
  return bytesToHex(
    sha256(
      new TextEncoder().encode(
        ["web2-ish-self-custody rate limit bucket v1", serviceProfileId, ruleId, subject].join("\n"),
      ),
    ),
  );
}

async function bucketCount(ruleId: string, subject: string): Promise<number | null> {
  const row = (
    await first.query(`SELECT count FROM ${prefix}_rate_limits WHERE bucket = $1::text`, [
      budgetBucket(ruleId, subject),
    ])
  ).rows[0];
  return row === undefined ? null : Number(row["count"]);
}

const budgetCount = (usernameNormalized: string): Promise<number | null> =>
  bucketCount("email-verification-account-failures", usernameNormalized);
const recipientBudgetCount = (email: string): Promise<number | null> =>
  bucketCount("email-verification-recipient-failures", email);

describe.skipIf(!url)("email verification codes on PostgreSQL", () => {
  beforeAll(async () => {
    const moduleName: string = "pg";
    const pg = (await import(moduleName)) as {
      Client: new (options: { connectionString: string }) => Client;
      Pool: new (options: { connectionString: string; max: number }) => Client;
    };
    first = new pg.Client({ connectionString: url! });
    pool = new pg.Pool({ connectionString: url!, max: 10 });
    await first.connect();
    symbols = createIdentityService(pgDriver(first), config());
    digits = createIdentityService(pgDriver(first), config({ emailVerificationCodeFormat: "digits6" }));
    await symbols.migrate();
  }, 60_000);

  afterAll(async () => {
    if (!first) return;
    await first.query(`DROP TABLE IF EXISTS ${tables.map((t) => `${prefix}_${t}`).join(", ")} CASCADE`);
    await first.query(`DROP FUNCTION IF EXISTS ${prefix}_reject_immutable_mutation() CASCADE`);
    await first.query(`DROP FUNCTION IF EXISTS ${prefix}_delete_account CASCADE`);
    await first.end();
    await pool.end();
  }, 60_000);

  describe("digits6", () => {
    it("issues six digits and confirms them typed plain, grouped or hyphenated", async () => {
      const name = username("digits");
      const email = mailbox("digits");
      for (const typed of [
        (code: string) => code,
        (code: string) => formatVerificationCode(code),
        (code: string) => `${code.slice(0, 3)}-${code.slice(3)}`,
        (code: string) => ` ${code.split("").join(" ")} `,
      ]) {
        const started = await digits.startEmailVerification({ username: name, email }, ctx());
        expect(started.code).toMatch(/^[0-9]{6}$/u);
        const confirmed = await digits.confirmEmailVerification(started.verificationId, typed(started.code), ctx());
        expect(confirmed.email).toBe(email);
        expect(confirmed.usernameNormalized).toBe(name);
      }
      // Each success gave its budget unit back.
      expect(await budgetCount(name)).toBe(0);
      expect(await recipientBudgetCount(email)).toBe(0);
    });

    it("refuses a wrong code, letters, and a code with a digit missing", async () => {
      const name = username("digits-wrong");
      const started = await digits.startEmailVerification({ username: name, email: mailbox("w") }, ctx());
      await expectCode(
        () => digits.confirmEmailVerification(started.verificationId, wrongCode(started.code, "digits6"), ctx()),
        "email-verification-failed",
      );
      await expectCode(
        () => digits.confirmEmailVerification(started.verificationId, "ABCDEF", ctx()),
        "email-verification-failed",
      );
      await expectCode(
        () => digits.confirmEmailVerification(started.verificationId, started.code.slice(1), ctx()),
        "email-verification-failed",
      );
      expect(await budgetCount(name)).toBe(3);
      // Still the right code works within the attempt bound.
      await digits.confirmEmailVerification(started.verificationId, started.code, ctx());
      expect(await budgetCount(name)).toBe(3);
    });

    it("keeps the per-verification attempt bound", async () => {
      const started = await digits.startEmailVerification({ username: username("attempts"), email: mailbox("a") }, ctx());
      for (let index = 0; index < 5; index += 1) {
        await expectCode(
          () => digits.confirmEmailVerification(started.verificationId, wrongCode(started.code, "digits6"), ctx()),
          "email-verification-failed",
        );
      }
      await expectCode(
        () => digits.confirmEmailVerification(started.verificationId, started.code, ctx()),
        "email-verification-failed",
      );
    });
  });

  describe("symbols8 (the default)", () => {
    it("issues eight symbols and confirms them in any case, with or without the hyphen", async () => {
      const name = username("symbols");
      const email = mailbox("symbols");
      for (const typed of [
        (code: string) => code,
        (code: string) => formatVerificationCode(code).toLowerCase(),
        (code: string) => `${code.slice(0, 4)} ${code.slice(4)}`,
      ]) {
        const started = await symbols.startEmailVerification({ username: name, email }, ctx());
        expect(started.code).toMatch(/^[A-HJ-NP-Z2-9]{8}$/u);
        await symbols.confirmEmailVerification(started.verificationId, typed(started.code), ctx());
      }
    });

    it("leaves a code issued in the other format unconfirmable", async () => {
      // Confirm normalizes to the configured format: switching formats strands
      // the codes already issued, which then expire.
      const name = username("switch");
      const started = await symbols.startEmailVerification({ username: name, email: mailbox("s") }, ctx());
      await expectCode(
        () => digits.confirmEmailVerification(started.verificationId, started.code, ctx()),
        "email-verification-failed",
      );
    });
  });

  describe.each(["symbols8", "digits6"] as const)("daily wrong-code budget (%s)", (format) => {
    // 25 attempts per verification, so a single verification can spend the
    // whole budget and the budget, not the attempt bound, is what refuses.
    const service = (): IdentityService =>
      createIdentityService(
        pgDriver(first),
        config({ emailVerificationCodeFormat: format, emailVerificationMaxAttempts: 25 }),
      );

    it("refuses confirmation, even of the right code, and new starts after 20 wrong codes", async () => {
      const s = service();
      const name = username(`budget-${format}`);
      const email = mailbox("budget");
      const started = await s.startEmailVerification({ username: name, email }, ctx());
      for (let index = 0; index < 20; index += 1) {
        await expectCode(
          () => s.confirmEmailVerification(started.verificationId, wrongCode(started.code, format), ctx()),
          "email-verification-failed",
        );
      }
      expect(await budgetCount(name)).toBe(20);

      const confirmRefused = await expectCode(
        () => s.confirmEmailVerification(started.verificationId, started.code, ctx()),
        "rate-limited",
      );
      expect(confirmRefused.details).toMatchObject({ rule: "email-verification-account-failures" });

      const startRefused = await expectCode(
        () => s.startEmailVerification({ username: name, email: mailbox("other") }, ctx()),
        "rate-limited",
      );
      expect(startRefused.details).toMatchObject({ rule: "email-verification-account-failures" });
      const retryAfter = (startRefused.details as { retryAfterSeconds: number }).retryAfterSeconds;
      expect(retryAfter).toBeGreaterThan(86_000);
      expect(retryAfter).toBeLessThanOrEqual(86_400);

      expect(await recipientBudgetCount(email)).toBe(20);
      // Another username at another address is unaffected.
      const other = await s.startEmailVerification(
        { username: username("bystander"), email: mailbox("bystander") },
        ctx(),
      );
      await s.confirmEmailVerification(other.verificationId, other.code, ctx());

      // Once the window has passed the username may start and confirm again.
      const later = { now: new Date(Date.now() + 86_401_000) };
      const fresh = await s.startEmailVerification({ username: name, email }, ctx(later));
      await s.confirmEmailVerification(fresh.verificationId, fresh.code, ctx(later));
    });

    it("counts wrong codes across verifications and gives back right ones", async () => {
      const s = service();
      const name = username(`across-${format}`);
      const email = mailbox("across");
      const first10 = await s.startEmailVerification({ username: name, email }, ctx());
      for (let index = 0; index < 10; index += 1) {
        await expectCode(
          () => s.confirmEmailVerification(first10.verificationId, wrongCode(first10.code, format), ctx()),
          "email-verification-failed",
        );
      }
      const next9 = await s.startEmailVerification({ username: name, email }, ctx());
      for (let index = 0; index < 9; index += 1) {
        await expectCode(
          () => s.confirmEmailVerification(next9.verificationId, wrongCode(next9.code, format), ctx()),
          "email-verification-failed",
        );
      }
      await s.confirmEmailVerification(next9.verificationId, next9.code, ctx());
      expect(await budgetCount(name)).toBe(19);

      // One more wrong code fills it; the start after it is refused.
      const last = await s.startEmailVerification({ username: name, email }, ctx());
      await expectCode(
        () => s.confirmEmailVerification(last.verificationId, wrongCode(last.code, format), ctx()),
        "email-verification-failed",
      );
      await expectCode(() => s.startEmailVerification({ username: name, email }, ctx()), "rate-limited");
    });

    it("bounds an address the same way however many usernames name it", async () => {
      const s = service();
      const email = mailbox(`rotate-${format}`);
      for (let round = 0; round < 4; round += 1) {
        const started = await s.startEmailVerification({ username: username("rotate"), email }, ctx());
        for (let index = 0; index < 5; index += 1) {
          await expectCode(
            () => s.confirmEmailVerification(started.verificationId, wrongCode(started.code, format), ctx()),
            "email-verification-failed",
          );
        }
      }
      expect(await recipientBudgetCount(email)).toBe(20);
      const refused = await expectCode(
        () => s.startEmailVerification({ username: username("rotate"), email }, ctx()),
        "rate-limited",
      );
      expect(refused.details).toMatchObject({ rule: "email-verification-recipient-failures" });
      // The same usernames at another address are not.
      await s.startEmailVerification({ username: username("rotate"), email: mailbox("elsewhere") }, ctx());
    });

    it("does not charge a username for a confirm its full address budget refused", async () => {
      const s = service();
      const email = mailbox(`victim-${format}`);
      const victim = username("victim");
      // The victim's code is issued before the address budget fills.
      const mine = await s.startEmailVerification({ username: victim, email }, ctx());
      for (let round = 0; round < 4; round += 1) {
        const started = await s.startEmailVerification({ username: username("filler"), email }, ctx());
        for (let index = 0; index < 5; index += 1) {
          await expectCode(
            () => s.confirmEmailVerification(started.verificationId, wrongCode(started.code, format), ctx()),
            "email-verification-failed",
          );
        }
      }
      expect(await recipientBudgetCount(email)).toBe(20);

      // More refusals than the username budget holds, all of the right code.
      for (let index = 0; index < 21; index += 1) {
        const refused = await expectCode(
          () => s.confirmEmailVerification(mine.verificationId, mine.code, ctx()),
          "rate-limited",
        );
        expect(refused.details).toMatchObject({ rule: "email-verification-recipient-failures" });
      }
      expect(await budgetCount(victim)).toBe(0);

      // The username can still verify another address.
      const elsewhere = await s.startEmailVerification({ username: victim, email: mailbox("elsewhere") }, ctx());
      await s.confirmEmailVerification(elsewhere.verificationId, elsewhere.code, ctx());
    });

    it("never lets more than 20 wrong codes through a concurrent burst", async () => {
      const s = createIdentityService(
        pgDriver(pool),
        config({ emailVerificationCodeFormat: format, emailVerificationMaxAttempts: 25 }),
      );
      const name = username(`burst-${format}`);
      const started = await s.startEmailVerification({ username: name, email: mailbox("burst") }, ctx());
      const outcomes = await Promise.all(
        Array.from({ length: 25 }, () =>
          captureError(() =>
            s.confirmEmailVerification(started.verificationId, wrongCode(started.code, format), ctx()),
          ),
        ),
      );
      const codes = outcomes.map((error) => error.code);
      expect(codes.filter((code) => code === "email-verification-failed")).toHaveLength(20);
      expect(codes.filter((code) => code === "rate-limited")).toHaveLength(5);
    });

    it("does not count an expired, unknown or exhausted verification", async () => {
      const s = service();
      const name = username(`dead-${format}`);
      const started = await s.startEmailVerification({ username: name, email: mailbox("dead") }, ctx());
      const after = { now: new Date(Date.now() + 3_600_000) };
      await expectCode(
        () => s.confirmEmailVerification(started.verificationId, wrongCode(started.code, format), ctx(after)),
        "email-verification-expired",
      );
      await expectCode(
        () => s.confirmEmailVerification(crypto.randomUUID(), wrongCode(started.code, format), ctx()),
        "email-verification-failed",
      );
      expect(await budgetCount(name)).toBeNull();
    });
  });
});
