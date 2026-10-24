import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { withKalvoraWalletFromMasterSeed } from "../../src/chains/kalvora.js";
import { signInEd25519ExternalSalt, withDerivedWallet } from "../../src/index.js";
import type { IdentityService } from "../../src/server/contract.js";
import { IdentityError } from "../../src/server/errors.js";
import { createIdentityService } from "../../src/server/service.js";
import { neonDriver, pgDriver, type NeonQueryable, type SqlDriver } from "../../src/server/sql.js";
import type { IdentityChallenge } from "../../src/server/types.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * The identity service over real PostgreSQL with the sign-in profile: the
 * pattern of docs/INTEGRATION.md, where the service enrolls a sign-in key and
 * the application's Kalvora wallet is an application secret of the same
 * password entry. Gated on W2SC_TEST_DATABASE_URL like the other server suites.
 */
const connectionString = process.env["W2SC_TEST_DATABASE_URL"];

const encoder = new TextEncoder();
const profile = signInEd25519ExternalSalt;
const applicationId = "example-app";
const networkId = "kalvora-mainnet";
const WALLET_SEED_LABEL = "example-wallet-seed-v1";
const signInIdentifier = /^S_[0-9a-f]{64}$/u;
const derivationTimeoutMs = 120_000;

type PgLikeClient = Readonly<{
  query: (text: string, params?: readonly unknown[]) => Promise<{ rows: Record<string, unknown>[] }>;
  connect?: () => Promise<unknown>;
  end?: () => Promise<unknown>;
}>;
type PgLikeConstructor = new (options: { connectionString: string }) => PgLikeClient;
type DriverHandle = Readonly<{ driver: SqlDriver; close: () => Promise<void> }>;

async function importOptional(specifier: string): Promise<Record<string, unknown> | null> {
  try {
    return (await import(/* @vite-ignore */ specifier)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function namedExport(loaded: Record<string, unknown>, name: string): unknown {
  const direct = loaded[name];
  if (direct !== undefined) return direct;
  const fallback = loaded["default"];
  return typeof fallback === "object" && fallback !== null
    ? (fallback as Record<string, unknown>)[name]
    : undefined;
}

/** The same client discovery as service.integration.test.ts. */
async function openDriver(url: string): Promise<DriverHandle | null> {
  const specifiers = [process.env["W2SC_TEST_PG_MODULE"], "pg"].filter(
    (specifier): specifier is string => specifier !== undefined && specifier.length > 0,
  );
  for (const specifier of specifiers) {
    const pg = await importOptional(specifier);
    const clientCtor = pg === null ? undefined : namedExport(pg, "Client");
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
  const neon = neonPackage === null ? undefined : namedExport(neonPackage, "neon");
  if (typeof neon === "function") {
    return Object.freeze({
      driver: neonDriver((neon as (value: string) => NeonQueryable)(url)),
      close: async () => {},
    });
  }
  return null;
}

const driverHandle =
  connectionString === undefined || connectionString.length === 0
    ? null
    : await openDriver(connectionString);

if (connectionString !== undefined && connectionString.length > 0 && driverHandle === null) {
  console.warn(
    "W2SC_TEST_DATABASE_URL is set but no PostgreSQL client could be loaded; " +
      "the sign-in profile integration suite is skipped.",
  );
}

function randomSuffix(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

async function captureIdentityError(run: () => Promise<unknown>): Promise<IdentityError> {
  try {
    await run();
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityError);
    return error as IdentityError;
  }
  throw new Error("Expected the call to reject with an IdentityError.");
}

const suffix = randomSuffix();
const tablePrefix = `w2scs${suffix}`;
const serviceProfileId = `w2sc-sign-in-test-${suffix}`;
const username = `alice-${suffix}@example.com`;
const password = `alice correct horse battery staple ${suffix}`;

type Entry = Readonly<{
  signIn: Readonly<{ address: string; publicKey: string; fingerprint: string }>;
  wallet: Readonly<{ address: string; publicKey: string }>;
  /** Signatures over each challenge's message, by challenge id. */
  signInSignatures: ReadonlyMap<string, string>;
  walletSignatures: ReadonlyMap<string, string>;
}>;

/** One password entry: one scrypt run gives the sign-in key and the wallet. */
function passwordEntry(publicSaltHex: string, challenges: readonly IdentityChallenge[]): Promise<Entry> {
  return withDerivedWallet(
    {
      profile,
      username,
      password: encoder.encode(password),
      context: { applicationId, networkId },
      salt: hexToBytes(publicSaltHex),
    },
    (signIn, secrets) => {
      const wallet = withKalvoraWalletFromMasterSeed(secrets.get(WALLET_SEED_LABEL)!, (opened) => ({
        address: opened.identity.address,
        publicKey: opened.identity.publicKey,
        signatures: new Map(
          challenges.map((challenge) => [
            challenge.id,
            bytesToHex(opened.signExactMessageUnsafe(encoder.encode(challenge.message))),
          ]),
        ),
      }));
      return {
        signIn: {
          address: signIn.identity.address,
          publicKey: signIn.identity.publicKey,
          fingerprint: signIn.identity.fingerprint,
        },
        wallet: { address: wallet.address, publicKey: wallet.publicKey },
        signInSignatures: new Map(
          challenges.map((challenge) => [
            challenge.id,
            bytesToHex(signIn.signExactMessageUnsafe(encoder.encode(challenge.message))),
          ]),
        ),
        walletSignatures: wallet.signatures,
      };
    },
    { applicationSecrets: [WALLET_SEED_LABEL] },
  );
}

type Harness = Readonly<{
  service: IdentityService;
  driver: SqlDriver;
  appliedVersions: readonly number[];
  entry: Entry;
  registration: IdentityChallenge;
  login: IdentityChallenge;
  walletLogin: IdentityChallenge;
}>;

let harness: Harness | undefined;

function h(): Harness {
  if (harness === undefined) throw new Error("The sign-in integration harness was not initialized.");
  return harness;
}

describe.skipIf(driverHandle === null)("identity service over PostgreSQL with the sign-in profile", () => {
  beforeAll(async () => {
    if (driverHandle === null) return;
    const service = createIdentityService(driverHandle.driver, {
      serviceProfileId,
      profile,
      applicationId,
      networkId,
      tablePrefix,
      sessionTtlSeconds: 3_600,
      challengeTtlSeconds: 300,
    });
    const appliedVersions = await service.migrate();
    const published = await service.derivationProfile();
    // Challenges are issued for unknown usernames too, so every signature this
    // suite needs comes from one password entry.
    const registration = await service.createChallenge(username, "registration");
    const login = await service.createChallenge(username, "login");
    const walletLogin = await service.createChallenge(username, "login");
    const entry = await passwordEntry(published.publicSaltHex, [registration, login, walletLogin]);
    harness = Object.freeze({
      service,
      driver: driverHandle.driver,
      appliedVersions,
      entry,
      registration,
      login,
      walletLogin,
    });
  }, derivationTimeoutMs);

  afterAll(async () => {
    if (driverHandle === null) return;
    // `tablePrefix` is generated above and matches the migration allowlist.
    await driverHandle.driver.query(
      `DROP TABLE IF EXISTS
         ${tablePrefix}_account_resets,
         ${tablePrefix}_account_recoveries,
         ${tablePrefix}_account_recovery_keys,
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
  }, 60_000);

  it("migrates and publishes the sign-in profile", async () => {
    const { service, appliedVersions } = h();
    expect([...appliedVersions]).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
    const published = await service.derivationProfile();
    expect(published).toMatchObject({
      walletMode: "service-deterministic",
      serviceProfileId,
      profileId: "web2ish-sign-in-ed25519-external-salt-v1",
      codecId: "web2ish-sign-in-ed25519-hex-v1",
      algorithm: "scrypt-sha512-hkdf-sha256-ed25519-external-32-v1",
      curve: "ed25519",
      applicationId,
      networkId,
      kdf: { N: 65_536, r: 8, p: 1, dkLen: 32 },
    });
    expect(published.publicSaltHex).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("refuses the Kalvora wallet's key at registration, then registers the sign-in key", async () => {
    const { service, entry, registration } = h();
    expect(entry.wallet.publicKey.startsWith("A_")).toBe(true);
    const refused = await captureIdentityError(() =>
      service.register({
        username,
        address: entry.wallet.address,
        publicKey: entry.wallet.publicKey,
        challengeId: registration.id,
        signature: entry.walletSignatures.get(registration.id)!,
      }),
    );
    expect(refused.code).toBe("invalid-public-key");

    const registered = await service.register({
      username,
      address: entry.signIn.address,
      publicKey: entry.signIn.publicKey,
      challengeId: registration.id,
      signature: entry.signInSignatures.get(registration.id)!,
    });
    expect(registered.wallet).toMatchObject({
      serviceProfileId,
      profileId: "web2ish-sign-in-ed25519-external-salt-v1",
      codecId: "web2ish-sign-in-ed25519-hex-v1",
      curve: "ed25519",
      address: entry.signIn.address,
      addressNormalized: entry.signIn.address.toLowerCase(),
      publicKey: entry.signIn.publicKey,
      fingerprint: entry.signIn.fingerprint,
      isPrimary: true,
    });
    expect(registered.wallet.publicKey).toMatch(signInIdentifier);
  }, 60_000);

  it("logs in with the sign-in key and refuses the wallet's signature", async () => {
    const { service, entry, login, walletLogin } = h();
    const session = await service.login({
      username,
      challengeId: login.id,
      signature: entry.signInSignatures.get(login.id)!,
    });
    const authenticated = await service.authenticate(session.session.token);
    expect(authenticated.wallets.map((wallet) => wallet.publicKey)).toEqual([entry.signIn.publicKey]);

    const refused = await captureIdentityError(() =>
      service.login({
        username,
        challengeId: walletLogin.id,
        signature: entry.walletSignatures.get(walletLogin.id)!,
      }),
    );
    expect(refused.code).toBe("invalid-signature");
  }, 60_000);

  it("stores only the sign-in key: nothing in its rows is the wallet's", async () => {
    const { driver, entry } = h();
    const rows = await driver.query<Record<string, unknown>>(
      `SELECT address, public_key, codec_id, profile_id FROM ${tablePrefix}_account_wallets`,
    );
    expect(rows).toEqual([
      {
        address: entry.signIn.address,
        public_key: entry.signIn.publicKey,
        codec_id: "web2ish-sign-in-ed25519-hex-v1",
        profile_id: "web2ish-sign-in-ed25519-external-salt-v1",
      },
    ]);
    const audit = await driver.query<{ metadata: unknown }>(
      `SELECT metadata FROM ${tablePrefix}_audit_events`,
    );
    const stored = JSON.stringify(rows) + JSON.stringify(audit);
    expect(stored).not.toContain(entry.wallet.address);
    expect(stored).not.toContain(entry.wallet.address.slice(0, 16));
    expect(stored).not.toContain(entry.wallet.publicKey);
  });
});
