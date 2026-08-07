import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { zeraEd25519ExternalSalt } from "../../src/chains/zera.js";
import { normalizeUsername, withDerivedWallet } from "../../src/index.js";
import type { DerivedWallet } from "../../src/index.js";
import { CHALLENGE_DOMAIN } from "../../src/server/challenge.js";
import type { IdentityService } from "../../src/server/contract.js";
import { IdentityError, enumerationSensitiveCodes } from "../../src/server/errors.js";
import {
  neonDriver,
  pgDriver,
  type NeonQueryable,
  type SqlDriver,
} from "../../src/server/sql.js";
import type { IdentityServiceConfig, IssuedSession } from "../../src/server/types.js";
import { createIdentityService } from "../../src/server/service.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };

/**
 * Real-PostgreSQL coverage. The default `npm test` must never need a database,
 * so the whole suite is gated on an explicit connection string.
 */
const connectionString = process.env["W2SC_TEST_DATABASE_URL"];

const encoder = new TextEncoder();
const profile = zeraEd25519ExternalSalt;
const profileId = profile.id;
const codecId = profile.codec.id;
const applicationId = "knight-armor";
const networkId = "zera-testnet";

const derivationTimeoutMs = 120_000;

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
      "to run the identity service integration suite.",
  );
}

function randomSuffix(): string {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise<void>((resolve) => {
    setTimeout(resolve, milliseconds);
  });
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

type WalletCredentials = Readonly<{ username: string; password: string }>;

function useWallet<T>(
  credentials: WalletCredentials,
  publicSaltHex: string,
  use: (wallet: DerivedWallet) => T,
): Promise<T> {
  return withDerivedWallet(
    {
      profile,
      username: credentials.username,
      password: encoder.encode(credentials.password),
      context: { applicationId, networkId },
      salt: hexToBytes(publicSaltHex),
    },
    (wallet) => use(wallet),
  );
}

type WalletFixture = Readonly<{ address: string; publicKey: string; fingerprint: string }>;

function deriveWallet(
  credentials: WalletCredentials,
  publicSaltHex: string,
): Promise<WalletFixture> {
  return useWallet(credentials, publicSaltHex, (wallet) =>
    Object.freeze({
      address: wallet.identity.address,
      publicKey: wallet.identity.publicKey,
      fingerprint: wallet.identity.fingerprint,
    }),
  );
}

function signChallenge(
  credentials: WalletCredentials,
  publicSaltHex: string,
  message: string,
): Promise<string> {
  return useWallet(credentials, publicSaltHex, (wallet) =>
    bytesToHex(wallet.signExactMessageUnsafe(encoder.encode(message))),
  );
}

type Harness = Readonly<{
  service: IdentityService;
  shortChallengeService: IdentityService;
  driver: SqlDriver;
  appliedVersions: readonly number[];
  publicSaltHex: string;
  credentialsA: WalletCredentials;
  credentialsB: WalletCredentials;
  walletA: WalletFixture;
  walletB: WalletFixture;
  registration: Readonly<{ accountId: string; walletId: string; session: IssuedSession }>;
}>;

const suffix = randomSuffix();
const tablePrefix = `w2sct${suffix}`;
const serviceProfileId = `w2sc-test-${suffix}`;

const baseConfig: IdentityServiceConfig = {
  serviceProfileId,
  profile,
  applicationId,
  networkId,
  tablePrefix,
  sessionTtlSeconds: 3_600,
  challengeTtlSeconds: 300,
};

let harness: Harness | undefined;

function h(): Harness {
  if (harness === undefined) {
    throw new Error("The identity service integration harness was not initialized.");
  }
  return harness;
}

describe.skipIf(driverHandle === null)("identity service over PostgreSQL", () => {
  beforeAll(async () => {
    if (driverHandle === null) {
      return;
    }
    const driver = driverHandle.driver;
    const service = createIdentityService(driver, baseConfig);
    expect(service.config.serviceProfileId).toBe(serviceProfileId);
    const appliedVersions = await service.migrate();
    const published = await service.derivationProfile();

    const credentialsA: WalletCredentials = {
      username: `alice-${suffix}@example.com`,
      password: `alice correct horse battery staple ${suffix}`,
    };
    const credentialsB: WalletCredentials = {
      username: `bob-${suffix}@example.com`,
      password: `bob correct horse battery staple ${suffix}`,
    };

    const [walletA, walletB] = await Promise.all([
      deriveWallet(credentialsA, published.publicSaltHex),
      deriveWallet(credentialsB, published.publicSaltHex),
    ]);

    const challenge = await service.createChallenge(credentialsA.username, "registration");
    const signature = await signChallenge(
      credentialsA,
      published.publicSaltHex,
      challenge.message,
    );
    const registered = await service.register({
      username: credentialsA.username,
      displayName: "Alice",
      address: walletA.address,
      publicKey: walletA.publicKey,
      challengeId: challenge.id,
      signature,
    });

    harness = Object.freeze({
      service,
      shortChallengeService: createIdentityService(driver, {
        ...baseConfig,
        challengeTtlSeconds: 1,
      }),
      driver,
      appliedVersions,
      publicSaltHex: published.publicSaltHex,
      credentialsA,
      credentialsB,
      walletA,
      walletB,
      registration: Object.freeze({
        accountId: registered.account.id,
        walletId: registered.wallet.id,
        session: registered.session,
      }),
    });

    expect(registered.account.usernameNormalized).toBe(
      normalizeUsername(credentialsA.username),
    );
    expect(registered.account.displayName).toBe("Alice");
    expect(registered.account.status).toBe("active");
    expect(registered.account.email).toBeNull();
    expect(registered.wallet.address).toBe(walletA.address);
    expect(registered.wallet.publicKey).toBe(walletA.publicKey);
    expect(registered.wallet.fingerprint).toBe(walletA.fingerprint);
    expect(registered.wallet.isPrimary).toBe(true);
    expect(registered.wallet.curve).toBe("ed25519");
    expect(registered.wallet.profileId).toBe(profileId);
    // The stored row records which encoding produced its address, so the
    // deployment stays able to resolve it if it ever adds a second chain.
    expect(registered.wallet.codecId).toBe(codecId);
    expect(registered.wallet.accountId).toBe(registered.account.id);
  }, derivationTimeoutMs);

  afterAll(async () => {
    if (driverHandle === null) {
      return;
    }
    // `tablePrefix` is generated here and matches the migration identifier
    // allowlist, so interpolating it into teardown DDL is safe.
    await driverHandle.driver.query(
      `DROP TABLE IF EXISTS
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

  it("applies every migration once and is safe to re-run", async () => {
    const { service, appliedVersions, driver } = h();
    // The service must reach PostgreSQL only through the portability seam.
    expect(["pg", "neon-http"]).toContain(driver.kind);
    expect([...appliedVersions]).toEqual([1, 2, 3]);
    expect(await service.migrate()).toEqual([]);
  }, 60_000);

  it("publishes a stable, non-zero public salt with the profile's KDF parameters", async () => {
    const { service, shortChallengeService, publicSaltHex } = h();
    const published = await service.derivationProfile();

    expect(published.serviceProfileId).toBe(serviceProfileId);
    expect(published.profileId).toBe(profileId);
    // Published so a client can confirm it will spell addresses the way the
    // server does before it enrolls anything.
    expect(published.codecId).toBe(codecId);
    expect(published.curve).toBe("ed25519");
    expect(published.algorithm).toBe("scrypt-sha512-ed25519-external-32-v1");
    expect(published.applicationId).toBe(applicationId);
    expect(published.networkId).toBe(networkId);
    expect(published.publicSaltHex).toMatch(/^[0-9a-f]{64}$/u);
    expect(published.publicSaltHex).not.toBe("00".repeat(32));
    expect(published.kdf).toEqual({ N: 65_536, r: 8, p: 1, dkLen: 32 });

    // The salt is a wallet namespace: republishing it must never change it.
    // A second service instance re-reads the row instead of its own cache, so
    // this proves the salt is persisted rather than re-minted per process.
    expect(published.publicSaltHex).toBe(publicSaltHex);
    expect((await shortChallengeService.derivationProfile()).publicSaltHex).toBe(
      publicSaltHex,
    );
  }, 60_000);

  it("issues single-use challenges in the canonical eight-line format", async () => {
    const { service, credentialsA } = h();
    const challenge = await service.createChallenge(credentialsA.username, "login");
    const lines = challenge.message.split("\n");

    expect(lines).toHaveLength(8);
    expect(lines[0]).toBe(CHALLENGE_DOMAIN);
    expect(lines[1]).toBe(serviceProfileId);
    expect(lines[2]).toBe(applicationId);
    expect(lines[3]).toBe(networkId);
    expect(lines[4]).toBe("login");
    expect(lines[5]).toBe(normalizeUsername(credentialsA.username));
    expect(lines[6]).toMatch(/^[0-9a-f]{64}$/u);
    expect(lines[7]).toBe(challenge.expiresAt.toISOString());

    expect(challenge.purpose).toBe("login");
    expect(challenge.usernameNormalized).toBe(
      normalizeUsername(credentialsA.username),
    );
    expect(challenge.expiresAt.getTime()).toBeGreaterThan(Date.now());

    // Nonces must not repeat, or two challenges could share a signature.
    const second = await service.createChallenge(credentialsA.username, "login");
    expect(second.id).not.toBe(challenge.id);
    expect(second.message).not.toBe(challenge.message);
  }, 60_000);

  it("issues a challenge for an unknown username so callers cannot enumerate accounts", async () => {
    const { service } = h();
    const challenge = await service.createChallenge(
      `ghost-${randomSuffix()}@example.com`,
      "login",
    );
    expect(challenge.message.split("\n")).toHaveLength(8);
    expect(challenge.id.length).toBeGreaterThan(0);
  }, 60_000);

  it("runs the full register, authenticate, login, revoke flow", async () => {
    const { service, credentialsA, publicSaltHex, walletA, registration } = h();

    const registerToken = registration.session.token;
    expect(registerToken).toMatch(/^[\x21-\x7e]{22,}$/u);

    const authenticated = await service.authenticate(registerToken);
    expect(authenticated.account.id).toBe(registration.accountId);
    expect(authenticated.session.id).toBe(registration.session.session.id);
    expect(authenticated.wallets.map((wallet) => wallet.address)).toContain(walletA.address);
    expect(authenticated.wallets.map((wallet) => wallet.id)).toContain(registration.walletId);
    expect(authenticated.wallets.filter((wallet) => wallet.isPrimary)).toHaveLength(1);
    // Every wallet the service hands back carries its address encoding, so the
    // `codec_id` column is read back and not merely written.
    for (const wallet of authenticated.wallets) {
      expect(wallet.codecId).toBe(codecId);
      expect(wallet.profileId).toBe(profileId);
    }

    const challenge = await service.createChallenge(credentialsA.username, "login");
    const signature = await signChallenge(credentialsA, publicSaltHex, challenge.message);
    const loggedIn = await service.login({
      username: credentialsA.username,
      challengeId: challenge.id,
      signature,
    });

    expect(loggedIn.account.id).toBe(registration.accountId);
    expect(loggedIn.session.token).not.toBe(registerToken);
    expect(loggedIn.session.session.id).not.toBe(registration.session.session.id);
    expect(loggedIn.session.session.expiresAt.getTime()).toBeGreaterThan(Date.now());

    const reauthenticated = await service.authenticate(loggedIn.session.token);
    expect(reauthenticated.account.id).toBe(registration.accountId);

    await service.revokeSession(loggedIn.session.token);
    const revoked = await captureIdentityError(() =>
      service.authenticate(loggedIn.session.token),
    );
    expect(["session-not-found", "session-expired"]).toContain(revoked.code);
    expect(revoked.status).toBe(401);

    // Revoking one session must not disturb the others.
    expect((await service.authenticate(registerToken)).account.id).toBe(
      registration.accountId,
    );
  }, derivationTimeoutMs);

  it("rejects a replayed challenge", async () => {
    const { service, credentialsA, publicSaltHex } = h();
    const challenge = await service.createChallenge(credentialsA.username, "login");
    const signature = await signChallenge(credentialsA, publicSaltHex, challenge.message);

    await service.login({
      username: credentialsA.username,
      challengeId: challenge.id,
      signature,
    });

    const replay = await captureIdentityError(() =>
      service.login({
        username: credentialsA.username,
        challengeId: challenge.id,
        signature,
      }),
    );
    expect(replay.code).toBe("challenge-consumed");
  }, derivationTimeoutMs);

  it("rejects an expired challenge even with a valid signature", async () => {
    const { service, shortChallengeService, credentialsA, publicSaltHex } = h();
    const challenge = await shortChallengeService.createChallenge(
      credentialsA.username,
      "login",
    );
    expect(challenge.expiresAt.getTime() - Date.now()).toBeLessThan(5_000);

    const signature = await signChallenge(credentialsA, publicSaltHex, challenge.message);
    await sleep(1_500);

    const expired = await captureIdentityError(() =>
      service.login({
        username: credentialsA.username,
        challengeId: challenge.id,
        signature,
      }),
    );
    expect(expired.code).toBe("challenge-expired");
  }, derivationTimeoutMs);

  it("rejects a duplicate username", async () => {
    const { service, credentialsA, credentialsB, publicSaltHex, walletB } = h();
    const challenge = await service.createChallenge(credentialsA.username, "registration");
    const signature = await signChallenge(credentialsB, publicSaltHex, challenge.message);

    const duplicate = await captureIdentityError(() =>
      service.register({
        username: credentialsA.username,
        address: walletB.address,
        publicKey: walletB.publicKey,
        challengeId: challenge.id,
        signature,
      }),
    );
    expect(duplicate.code).toBe("account-exists");
  }, derivationTimeoutMs);

  it("rejects a wallet address that is already enrolled", async () => {
    const { service, credentialsA, credentialsB, publicSaltHex, walletA } = h();
    const challenge = await service.createChallenge(credentialsB.username, "registration");
    // Signed by wallet A, because the submitted public key must be wallet A's.
    const signature = await signChallenge(credentialsA, publicSaltHex, challenge.message);

    const duplicate = await captureIdentityError(() =>
      service.register({
        username: credentialsB.username,
        address: walletA.address,
        publicKey: walletA.publicKey,
        challengeId: challenge.id,
        signature,
      }),
    );
    expect(duplicate.code).toBe("wallet-registered");
  }, derivationTimeoutMs);

  it("fails an unknown username exactly like a wrong signature", async () => {
    const { service, credentialsA, credentialsB, publicSaltHex } = h();

    const knownChallenge = await service.createChallenge(credentialsA.username, "login");
    const foreignSignature = await signChallenge(
      credentialsB,
      publicSaltHex,
      knownChallenge.message,
    );
    const wrongSignature = await captureIdentityError(() =>
      service.login({
        username: credentialsA.username,
        challengeId: knownChallenge.id,
        signature: foreignSignature,
      }),
    );

    const unknownUsername = `ghost-${randomSuffix()}@example.com`;
    const unknownChallenge = await service.createChallenge(unknownUsername, "login");
    const unknownSignature = await signChallenge(
      credentialsB,
      publicSaltHex,
      unknownChallenge.message,
    );
    const unknownAccount = await captureIdentityError(() =>
      service.login({
        username: unknownUsername,
        challengeId: unknownChallenge.id,
        signature: unknownSignature,
      }),
    );

    // Distinguishable failures here would turn login into an account oracle.
    expect(unknownAccount.code).toBe(wrongSignature.code);
    expect(unknownAccount.status).toBe(wrongSignature.status);
    expect(unknownAccount.message).toBe(wrongSignature.message);
    expect(enumerationSensitiveCodes.has(wrongSignature.code)).toBe(true);
  }, derivationTimeoutMs);
});
