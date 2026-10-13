import { bytesToHex } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRandomAccountWallet, withAccountWallet, openWalletVaultWithPassword, rewrapWalletVaultPassword, type AccountWalletSetup } from "../../src/index.js";
import { kalvoraEd25519ExternalSalt as profile } from "../../src/chains/kalvora.js";
import { createIdentityService, createIdentityRouter, pgDriver, type IdentityService, type SqlDriver, type SqlRow, type ServiceWalletMode } from "../../src/server/index.js";

declare const process: { readonly env: Readonly<Record<string, string | undefined>> };
const url = process.env["W2SC_TEST_DATABASE_URL"];
const encoder = new TextEncoder();
const password = encoder.encode("correct horse battery staple");
const nextPassword = encoder.encode("another strong account password");
const suffix = crypto.randomUUID().replaceAll("-", "").slice(0, 10);
const prefixes = [`wd_${suffix}`, `wv_${suffix}`, `wo_${suffix}`];
type Client = { connect(): Promise<void>; end(): Promise<void>; query(text: string, parameters?: readonly unknown[]): Promise<{ rows: SqlRow[] }> };
let client: Client;
let sql: SqlDriver;
let deterministic: IdentityService;
let vaultService: IdentityService;
let other: IdentityService;
const config = (tablePrefix: string, walletMode: ServiceWalletMode) => ({
  tablePrefix, walletMode, serviceProfileId: "example.identity", profile,
  applicationId: "example-app", networkId: "kalvora-testnet",
});
const sign = (setup: AccountWalletSetup, message: string, secret = password) =>
  withAccountWallet(setup, profile, secret, w => bytesToHex(w.signExactMessageUnsafe(encoder.encode(message))));

describe.skipIf(!url)("account wallet modes on PostgreSQL", () => {
  beforeAll(async () => {
    const moduleName: string = "pg";
    const pg = await import(moduleName) as { Client: new (options: { connectionString: string }) => Client };
    client = new pg.Client({ connectionString: url! });
    await client.connect();
    sql = pgDriver(client);
    deterministic = createIdentityService(sql, config(prefixes[0]!, "per-account-deterministic"));
    vaultService = createIdentityService(sql, config(prefixes[1]!, "random-vault"));
    other = createIdentityService(sql, config(prefixes[2]!, "per-account-deterministic"));
    for (const service of [deterministic, vaultService, other]) await service.migrate();
  }, 60_000);

  afterAll(async () => {
    if (!client) return;
    for (const prefix of prefixes) {
      const tables = ["wallet_setups", "wallet_policy", "audit_events", "rate_limits", "email_verifications", "sessions", "auth_challenges", "account_wallets", "accounts", "service_profile_bootstrap", "service_profiles", "schema_migrations"];
      await client.query(`DROP TABLE IF EXISTS ${tables.map(t => `${prefix}_${t}`).join(", ")} CASCADE`);
      await client.query(`DROP FUNCTION IF EXISTS ${prefix}_reject_immutable_mutation() CASCADE`);
    }
    await client.end();
  }, 60_000);

  async function register(username: string) {
    const challenge = await deterministic.createChallenge(username, "registration");
    const setup = challenge.walletSetup!;
    const identity = await withAccountWallet(setup, profile, password, w => w.identity);
    const registered = await deterministic.register({ username, address: identity.address, publicKey: identity.publicKey,
      challengeId: challenge.id, signature: await sign(setup, challenge.message) });
    return { setup, registered, identity };
  }

  it("persists one random salt before registration, even with concurrent requests", async () => {
    const [a, b] = await Promise.all([deterministic.createChallenge("same-user", "registration"), deterministic.createChallenge("same-user", "login")]);
    expect(a.walletSetup).toEqual(b.walletSetup);
    const c = await other.createChallenge("same-user", "registration");
    expect(c.walletSetup!.publicSaltHex).not.toBe(a.walletSetup!.publicSaltHex);
    expect(await withAccountWallet(a.walletSetup!, profile, password, w => w.identity.address))
      .not.toBe(await withAccountWallet(c.walletSetup!, profile, password, w => w.identity.address));
    const { setup, registered } = await register("alice");
    expect(registered.account.id).toBe(setup.accountId);
    expect((await deterministic.createChallenge("alice", "login")).walletSetup).toEqual(setup);
    await expect(client.query(`UPDATE ${prefixes[0]}_wallet_setups SET public_salt = gen_random_bytes(32)`)).rejects.toMatchObject({ code: "55000" });
    await expect(createIdentityService(sql, config(prefixes[0]!, "random-vault")).migrate()).rejects.toMatchObject({ code: "invalid-service-profile" });
  });

  it("does not reserve account metadata for registration without a valid challenge", async () => {
    const c = await deterministic.createChallenge("existing-setup", "registration");
    const identity = await withAccountWallet(c.walletSetup!, profile, password, w => w.identity);
    await expect(deterministic.register({ username: "unprovisioned-user", address: identity.address, publicKey: identity.publicKey,
      challengeId: crypto.randomUUID(), signature: "00".repeat(64),
    })).rejects.toMatchObject({ code: "challenge-not-found" });
    expect((await client.query(`SELECT id FROM ${prefixes[0]}_wallet_setups WHERE username_normalized = $1`, ["unprovisioned-user"])).rows).toEqual([]);
  });

  it("does not reassign a deterministic account when its password input changes", async () => {
    const { setup, registered, identity } = await register("unchanged-user");
    const next = await withAccountWallet(setup, profile, nextPassword, w => w.identity);
    expect(next.address).not.toBe(identity.address);
    const login = await deterministic.createChallenge("unchanged-user", "login");
    await expect(deterministic.login({ username: "unchanged-user", challengeId: login.id,
      signature: await sign(setup, login.message, nextPassword),
    })).rejects.toMatchObject({ code: "invalid-signature" });
    expect((await deterministic.listWallets(registered.account.id)).map(w => w.address)).toEqual([identity.address]);
    const originalLogin = await deterministic.createChallenge("unchanged-user", "login");
    expect((await deterministic.login({ username: "unchanged-user", challengeId: originalLogin.id,
      signature: await sign(setup, originalLogin.message),
    })).account.id).toBe(registered.account.id);

    const router = createIdentityRouter(deterministic, { useCookies: false });
    for (const path of ["wallet-replacement-challenges", "wallet-replacements", "wallet-replacements/recovery"]) {
      expect((await router(new Request(`https://example.test/identity/${path}`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
      }))).status).toBe(404);
    }
  });

  it("stores vaults, authorizes downloads, and updates the password without changing the signing identity", async () => {
    const challenge = await vaultService.createChallenge("vault-user", "registration");
    const { vault, recoveryCode } = await createRandomAccountWallet(challenge.walletSetup!, profile, password);
    const signature = await openWalletVaultWithPassword(vault, password, profile.codec, w => bytesToHex(w.signExactMessageUnsafe(encoder.encode(challenge.message))));
    const registered = await vaultService.register({ username: "vault-user", address: vault.address, publicKey: vault.publicKey, challengeId: challenge.id, signature, vault });
    const deniedRouter = createIdentityRouter(vaultService, { useCookies: false });
    const request = () => new Request("https://example.test/identity/wallet-vault", { method: "POST" });
    expect((await deniedRouter(request())).status).toBe(401);
    const router = createIdentityRouter(vaultService, { useCookies: false, authorizeVaultRead: async () => registered.account.id });
    const response = await router(request());
    expect(response.status).toBe(200);
    const downloaded = await response.json() as { vault: typeof vault; revision: number };
    expect(downloaded).toEqual({ vault, revision: 1 });
    const changed = await rewrapWalletVaultPassword(downloaded.vault, { recoveryCode }, nextPassword, recoveryCode);
    await expect(vaultService.updateWalletVault("bad-token", changed, 1)).rejects.toMatchObject({ code: "session-not-found" });
    await expect(vaultService.updateWalletVault(registered.session.token, { ...changed, address: "wrong" }, 1)).rejects.toMatchObject({ code: "wallet-conflict" });
    const saveResponse = await router(new Request("https://example.test/identity/wallet-vault", {
      method: "PUT", headers: { "Content-Type": "application/json", Authorization: `Bearer ${registered.session.token}` },
      body: JSON.stringify({ vault: changed, expectedRevision: 1 }),
    }));
    expect(saveResponse.status).toBe(200);
    const saved = await saveResponse.json() as { vault: typeof vault; revision: number };
    expect(saved.revision).toBe(2);
    expect(saved.vault.address).toBe(vault.address);
    await expect(vaultService.updateWalletVault(registered.session.token, vault, 1)).rejects.toMatchObject({ code: "wallet-conflict" });
    const login = await vaultService.createChallenge("vault-user", "login");
    const proof = await openWalletVaultWithPassword(saved.vault, nextPassword, profile.codec, w => bytesToHex(w.signExactMessageUnsafe(encoder.encode(login.message))));
    expect((await vaultService.login({ username: "vault-user", challengeId: login.id, signature: proof })).account.id).toBe(registered.account.id);
  });
});
