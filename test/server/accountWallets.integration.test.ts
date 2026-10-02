import { bytesToHex } from "@noble/hashes/utils.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRandomAccountWallet, withAccountWallet, openWalletVaultWithPassword, rewrapWalletVaultPassword, type AccountWalletSetup } from "../../src/index.js";
import { kalvoraEd25519ExternalSalt as profile } from "../../src/chains/kalvora.js";
import { createIdentityService, createIdentityRouter, pgDriver, type IdentityService, type SqlDriver, type SqlRow, type SqlParameter, type ServiceWalletMode } from "../../src/server/index.js";

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

  it("binds replacement to the new key, revokes old sessions and keys, and preserves the account", async () => {
    const { setup, registered, identity } = await register("rotate-user");
    const next = await withAccountWallet(setup, profile, nextPassword, w => w.identity);
    const challenge = await deterministic.createWalletReplacementChallenge("rotate-user", next);
    const input = { username: "rotate-user", address: next.address, publicKey: next.publicKey, challengeId: challenge.id,
      signature: await sign(setup, challenge.message, nextPassword), currentSignature: await sign(setup, challenge.message) };
    // A different target cannot reuse either proof. Failure consumes that challenge.
    await expect(deterministic.replaceWallet({ ...input, address: identity.address, publicKey: identity.publicKey })).rejects.toMatchObject({ code: "invalid-signature" });
    const retry = await deterministic.createWalletReplacementChallenge("rotate-user", next);
    const rotated = await deterministic.replaceWallet({ ...input, challengeId: retry.id,
      signature: await sign(setup, retry.message, nextPassword), currentSignature: await sign(setup, retry.message) });
    expect(rotated.accountId).toBe(registered.account.id);
    expect((await deterministic.listWallets(registered.account.id)).map(w => w.address)).toEqual([next.address]);
    await expect(deterministic.authenticate(registered.session.token)).rejects.toMatchObject({ code: "session-not-found" });
    const oldLogin = await deterministic.createChallenge("rotate-user", "login");
    await expect(deterministic.login({ username: "rotate-user", challengeId: oldLogin.id, signature: await sign(setup, oldLogin.message) })).rejects.toMatchObject({ code: "invalid-signature" });
    const login = await deterministic.createChallenge("rotate-user", "login");
    const loggedIn = await deterministic.login({ username: "rotate-user", challengeId: login.id, signature: await sign(setup, login.message, nextPassword) });
    expect((await deterministic.authenticate(loggedIn.session.token)).account.id).toBe(registered.account.id);
    await expect(deterministic.replaceWallet({ ...input, challengeId: retry.id })).rejects.toMatchObject({ code: "challenge-consumed" });
  });

  it("allows platform-authorized recovery with new-key proof but never exposes it as a route", async () => {
    const { setup, registered } = await register("recover-user");
    const next = await withAccountWallet(setup, profile, nextPassword, w => w.identity);
    const challenge = await deterministic.createWalletReplacementChallenge("recover-user", next);
    const input = { accountId: registered.account.id, address: next.address, publicKey: next.publicKey,
      challengeId: challenge.id, signature: await sign(setup, challenge.message, nextPassword) };
    const router = createIdentityRouter(deterministic, { useCookies: false });
    const response = await router(new Request("https://example.test/identity/wallet-replacements/recovery", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(input),
    }));
    expect(response.status).toBe(404);
    expect((await deterministic.replaceWalletAfterRecovery(input)).accountId).toBe(registered.account.id);
  });

  it("requires current-wallet proof over HTTP and only permits one concurrent replacement", async () => {
    const { setup, registered } = await register("race-user");
    const next = await withAccountWallet(setup, profile, nextPassword, w => w.identity);
    const router = createIdentityRouter(deterministic, { useCookies: false });
    const post = (path: string, body: unknown) => router(new Request(`https://example.test/identity/${path}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
    }));
    const response = await post("wallet-replacement-challenges", { username: "race-user", address: next.address, publicKey: next.publicKey });
    expect(response.status).toBe(200);
    const challenge = await response.json() as { id: string; message: string };
    const base = { username: "race-user", address: next.address, publicKey: next.publicKey };
    expect((await post("wallet-replacements", { ...base, challengeId: challenge.id,
      signature: await sign(setup, challenge.message, nextPassword), currentSignature: "00".repeat(64),
    })).status).toBe(401);
    const challenges = await Promise.all([deterministic.createWalletReplacementChallenge("race-user", next), deterministic.createWalletReplacementChallenge("race-user", next)]);
    const inputs = await Promise.all(challenges.map(async c => ({ ...base, challengeId: c.id,
      signature: await sign(setup, c.message, nextPassword), currentSignature: await sign(setup, c.message),
    })));
    const outcomes = await Promise.all(inputs.map(input => post("wallet-replacements", input)));
    expect(outcomes.filter(r => r.status === 200)).toHaveLength(1);
    expect(outcomes.filter(r => r.status === 409 || r.status === 401)).toHaveLength(1);
    expect((await deterministic.listWallets(registered.account.id)).map(w => w.address)).toEqual([next.address]);
  }, 20_000);

  it("does not issue a usable old-key session when login overlaps replacement", async () => {
    const { setup } = await register("overlap-user");
    let entered!: () => void;
    let release!: () => void;
    const atInsert = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    const delayed: SqlDriver = {
      kind: sql.kind,
      async query<T extends SqlRow>(text: string, params?: readonly SqlParameter[]): Promise<T[]> {
        if (params?.includes("account.login")) { entered(); await gate; }
        return sql.query<T>(text, params);
      },
    };
    const service = createIdentityService(delayed, config(prefixes[0]!, "per-account-deterministic"));
    const login = await deterministic.createChallenge("overlap-user", "login");
    const pending = service.login({ username: "overlap-user", challengeId: login.id, signature: await sign(setup, login.message) })
      .then(result => ({ result }), error => ({ error }));
    try {
      await atInsert;
      const next = await withAccountWallet(setup, profile, nextPassword, w => w.identity);
      const c = await deterministic.createWalletReplacementChallenge("overlap-user", next);
      await deterministic.replaceWallet({ username: "overlap-user", address: next.address, publicKey: next.publicKey,
        challengeId: c.id, signature: await sign(setup, c.message, nextPassword), currentSignature: await sign(setup, c.message),
      });
    } finally { release(); }
    expect(await pending).toMatchObject({ error: { code: "account-not-found" } });
  }, 20_000);

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
