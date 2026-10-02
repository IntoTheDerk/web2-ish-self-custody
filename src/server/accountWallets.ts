import type { AccountWalletSetup } from "../accountWallet.js";
import { fingerprint } from "../encoding.js";
import { parseWalletVault, type WalletVault } from "../vault.js";
import { buildWalletReplacementMessage, canonicalWalletIdentity, verifyChallengeSignature, type WalletIdentityInput } from "./challenge.js";
import { IdentityError } from "./errors.js";
import { integerColumn, optionalRow, requireSingleRow, textColumn, type SqlDriver, type SqlRow } from "./sql.js";
import { hashSessionToken } from "./tokens.js";
import type { ResolvedIdentityServiceConfig, StoredWalletVault, WalletReplacementInput } from "./types.js";

/** Internal persistence for the two opt-in modes. All multi-row writes are one statement. */
export function accountWalletOperations(sql: SqlDriver, config: ResolvedIdentityServiceConfig) {
  const p = config.tablePrefix; // Validated by service.ts before construction.
  const sid = config.serviceProfileId;
  const conflict = () => new IdentityError("Wallet changed; fetch the current state and retry.", "wallet-conflict");
  const requireVaultMode = () => {
    if (config.walletMode !== "random-vault") {
      throw new IdentityError("This service does not store wallet vaults.", "invalid-request");
    }
  };

  const checkPolicy = async (): Promise<void> => {
    const rows = await sql.query(`SELECT mode FROM ${p}_wallet_policy WHERE service_profile_id = $1`, [sid]);
    if (optionalRow(rows)?.["mode"] !== config.walletMode) {
      throw new IdentityError("Stored wallet mode differs from configuration; use a new service namespace.", "invalid-service-profile");
    }
  };

  const prepare = async (username: string): Promise<AccountWalletSetup | undefined> => {
    await checkPolicy();
    if (config.walletMode === "service-deterministic") return undefined;
    await sql.query(`INSERT INTO ${p}_wallet_setups (service_profile_id, username_normalized)
      SELECT $1, $2 WHERE NOT EXISTS (SELECT 1 FROM ${p}_accounts
        WHERE service_profile_id = $1 AND username_normalized = $2)
      ON CONFLICT DO NOTHING`, [sid, username]);
    // A second statement sees the winning insert even under concurrent enrollment.
    const row = requireSingleRow(await sql.query(`SELECT id, encode(public_salt, 'hex') AS salt
      FROM ${p}_wallet_setups WHERE service_profile_id = $1 AND username_normalized = $2`, [sid, username]), conflict);
    return Object.freeze({
      accountId: textColumn(row, "id"), mode: config.walletMode,
      profileId: config.profile.id, codecId: config.profile.codec.id,
      applicationId: config.applicationId, networkId: config.networkId,
      normalizedUsername: username, publicSaltHex: textColumn(row, "salt"),
    });
  };

  const validateVault = (value: unknown, username: string, wallet: WalletIdentityInput): WalletVault => {
    requireVaultMode();
    let vault: WalletVault;
    try { vault = parseWalletVault(value); } catch {
      throw new IdentityError("Invalid wallet vault.", "invalid-request");
    }
    if (vault.profileId !== config.profile.id || vault.codecId !== config.profile.codec.id ||
        vault.applicationId !== config.applicationId || vault.networkId !== config.networkId ||
        vault.normalizedUsername !== username || vault.address !== wallet.address || vault.publicKey !== wallet.publicKey ||
        vault.password.kdf.N !== config.profile.kdf.N || vault.password.kdf.r !== config.profile.kdf.r ||
        vault.password.kdf.p !== config.profile.kdf.p || vault.password.kdf.dkLen !== config.profile.kdf.dkLen ||
        [vault.seed, vault.password, vault.recovery].some((box) => box.ciphertextHex.length !== 96)) {
      throw new IdentityError("Vault does not match the enrolled identity and profile.", "wallet-mismatch");
    }
    return vault;
  };

  const getVault = async (accountId: string): Promise<StoredWalletVault> => {
    requireVaultMode();
    await checkPolicy();
    const row = requireSingleRow(await sql.query(`SELECT w.vault, w.vault_revision
      FROM ${p}_accounts a JOIN ${p}_account_wallets w ON w.account_id = a.id
      WHERE a.service_profile_id = $1 AND a.id = $2::uuid AND a.status = 'active'
        AND w.is_primary AND w.revoked_at IS NULL AND w.vault IS NOT NULL`, [sid, accountId]),
      () => new IdentityError("Wallet vault is unavailable.", "account-not-found"));
    return Object.freeze({ vault: parseWalletVault(row["vault"]), revision: integerColumn(row, "vault_revision") });
  };

  const updateVault = async (token: string, value: WalletVault, revision: number, now: string | null): Promise<StoredWalletVault> => {
    requireVaultMode();
    await checkPolicy();
    if (!Number.isSafeInteger(revision) || revision < 1 || revision >= 2_147_483_647) {
      throw new IdentityError("expectedRevision must be a positive revision number.", "invalid-request");
    }
    const vault = validateVault(value, value.normalizedUsername, value);
    const rows = await sql.query(`WITH updated AS (
      UPDATE ${p}_account_wallets w SET vault = $3::jsonb, vault_revision = vault_revision + 1
      FROM ${p}_accounts a, ${p}_sessions s
      WHERE w.account_id = a.id AND s.account_id = a.id AND s.token_hash = $1
        AND a.service_profile_id = $2 AND a.status = 'active'
        AND s.revoked_at IS NULL AND s.expires_at > COALESCE($5::timestamptz, now())
        AND s.wallet_generation = a.wallet_generation
        AND w.is_primary AND w.revoked_at IS NULL AND w.vault_revision = $4
        AND w.address = $6 AND w.public_key = $7 AND a.username_normalized = $8
      RETURNING w.account_id, w.vault_revision
    ), logged AS (
      INSERT INTO ${p}_audit_events (account_id, action, metadata)
      SELECT account_id, 'wallet.vault-update', jsonb_build_object('revision', vault_revision) FROM updated
    ) SELECT vault_revision FROM updated`,
    [hashSessionToken(token), sid, JSON.stringify(vault), revision, now, vault.address, vault.publicKey, vault.normalizedUsername]);
    const row = requireSingleRow(rows, conflict);
    return Object.freeze({ vault, revision: integerColumn(row, "vault_revision") });
  };

  const replace = async (
    input: Omit<WalletReplacementInput, "currentSignature"> & { currentSignature?: string },
    baseMessage: string,
    now: string | null,
    recoveryAccountId?: string,
  ): Promise<SqlRow> => {
    if (config.walletMode !== "per-account-deterministic") {
      throw new IdentityError("Wallet replacement requires per-account deterministic mode.", "invalid-request");
    }
    await checkPolicy();
    const target = canonicalWalletIdentity(config.profile.codec, input);
    const message = buildWalletReplacementMessage(baseMessage, target);
    const row = requireSingleRow(await sql.query(`SELECT a.id, a.wallet_generation,
      w.id AS wallet_id, w.address, w.public_key
      FROM ${p}_accounts a JOIN ${p}_account_wallets w ON w.account_id = a.id
      WHERE a.service_profile_id = $1 AND a.username_normalized = $2 AND a.status = 'active'
        AND w.is_primary AND w.revoked_at IS NULL`, [sid, input.username]),
      () => new IdentityError("Wallet proof failed.", "invalid-signature"));
    const old = canonicalWalletIdentity(config.profile.codec, { address: textColumn(row, "address"), publicKey: textColumn(row, "public_key") });
    if (!verifyChallengeSignature(target, message, input.signature) ||
        (recoveryAccountId === undefined
          ? !verifyChallengeSignature(old, message, input.currentSignature ?? "")
          : textColumn(row, "id") !== recoveryAccountId)) {
      throw new IdentityError("Wallet proof failed.", "invalid-signature");
    }
    if (old.address === target.address) throw new IdentityError("Replacement must be a new wallet.", "invalid-request");
    let rows: SqlRow[];
    try {
      rows = await sql.query(`WITH changed AS (
        UPDATE ${p}_accounts SET wallet_generation = wallet_generation + 1,
          updated_at = COALESCE($4::timestamptz, now())
        WHERE id = $1::uuid AND service_profile_id = $2 AND wallet_generation = $3 AND status = 'active'
        RETURNING id
      ), retired AS (
        UPDATE ${p}_account_wallets SET is_primary = false, revoked_at = COALESCE($4::timestamptz, now())
        WHERE account_id IN (SELECT id FROM changed) AND revoked_at IS NULL RETURNING *
      ), enrolled AS (
        INSERT INTO ${p}_account_wallets (account_id, service_profile_id, profile_id, codec_id, curve,
          application_id, network_id, address, address_normalized, public_key, fingerprint, is_primary)
        SELECT account_id, service_profile_id, profile_id, codec_id, curve, application_id, network_id,
          $5, $6, $7, $8, true FROM retired WHERE id = $9::uuid RETURNING *
      ), revoked AS (
        UPDATE ${p}_sessions SET revoked_at = COALESCE($4::timestamptz, now())
        WHERE account_id IN (SELECT id FROM changed) AND revoked_at IS NULL
      ), logged AS (
        INSERT INTO ${p}_audit_events (account_id, action, metadata)
        SELECT account_id, $10, jsonb_build_object('oldWalletId', $9::text, 'newWalletId', id) FROM enrolled
      ) SELECT * FROM enrolled`,
      [textColumn(row, "id"), sid, integerColumn(row, "wallet_generation"), now,
        target.address, target.addressNormalized, target.publicKey, fingerprint(target.address),
        textColumn(row, "wallet_id"), recoveryAccountId === undefined ? "wallet.replace" : "wallet.recover"]);
    } catch (error) {
      if ((error as { code?: string }).code === "23505") {
        throw new IdentityError("That wallet has already been enrolled.", "wallet-registered");
      }
      throw error;
    }
    return requireSingleRow(rows, conflict);
  };

  return { checkPolicy, prepare, validateVault, getVault, updateVault, replace };
}
