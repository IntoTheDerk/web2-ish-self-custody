import type { AccountWalletSetup } from "../accountWallet.js";
import { parseWalletVault, type WalletVault } from "../vault.js";
import type { WalletIdentityInput } from "./challenge.js";
import { IdentityError } from "./errors.js";
import { integerColumn, optionalRow, requireSingleRow, textColumn, type SqlDriver } from "./sql.js";
import { hashSessionToken } from "./tokens.js";
import type { ResolvedIdentityServiceConfig, StoredWalletVault } from "./types.js";

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
        AND w.is_primary AND w.vault IS NOT NULL`, [sid, accountId]),
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
        AND w.is_primary AND w.vault_revision = $4
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

  return { checkPolicy, prepare, validateVault, getVault, updateVault };
}
