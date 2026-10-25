/**
 * The public server surface.
 *
 * Importing this module pulls in no database driver: Neon and `pg` are always
 * injected by the host through the adapters below. That is what keeps one
 * deployment on Vercel and another on self-hosted PostgreSQL behaviorally
 * identical.
 */

export { createNeonIdentityService } from "./adapters/neon.js";
export type { NeonClientFactory, NeonIdentityServiceOptions } from "./adapters/neon.js";
export { createPgIdentityService, nodeRequestListener } from "./adapters/node.js";
export type {
  NodeHeaders,
  NodeRequestLike,
  NodeRequestListener,
  NodeRequestListenerOptions,
  NodeResponseLike,
  PgIdentityServiceOptions,
} from "./adapters/node.js";

export {
  CHALLENGE_DOMAIN,
  buildChallengeMessage,
  canonicalWalletIdentity,
  verifyChallengeSignature,
} from "./challenge.js";
export type {
  CanonicalWalletIdentity,
  ChallengeMessageInput,
  WalletIdentityInput,
} from "./challenge.js";

export { identityServiceDefaults, resolveIdentityServiceConfig } from "./config.js";

export type {
  IdentityService,
  LoginResult,
  ResetCompletionResult,
  SessionOrSecondFactor,
  SessionResult,
} from "./contract.js";

export {
  EmailDeliveryError,
  assertEmailVerificationDelivery,
  deliverEmailVerification,
  escapeHtml,
  formatVerificationCode,
  parseMailbox,
  renderVerificationEmail,
  resolveVerificationEmailTheme,
} from "./email.js";
export type {
  EmailDeliveryFailure,
  EmailDeliveryFailureReason,
  EmailDeliveryReceipt,
  EmailMessage,
  EmailSender,
  EmailVerificationDelivery,
  VerificationEmailContent,
  VerificationEmailInput,
  VerificationEmailTheme,
} from "./email.js";
export {
  createEmailSender,
  createPostmarkEmailSender,
  createResendEmailSender,
  createSendGridEmailSender,
  emailProviders,
} from "./emailProviders.js";
export type {
  EmailProviderConfig,
  EmailProviderName,
  PostmarkEmailSenderOptions,
  ResendEmailSenderOptions,
  SendGridEmailSenderOptions,
} from "./emailProviders.js";

export { IdentityError, enumerationSensitiveCodes, identityErrorStatus } from "./errors.js";
export type { IdentityErrorCode } from "./errors.js";

export { identityMigrations, runIdentityMigrations } from "./migrations.js";
export {
  platformSaltMigration,
  provisionPlatformSalt,
  readPlatformSalt,
} from "./serviceProfile.js";
export type { PlatformSaltConfig } from "./serviceProfile.js";
export type { IdentityMigration } from "./migrations.js";

export { createIdentityRouter, createSessionResponder, jsonResponse } from "./router.js";
export type { IdentityRouterOptions, SessionResponder } from "./router.js";

export { createIdentityService } from "./service.js";

export { neonDriver, pgDriver } from "./sql.js";
export type {
  NeonQueryable,
  PgQueryable,
  SqlDriver,
  SqlParameter,
  SqlRow,
} from "./sql.js";

export { challengePurposes } from "./types.js";
export type {
  AccountDeletion,
  AccountDeletionOptions,
  AccountResetCompletionInput,
  AccountResetDelivery,
  AccountResetSettingInput,
  AccountResetSettingName,
  AccountResetSettings,
  AccountResetStatus,
  AccountSecurityOptions,
  AuthenticatedIdentity,
  AuthenticatedRecovery,
  ChallengePurpose,
  EmailChangeInput,
  EmailVerificationCodeFormat,
  EmailVerificationRequest,
  EnrolledKeyInput,
  IdentityAccount,
  IdentityChallenge,
  IdentityRecoveryKey,
  IdentityServiceConfig,
  IdentitySession,
  IdentityWallet,
  IssuedAccountReset,
  IssuedEmailVerification,
  IssuedRecovery,
  IssuedSecondFactorTicket,
  IssuedSession,
  IssuedSignedInReset,
  ListedSession,
  LoginInput,
  PendingSignedInReset,
  PublishedDerivationProfile,
  ReauthenticationInput,
  RecoveryBeginInput,
  RecoveryCompletionInput,
  RecoveryKeyEnrollmentInput,
  RecoveryKeyRemovalInput,
  RecoveryStatus,
  RegistrationInput,
  RequestContext,
  ResolvedIdentityServiceConfig,
  SecondFactorCompletionInput,
  SecondFactorContext,
  SecondFactorIdentityServiceConfig,
  SecondFactorOptions,
  SecondFactorPurpose,
  SecondFactorVerdict,
  SecurityEvent,
  SecurityEventAction,
  SecurityEventHook,
  SecurityEventNotice,
  ServiceWalletMode,
  SignedInResetCompletionInput,
  SignInKeyRotationInput,
  StoredWalletVault,
  VerifiedReauthentication,
} from "./types.js";
