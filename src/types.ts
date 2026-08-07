/**
 * Every profile in this package derives an Ed25519 wallet. The two differ only
 * in where the scrypt salt comes from:
 *
 * - `web2ish-zera-ed25519-v1` derives its salt from the normalized username, so
 *   it needs no server. Identical credentials always yield the same wallet.
 * - `web2ish-zera-ed25519-external-salt-v1` takes a 32-byte salt the service
 *   owns and publishes, so each service gets a distinct wallet namespace.
 */
export type ZeraEd25519ProfileId =
  | "web2ish-zera-ed25519-v1"
  | "web2ish-zera-ed25519-external-salt-v1";

export type BuiltInProfileId = ZeraEd25519ProfileId;

export type DerivationContext = Readonly<{
  applicationId: string;
  networkId: string;
}>;

type SharedDerivationCredentials = Readonly<{
  username: string;
  password: Uint8Array;
  signal?: AbortSignal;
  onProgress?: (progress: number) => void;
}>;

export type ZeraEd25519Credentials = SharedDerivationCredentials &
  Readonly<{
    profile: "web2ish-zera-ed25519-v1";
    context: DerivationContext;
    salt?: never;
  }>;

export type ZeraEd25519ExternalSaltCredentials = SharedDerivationCredentials &
  Readonly<{
    profile: "web2ish-zera-ed25519-external-salt-v1";
    context: DerivationContext;
    salt: Uint8Array;
  }>;

export type DerivationCredentials =
  | ZeraEd25519Credentials
  | ZeraEd25519ExternalSaltCredentials;

export type Ed25519Identity = Readonly<{
  profileId: ZeraEd25519ProfileId;
  curve: "ed25519";
  normalizedUsername: string;
  address: string;
  publicKey: string;
  publicKeyBytes: Uint8Array;
  fingerprint: string;
}>;

export type DerivedPublicIdentity = Ed25519Identity;

export type Ed25519Wallet = Readonly<{
  identity: Ed25519Identity;
  signExactMessageUnsafe: (message: Uint8Array) => Uint8Array;
}>;

export type DerivedWallet = Ed25519Wallet;

export type ProfileDescription = Readonly<{
  id: BuiltInProfileId;
  curve: "ed25519";
  algorithm: string;
  saltPolicy: "external-32-v1" | "public-username-sha256-v1";
  N: number;
  r: number;
  p: number;
  dkLen: 32;
}>;
