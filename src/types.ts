export type BuiltInProfileId =
  | "democracyos-scrypt-sha512-secp256k1-v2"
  | "web2ish-zera-ed25519-v1";

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

export type DemocracyOsCredentials = SharedDerivationCredentials &
  Readonly<{
    profile: "democracyos-scrypt-sha512-secp256k1-v2";
    salt: Uint8Array;
    context?: never;
  }>;

export type ZeraEd25519Credentials = SharedDerivationCredentials &
  Readonly<{
    profile: "web2ish-zera-ed25519-v1";
    context: DerivationContext;
    salt?: never;
  }>;

export type DerivationCredentials =
  | DemocracyOsCredentials
  | ZeraEd25519Credentials;

export type Ed25519Identity = Readonly<{
  profileId: "web2ish-zera-ed25519-v1";
  curve: "ed25519";
  normalizedUsername: string;
  address: string;
  publicKey: string;
  publicKeyBytes: Uint8Array;
  fingerprint: string;
}>;

export type Secp256k1Identity = Readonly<{
  profileId: "democracyos-scrypt-sha512-secp256k1-v2";
  curve: "secp256k1";
  normalizedUsername: string;
  address: string;
  publicKey: string;
  publicKeyBytes: Uint8Array;
  fingerprint: string;
}>;

export type DerivedPublicIdentity = Ed25519Identity | Secp256k1Identity;

export type Ed25519Wallet = Readonly<{
  identity: Ed25519Identity;
  signExactMessageUnsafe: (message: Uint8Array) => Uint8Array;
}>;

export type Secp256k1Wallet = Readonly<{
  identity: Secp256k1Identity;
  signDemocracyOsChallengeDigest: (digest: Uint8Array) => Uint8Array;
}>;

export type DerivedWallet = Ed25519Wallet | Secp256k1Wallet;

export type ProfileDescription = Readonly<{
  id: BuiltInProfileId;
  curve: "ed25519" | "secp256k1";
  algorithm: string;
  saltPolicy: "external-32-v1" | "public-username-sha256-v1";
  N: number;
  r: number;
  p: number;
  dkLen: 32;
}>;
