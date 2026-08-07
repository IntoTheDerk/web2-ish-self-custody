import { DerivationError } from "./errors.js";
import type { BuiltInProfileId, ProfileDescription } from "./types.js";

const profiles: Readonly<Record<BuiltInProfileId, ProfileDescription>> = Object.freeze({
  "web2ish-zera-ed25519-v1": Object.freeze({
    id: "web2ish-zera-ed25519-v1",
    curve: "ed25519",
    algorithm: "scrypt-sha512-ed25519-v1",
    saltPolicy: "public-username-sha256-v1",
    N: 65_536,
    r: 8,
    p: 1,
    dkLen: 32,
  }),
  "web2ish-zera-ed25519-external-salt-v1": Object.freeze({
    id: "web2ish-zera-ed25519-external-salt-v1",
    curve: "ed25519",
    algorithm: "scrypt-sha512-ed25519-external-32-v1",
    saltPolicy: "external-32-v1",
    N: 65_536,
    r: 8,
    p: 1,
    dkLen: 32,
  }),
});

export function getProfile(id: BuiltInProfileId): ProfileDescription {
  const profile = profiles[id];
  if (!profile) {
    throw new DerivationError("Unknown deterministic wallet profile.", "invalid-profile");
  }
  return profile;
}

export const builtInProfiles = profiles;
