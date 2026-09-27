import { describe, expect, it } from "vitest";
import {
  zeraEd25519Codec,
  zeraEd25519ExternalSalt,
  zeraProfiles,
} from "../../src/chains/zera.js";

/**
 * Byte-identity guard.
 *
 * Every value pinned below is part of the definition of a wallet, not of its
 * formatting: the domain strings and KDF parameters feed the scrypt transcript,
 * and the codec decides how the resulting key is spelled. An edit to
 * `src/chains/zera.ts` that changed any of them would silently redefine every
 * wallet ever derived under this profile — users would keep their password
 * and lose their address. The committed vector proves the end-to-end result;
 * this file names the individual inputs so a diff that breaks them fails here
 * with an obvious message rather than as an opaque vector mismatch.
 *
 * If one of these assertions fails, the correct response is almost never to
 * update the expectation. It is to publish a new profile id instead.
 */

/** Concatenated with the raw password bytes. */
const PASSWORD_HASH_DOMAIN = "web2-ish-self-custody password hash v1\n";

describe("ZERA Ed25519 profile constants", () => {
  it("pins the external-salt profile exactly", () => {
    expect(zeraEd25519ExternalSalt.id).toBe("web2ish-zera-ed25519-external-salt-v1");
    expect(zeraEd25519ExternalSalt.curve).toBe("ed25519");
    expect(zeraEd25519ExternalSalt.algorithm).toBe("scrypt-sha512-ed25519-external-32-v1");
    expect(zeraEd25519ExternalSalt.saltPolicy).toBe("external-32");
    expect(zeraEd25519ExternalSalt.kdf).toEqual({ N: 65_536, r: 8, p: 1, dkLen: 32 });
    expect(zeraEd25519ExternalSalt.domains).toEqual({
      passwordHash: PASSWORD_HASH_DOMAIN,
      entropy: "web2-ish-self-custody ZERA Ed25519 external salt entropy v1",
    });
    // A stray salt domain here would be dead weight the service never reads.
    expect(zeraEd25519ExternalSalt.domains.salt).toBeUndefined();
    expect(zeraEd25519ExternalSalt.codec.id).toBe("zera-ed25519-base58-v1");
  });

  it("keeps the trailing newline that makes the password-hash domain a prefix", () => {
    // `derive` concatenates this with the raw password bytes rather than
    // joining with a newline, so the newline has to live in the string itself.
    expect(PASSWORD_HASH_DOMAIN.endsWith("\n")).toBe(true);
    expect(zeraEd25519ExternalSalt.domains.passwordHash).toBe(PASSWORD_HASH_DOMAIN);
  });

  it("freezes the profile, its KDF parameters, and its domains", () => {
    expect(Object.isFrozen(zeraEd25519ExternalSalt)).toBe(true);
    expect(Object.isFrozen(zeraEd25519ExternalSalt.kdf)).toBe(true);
    expect(Object.isFrozen(zeraEd25519ExternalSalt.domains)).toBe(true);
    expect(Object.isFrozen(zeraEd25519ExternalSalt.codec)).toBe(true);
    expect(zeraEd25519ExternalSalt.codec).toBe(zeraEd25519Codec);
  });

  it("exposes exactly the bundled profile, keyed by its own id", () => {
    // The self-salting built-in profile (web2ish-zera-ed25519-v1) was removed
    // in v0.9.0; a stored id for it must not resolve to anything.
    expect(Object.keys(zeraProfiles)).toEqual(["web2ish-zera-ed25519-external-salt-v1"]);
    expect(zeraProfiles["web2ish-zera-ed25519-external-salt-v1"]).toBe(zeraEd25519ExternalSalt);
    expect(zeraProfiles["web2ish-zera-ed25519-v1"]).toBeUndefined();
    expect(Object.isFrozen(zeraProfiles)).toBe(true);
  });
});

describe("ZERA Ed25519 codec constants", () => {
  const publicKeyBytes = Uint8Array.from({ length: 32 }, (_, index) => index);

  it("pins the base58 address and A_-tagged identifier convention", () => {
    expect(zeraEd25519Codec.id).toBe("zera-ed25519-base58-v1");
    expect(zeraEd25519Codec.encodeAddress(publicKeyBytes)).toBe(
      "1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
    );
    expect(zeraEd25519Codec.encodePublicKey(publicKeyBytes)).toBe(
      "A_1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
    );
  });
});
