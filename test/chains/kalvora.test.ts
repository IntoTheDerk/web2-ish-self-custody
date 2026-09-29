import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import bs58 from "bs58";
import {
  KALVORA_TYPE,
  KEY_TYPE,
  SLIP0010_DERIVATION_PATH,
  createWallet,
  deriveHDPrivateKey,
  deriveMultipleWallets,
  generateSeed,
} from "kalvora.js/wallet";
import { describe, expect, it } from "vitest";
import {
  KALVORA_DERIVATION_PATH,
  KALVORA_SLIP44_COIN_TYPE,
  kalvoraEd25519Codec,
  kalvoraEd25519ExternalSalt,
  kalvoraProfiles,
  kalvoraSlip10Ed25519,
} from "../../src/chains/kalvora.js";

/**
 * Byte-identity guard.
 *
 * Every value pinned below is part of the definition of a wallet, not of its
 * formatting: the domain strings and KDF parameters feed the scrypt transcript,
 * the key-derivation step turns its output into the wallet key, and the codec
 * decides how that key is spelled. An edit to `src/chains/kalvora.ts` that
 * changed any of them would silently redefine every wallet ever derived under
 * this profile — users would keep their password and lose their address. The
 * committed vector proves the end-to-end result; this file names the
 * individual inputs so a diff that breaks them fails here with an obvious
 * message rather than as an opaque vector mismatch.
 *
 * If one of these assertions fails, the correct response is almost never to
 * update the expectation. It is to publish a new profile id instead.
 */

/** Concatenated with the raw password bytes. */
const PASSWORD_HASH_DOMAIN = "web2-ish-self-custody password hash v1\n";

const ABANDON_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

describe("Kalvora Ed25519 profile constants", () => {
  it("pins the external-salt profile exactly", () => {
    expect(kalvoraEd25519ExternalSalt.id).toBe("web2ish-kalvora-ed25519-external-salt-v1");
    expect(kalvoraEd25519ExternalSalt.curve).toBe("ed25519");
    expect(kalvoraEd25519ExternalSalt.algorithm).toBe(
      "scrypt-sha512-slip10-ed25519-external-32-v1",
    );
    expect(kalvoraEd25519ExternalSalt.saltPolicy).toBe("external-32");
    expect(kalvoraEd25519ExternalSalt.kdf).toEqual({ N: 65_536, r: 8, p: 1, dkLen: 32 });
    expect(kalvoraEd25519ExternalSalt.domains).toEqual({
      passwordHash: PASSWORD_HASH_DOMAIN,
      entropy: "web2-ish-self-custody Kalvora Ed25519 external salt entropy v1",
    });
    // A stray salt domain here would be dead weight the service never reads.
    expect(kalvoraEd25519ExternalSalt.domains.salt).toBeUndefined();
    expect(kalvoraEd25519ExternalSalt.keyDerivation?.id).toBe(
      "slip10-ed25519:m/44'/5258'/0'/0'/0'",
    );
    expect(kalvoraEd25519ExternalSalt.codec.id).toBe("kalvora-ed25519-base58-v1");
  });

  it("pins SLIP-44 coin type 5258 and agrees with kalvora.js about it", () => {
    expect(KALVORA_SLIP44_COIN_TYPE).toBe(5258);
    expect(KALVORA_DERIVATION_PATH).toBe("m/44'/5258'/0'/0'/0'");
    // The path is pinned locally so a kalvora.js release cannot move it; this
    // only checks that the two still describe the same first wallet.
    expect(KALVORA_TYPE).toBe(KALVORA_SLIP44_COIN_TYPE);
    expect(SLIP0010_DERIVATION_PATH).toBe(KALVORA_DERIVATION_PATH);
  });

  it("keeps the trailing newline that makes the password-hash domain a prefix", () => {
    // `derive` concatenates this with the raw password bytes rather than
    // joining with a newline, so the newline has to live in the string itself.
    expect(PASSWORD_HASH_DOMAIN.endsWith("\n")).toBe(true);
    expect(kalvoraEd25519ExternalSalt.domains.passwordHash).toBe(PASSWORD_HASH_DOMAIN);
  });

  it("freezes the profile, its KDF parameters, domains, key derivation, and codec", () => {
    expect(Object.isFrozen(kalvoraEd25519ExternalSalt)).toBe(true);
    expect(Object.isFrozen(kalvoraEd25519ExternalSalt.kdf)).toBe(true);
    expect(Object.isFrozen(kalvoraEd25519ExternalSalt.domains)).toBe(true);
    expect(Object.isFrozen(kalvoraEd25519ExternalSalt.keyDerivation)).toBe(true);
    expect(Object.isFrozen(kalvoraEd25519ExternalSalt.codec)).toBe(true);
    expect(kalvoraEd25519ExternalSalt.codec).toBe(kalvoraEd25519Codec);
  });

  it("exposes exactly the bundled profile, keyed by its own id", () => {
    expect(Object.keys(kalvoraProfiles)).toEqual(["web2ish-kalvora-ed25519-external-salt-v1"]);
    expect(kalvoraProfiles["web2ish-kalvora-ed25519-external-salt-v1"]).toBe(
      kalvoraEd25519ExternalSalt,
    );
    expect(Object.isFrozen(kalvoraProfiles)).toBe(true);
  });
});

describe("Kalvora key derivation", () => {
  it("is kalvora.js's SLIP-0010 Ed25519 at the Kalvora path, which meets the spec", () => {
    const seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
    const before = Uint8Array.from(seed);

    // SLIP-0010 "Test vector 1 for ed25519" lives at m/0'/1'/2'/2'/1000000000',
    // so the scheme is checked through the kalvora.js function the step calls…
    expect(
      bytesToHex(deriveHDPrivateKey(seed, "m/0'/1'/2'/2'/1000000000'")),
    ).toBe("8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793");
    // …and the step is that function at the Kalvora path, Ed25519.
    expect(kalvoraSlip10Ed25519.deriveKey(seed)).toEqual(
      deriveHDPrivateKey(seed, KALVORA_DERIVATION_PATH, KEY_TYPE.ED25519),
    );
    expect(seed).toEqual(before);
  });

  it("derives the same wallet as kalvora.js from the same seed", async () => {
    const seed = generateSeed(ABANDON_MNEMONIC);
    const key = kalvoraSlip10Ed25519.deriveKey(seed);
    const address = kalvoraEd25519Codec.encodeAddress(ed25519.getPublicKey(key));

    const wallet = await createWallet({ keyType: KEY_TYPE.ED25519, mnemonic: ABANDON_MNEMONIC });
    expect(wallet.derivationPath).toBe(KALVORA_DERIVATION_PATH);
    expect(address).toBe(wallet.address);
    // The SLIP-0010 value for this mnemonic and path, as published in
    // kalvora.js's docs/guides/hd-derivation.md.
    expect(address).toBe("35q7SEc9HVV7Gd9oVKCnZjPMxpLrH9DftTcBUyHahTZP");
    expect(bs58.encode(key)).toBe(wallet.privateKey);
    wallet.secureClear();
  });

  it("uses kalvora.js's first wallet, not any later account", async () => {
    const wallets = await deriveMultipleWallets({
      keyType: KEY_TYPE.ED25519,
      mnemonic: ABANDON_MNEMONIC,
      count: 2,
    });
    const key = kalvoraSlip10Ed25519.deriveKey(generateSeed(ABANDON_MNEMONIC));
    const address = kalvoraEd25519Codec.encodeAddress(ed25519.getPublicKey(key));
    expect(address).toBe(wallets[0]?.address);
    expect(address).not.toBe(wallets[1]?.address);
  });
});

describe("Kalvora Ed25519 codec constants", () => {
  const publicKeyBytes = Uint8Array.from({ length: 32 }, (_, index) => index);

  it("pins the base58 address and A_-tagged identifier convention", () => {
    expect(kalvoraEd25519Codec.id).toBe("kalvora-ed25519-base58-v1");
    expect(kalvoraEd25519Codec.encodeAddress(publicKeyBytes)).toBe(
      "1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
    );
    expect(kalvoraEd25519Codec.encodePublicKey(publicKeyBytes)).toBe(
      "A_1thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE",
    );
  });

  it("decodes only the exact A_<base58> form it encodes", () => {
    const identifier = kalvoraEd25519Codec.encodePublicKey(publicKeyBytes);
    expect(kalvoraEd25519Codec.decodePublicKey(identifier)).toEqual(publicKeyBytes);
    expect(() => kalvoraEd25519Codec.decodePublicKey(`B_${identifier.slice(2)}`)).toThrow();
    expect(() => kalvoraEd25519Codec.decodePublicKey(identifier.slice(2))).toThrow();
  });
});
