import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import vector from "../vectors/oprf-salt-v1.json" with { type: "json" };
import { derivePublicIdentity, signInEd25519ExternalSaltV2, startOprfSalt } from "../src/index.js";
import { createOprfServer } from "../src/server/oprf.js";

const encoder = new TextEncoder();
const masterKey = hexToBytes(vector.masterKeyHex);
const publicSalt = hexToBytes(vector.publicSaltHex);

/** A repeatable stand-in for the CSPRNG: only vectors may use it. */
function fixedRng(hex: string): (bytes?: number) => Uint8Array {
  const bytes = hexToBytes(hex);
  return (length) => {
    if (length !== undefined && length !== bytes.byteLength) throw new Error("unexpected rng length");
    return Uint8Array.from(bytes);
  };
}

function run(options: {
  username?: string;
  password?: string;
  master?: Uint8Array;
  serviceProfileId?: string;
  salt?: Uint8Array;
}): { blindedHex: string; evaluatedHex: string; saltHex: string } {
  const server = createOprfServer({
    masterKey: options.master ?? masterKey,
    serviceProfileId: options.serviceProfileId ?? vector.serviceProfileId,
  });
  const request = startOprfSalt(
    options.username ?? vector.username,
    encoder.encode(options.password ?? vector.passwordUtf8),
    fixedRng(vector.blindRandomHex),
  );
  const blindedHex = bytesToHex(request.blinded);
  const evaluated = server.evaluate(options.username ?? vector.username, request.blinded);
  return {
    blindedHex,
    evaluatedHex: bytesToHex(evaluated),
    saltHex: bytesToHex(request.finish(evaluated, options.salt ?? publicSalt)),
  };
}

describe("server-keyed salt", () => {
  it("reproduces the known answer", () => {
    const result = run({});
    expect(result.blindedHex).toBe(vector.blindedHex);
    expect(result.evaluatedHex).toBe(vector.evaluatedHex);
    expect(result.saltHex).toBe(vector.saltHex);
  });

  it("gives the same salt for every blind, so the client can re-derive it", () => {
    const server = createOprfServer({ masterKey, serviceProfileId: vector.serviceProfileId });
    const salts = [0, 1].map(() => {
      const request = startOprfSalt(vector.username, encoder.encode(vector.passwordUtf8));
      return bytesToHex(request.finish(server.evaluate(vector.username, request.blinded), publicSalt));
    });
    expect(salts[0]).toBe(salts[1]);
  });

  it("normalizes the username the way a sign-in does", () => {
    const upper = run({ username: `  ${vector.username.toUpperCase()} ` });
    expect(upper.saltHex).toBe(vector.saltHex);
  });

  it("changes with the password, the username, the master key, the profile and the public salt", () => {
    const other = new Uint8Array(masterKey);
    other[0] = (other[0] ?? 0) ^ 1;
    const changed = [
      run({ password: `${vector.passwordUtf8}!` }),
      run({ username: `${vector.username}-2` }),
      run({ master: other }),
      run({ serviceProfileId: "other-profile" }),
      run({ salt: new Uint8Array(32).fill(7) }),
    ].map((entry) => entry.saltHex);
    expect(new Set([vector.saltHex, ...changed]).size).toBe(changed.length + 1);
  });

  it("answers an unknown username exactly like any other: by the request alone", () => {
    expect(run({ username: "nobody-ever-registered-this" }).evaluatedHex).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("refuses a malformed element and a short master key", () => {
    const server = createOprfServer({ masterKey, serviceProfileId: vector.serviceProfileId });
    expect(() => server.evaluate(vector.username, new Uint8Array(31))).toThrow();
    expect(() => server.evaluate(vector.username, new Uint8Array(32).fill(0xff))).toThrow();
    expect(() => createOprfServer({ masterKey: new Uint8Array(31).fill(1), serviceProfileId: "x" })).toThrow();
    expect(() => createOprfServer({ masterKey: new Uint8Array(32), serviceProfileId: "x" })).toThrow();
  });

  it("works once and zeroes what it held", () => {
    const server = createOprfServer({ masterKey, serviceProfileId: vector.serviceProfileId });
    const request = startOprfSalt(vector.username, encoder.encode(vector.passwordUtf8));
    const answer = server.evaluate(vector.username, request.blinded);
    request.finish(answer, publicSalt);
    expect(() => request.finish(answer, publicSalt)).toThrow();
    request.discard();
  });

  it("feeds an unchanged profile: the key differs from the one the public salt alone gives", async () => {
    const base = {
      profile: signInEd25519ExternalSaltV2,
      username: vector.username,
      password: encoder.encode(vector.passwordUtf8),
      context: { applicationId: "knight-armor", networkId: "kalvora-mainnet" },
    } as const;
    const plain = await derivePublicIdentity({ ...base, salt: publicSalt });
    const keyed = await derivePublicIdentity({ ...base, salt: hexToBytes(vector.saltHex) });
    expect(keyed.publicKey).not.toBe(plain.publicKey);
    expect(keyed.publicKey).toBe(vector.signInPublicKey);
  }, 180_000);
});
