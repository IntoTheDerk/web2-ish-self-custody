import { describe, expect, it, vi } from "vitest";

/**
 * The sign-in profile is chain-neutral: the core entry, which exports it, must
 * load without kalvora.js. Every kalvora.js entry is replaced by a module whose
 * import throws, so any path from the core to it fails here.
 */
vi.mock("kalvora.js/wallet", () => {
  throw new Error("kalvora.js/wallet must not be imported by the core entry");
});
vi.mock("kalvora.js", () => {
  throw new Error("kalvora.js must not be imported by the core entry");
});

describe("the sign-in profile's import boundary", () => {
  it("loads from the core entry with kalvora.js unavailable", async () => {
    const core = await import("../src/index.js");
    expect(core.signInEd25519ExternalSalt.id).toBe("web2ish-sign-in-ed25519-external-salt-v1");
    expect(core.signInEd25519ExternalSaltV2.id).toBe("web2ish-sign-in-ed25519-external-salt-v2");
    expect(core.signInEd25519Codec.id).toBe("web2ish-sign-in-ed25519-hex-v1");
    expect(core.signInHkdfEd25519.id).toBe("hkdf-sha256-sign-in-key-v1");
    expect(core.SIGN_IN_KEY_DOMAIN).toBe("web2-ish-self-custody sign-in key v1");
  });

  it("would notice an import: the Kalvora chain module fails to load here", async () => {
    const failure: unknown = await import("../src/chains/kalvora.js").then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(Error);
    // vitest reports a throwing mock factory with the factory's error as cause.
    expect(String((failure as Error).cause)).toMatch(/must not be imported/u);
  });
});
