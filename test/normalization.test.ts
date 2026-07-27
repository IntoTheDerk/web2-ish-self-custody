import { describe, expect, it } from "vitest";
import {
  getProfile,
  normalizeDemocracyOsUsername,
  normalizeWeb2ishUsername,
} from "../src/index.js";

describe("versioned input contracts", () => {
  it("retains DemocracyOS trim and lowercase compatibility", () => {
    expect(normalizeDemocracyOsUsername("  Jesse@Example.COM ")).toBe("jesse@example.com");
  });

  it("keeps the new stateless profile ASCII-only", () => {
    expect(normalizeWeb2ishUsername("  JESSE@example.COM ")).toBe("jesse@example.com");
    expect(() => normalizeWeb2ishUsername("ｊｅｓｓｅ@example.com")).toThrow();
    expect(() => normalizeWeb2ishUsername("bad\u0000name")).toThrow();
  });

  it("exposes immutable, fixed-cost built-in profiles", () => {
    const profile = getProfile("web2ish-zera-ed25519-v1");
    expect(profile).toMatchObject({
      curve: "ed25519",
      saltPolicy: "public-username-sha256-v1",
      N: 65_536,
      r: 8,
      p: 1,
      dkLen: 32,
    });
    expect(Object.isFrozen(profile)).toBe(true);
  });
});
