import { describe, expect, it } from "vitest";
import { builtInProfiles, getProfile, normalizeUsername } from "../src/index.js";

const ed25519ProfileIds = [
  "web2ish-zera-ed25519-external-salt-v1",
  "web2ish-zera-ed25519-v1",
];

describe("username normalization", () => {
  it("folds case and trims whitespace using ASCII rules only", () => {
    expect(normalizeUsername("  JESSE@example.COM ")).toBe("jesse@example.com");
    expect(normalizeUsername("\tJesse@Example.COM\r\n")).toBe("jesse@example.com");
    // `toLowerCase` is locale-sensitive — a Turkish locale folds "I" to "ı" —
    // so ASCII-only folding is what lets the same credentials derive the same
    // wallet on every device.
    expect(normalizeUsername("ISTANBUL@example.com")).toBe("istanbul@example.com");
  });

  it("rejects anything outside 3–120 printable ASCII characters", () => {
    for (const bad of [
      "ｊｅｓｓｅ@example.com",
      "İstanbul@example.com",
      "bad name",
      "bad\u0000name",
      "ab",
      "a".repeat(121),
      "   ",
    ]) {
      expect(() => normalizeUsername(bad)).toThrowError(
        expect.objectContaining({ code: "invalid-username" }),
      );
    }
  });
});

describe("built-in wallet profiles", () => {
  it("exposes exactly the two Ed25519 profiles and no other curve", () => {
    expect(Object.keys(builtInProfiles).sort()).toEqual(ed25519ProfileIds);

    for (const [id, profile] of Object.entries(builtInProfiles)) {
      expect(profile.id).toBe(id);
      expect(profile.curve).toBe("ed25519");
    }
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
    expect(Object.isFrozen(builtInProfiles)).toBe(true);
  });
});
