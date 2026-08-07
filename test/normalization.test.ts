import { describe, expect, it } from "vitest";
import { MAXIMUM_PASSWORD_BYTES, MINIMUM_PASSWORD_BYTES, normalizeUsername } from "../src/index.js";

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

describe("password bounds", () => {
  it("publishes the byte bounds every profile enforces", () => {
    // These are part of the package's public contract: a UI that lets a user
    // pick a password outside them would produce a wallet they cannot re-derive.
    expect(MINIMUM_PASSWORD_BYTES).toBe(24);
    expect(MAXIMUM_PASSWORD_BYTES).toBe(1_024);
    expect(MINIMUM_PASSWORD_BYTES).toBeLessThan(MAXIMUM_PASSWORD_BYTES);
  });
});
