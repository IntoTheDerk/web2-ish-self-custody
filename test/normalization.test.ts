import { describe, expect, it } from "vitest";
import {
  MAXIMUM_PASSWORD_BYTES,
  MINIMUM_PASSWORD_CHARACTERS,
  normalizeUsername,
} from "../src/index.js";
import { assertWalletPassword } from "../src/normalization.js";

const encoder = new TextEncoder();

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
  it("publishes the bounds every profile enforces", () => {
    // These are part of the package's public contract: a UI that lets a user
    // pick a password outside them would produce a wallet they cannot re-derive.
    expect(MINIMUM_PASSWORD_CHARACTERS).toBe(10);
    expect(MAXIMUM_PASSWORD_BYTES).toBe(1_024);
  });

  function rejects(password: unknown): void {
    expect(
      () => assertWalletPassword(password as Uint8Array),
      `${String(password)} must be rejected`,
    ).toThrowError(expect.objectContaining({ code: "invalid-password" }));
  }

  it("counts characters as Unicode code points, not bytes or UTF-16 units", () => {
    // Accepting edge: exactly ten code points, however many bytes each takes.
    for (const accepted of [
      "a".repeat(10),
      "é".repeat(10), // 2 bytes each
      "€".repeat(10), // 3 bytes each
      "🔐".repeat(10), // 4 bytes each, and 2 UTF-16 units each
      "passwørd🔐!", // mixed widths
    ]) {
      expect([...accepted].length).toBe(10);
      expect(() => assertWalletPassword(encoder.encode(accepted))).not.toThrow();
    }

    // Rejecting edge: nine code points, even where the byte count or the
    // UTF-16 length is well past ten. Six emoji are 24 bytes, which the old
    // byte floor accepted.
    for (const rejected of ["a".repeat(9), "🔐".repeat(9), "🔐".repeat(6), "", "passwørd"]) {
      expect([...rejected].length).toBeLessThan(10);
      rejects(encoder.encode(rejected));
    }
  });

  it("does not normalize: whitespace and combining marks count as typed", () => {
    // Ten code points, four of them spaces. Trimming would take it under the
    // floor, so accepting it proves nothing is trimmed before counting.
    expect(() => assertWalletPassword(encoder.encode("  abcdef  "))).not.toThrow();
    // "e" + U+0301 is two code points; NFC would fold each pair into one "é"
    // and take ten code points down to five.
    const decomposed = "e\u0301".repeat(5);
    expect([...decomposed].length).toBe(10);
    expect(() => assertWalletPassword(encoder.encode(decomposed))).not.toThrow();
    // A leading U+FEFF is a character like any other, not a stripped BOM.
    expect(() => assertWalletPassword(encoder.encode("\ufeffabcdefghi"))).not.toThrow();
    rejects(encoder.encode("\ufeffabcdefgh"));
  });

  it("keeps the 1,024-byte ceiling on the encoded bytes", () => {
    expect(() => assertWalletPassword(new Uint8Array(MAXIMUM_PASSWORD_BYTES).fill(0x61))).not.toThrow();
    rejects(new Uint8Array(MAXIMUM_PASSWORD_BYTES + 1).fill(0x61));
    // 256 four-byte characters is exactly the ceiling; one more is over it.
    expect(() => assertWalletPassword(encoder.encode("🔐".repeat(256)))).not.toThrow();
    rejects(encoder.encode("🔐".repeat(257)));
  });

  it("rejects anything that is not a Uint8Array", () => {
    for (const bad of ["correct horse battery staple", null, undefined, 42, [0x61], new Uint16Array(12)]) {
      rejects(bad);
    }
  });

  it("rejects bytes that are not well-formed UTF-8", () => {
    const pad = Array.from(encoder.encode("abcdefghij"));
    for (const bad of [
      [0x80], // stray continuation byte
      [0xbf],
      [0xc0, 0x80], // overlong NUL
      [0xc1, 0xbf], // overlong
      [0xe0, 0x80, 0x80], // overlong
      [0xe0, 0x9f, 0xbf], // overlong
      [0xed, 0xa0, 0x80], // UTF-16 high surrogate
      [0xed, 0xbf, 0xbf], // UTF-16 low surrogate
      [0xf0, 0x80, 0x80, 0x80], // overlong
      [0xf0, 0x8f, 0xbf, 0xbf], // overlong
      [0xf4, 0x90, 0x80, 0x80], // above U+10FFFF
      [0xf5, 0x80, 0x80, 0x80], // invalid lead byte
      [0xff],
      [0xc3], // truncated two-byte sequence
      [0xe2, 0x82], // truncated three-byte sequence
      [0xf0, 0x9f, 0x94], // truncated four-byte sequence
      [0xe2, 0x41, 0x82], // non-continuation inside a sequence
    ]) {
      rejects(Uint8Array.from([...pad, ...bad]));
      rejects(Uint8Array.from([...bad, ...pad]));
    }
  });

  it("agrees with a strict UTF-8 decoder on arbitrary bytes", () => {
    // TextDecoder is the reference here only. The implementation deliberately
    // does not use it, so the password never becomes an unzeroable string.
    const strict = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    // Bytes at every boundary of the well-formed ranges.
    const edgeBytes = [
      0x00, 0x41, 0x7f, 0x80, 0x8f, 0x90, 0x9f, 0xa0, 0xbf, 0xc0, 0xc1, 0xc2, 0xdf,
      0xe0, 0xe1, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf3, 0xf4, 0xf5, 0xff,
    ];
    let state = 0x2545f491;
    const next = (): number => {
      state ^= state << 13;
      state ^= state >>> 17;
      state ^= state << 5;
      return state >>> 0;
    };
    // Mostly well-formed characters of every width, with an occasional edge
    // byte spliced in, so both verdicts and both sides of the floor are common.
    const randomBytes = (): Uint8Array => {
      const out: number[] = [];
      const units = 3 + (next() % 14);
      for (let unit = 0; unit < units; unit += 1) {
        if (next() % 8 === 0) {
          out.push(edgeBytes[next() % edgeBytes.length] as number);
          continue;
        }
        const width = next() % 4;
        const codePoint =
          width === 0
            ? next() % 0x80
            : width === 1
              ? 0x80 + (next() % 0x780)
              : width === 2
                ? 0x800 + (next() % 0xf800)
                : 0x10000 + (next() % 0x100000);
        // Lone surrogates encode to U+FFFD, which is still one code point.
        out.push(...encoder.encode(String.fromCodePoint(codePoint)));
      }
      return Uint8Array.from(out);
    };

    const verdicts = { accepted: 0, rejectedShort: 0, rejectedMalformed: 0 };
    for (let round = 0; round < 20_000; round += 1) {
      const bytes = randomBytes();
      let characters: number | undefined;
      try {
        characters = [...strict.decode(bytes)].length;
      } catch {
        characters = undefined;
      }
      const expected =
        characters === undefined
          ? "rejectedMalformed"
          : characters >= MINIMUM_PASSWORD_CHARACTERS
            ? "accepted"
            : "rejectedShort";
      let actual: "accepted" | "rejected";
      try {
        assertWalletPassword(bytes);
        actual = "accepted";
      } catch {
        actual = "rejected";
      }
      expect(
        actual,
        Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(" "),
      ).toBe(expected === "accepted" ? "accepted" : "rejected");
      verdicts[expected] += 1;
    }
    // Guard against a generator that only ever exercises one branch.
    expect(verdicts.accepted).toBeGreaterThan(1_000);
    expect(verdicts.rejectedShort).toBeGreaterThan(1_000);
    expect(verdicts.rejectedMalformed).toBeGreaterThan(1_000);
  });
});
