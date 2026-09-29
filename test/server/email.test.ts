import { describe, expect, it } from "vitest";
import type { IdentityService } from "../../src/server/contract.js";
import {
  EmailDeliveryError,
  assertEmailVerificationDelivery,
  deliverEmailVerification,
  formatVerificationCode,
  parseMailbox,
  renderVerificationEmail,
  type EmailDeliveryFailure,
  type EmailMessage,
  type EmailSender,
  type EmailVerificationDelivery,
} from "../../src/server/email.js";
import {
  createEmailSender,
  createPostmarkEmailSender,
  createResendEmailSender,
  createSendGridEmailSender,
} from "../../src/server/emailProviders.js";
import { createIdentityRouter } from "../../src/server/router.js";

const secret = "re_test_SECRET_value_123";
const code = "ABCD2345";
const issued = Object.freeze({
  verificationId: "5b0c7f1e-8f5a-4a1e-9c3a-0e2f6a1d9b77",
  code,
  email: "ada@example.org",
  expiresAt: new Date("2026-09-29T12:15:00.000Z"),
});
const now = new Date("2026-09-29T12:00:00.000Z");

type Call = Readonly<{ url: string; init: RequestInit }>;

function fakeFetch(response: () => Response): {
  calls: Call[];
  fetch: (url: string, init: RequestInit) => Promise<Response>;
} {
  const calls: Call[] = [];
  return {
    calls,
    fetch: (url, init) => {
      calls.push({ url, init });
      return Promise.resolve(response());
    },
  };
}

function jsonBody(call: Call | undefined): Record<string, unknown> {
  return JSON.parse(String(call?.init.body)) as Record<string, unknown>;
}

function headers(call: Call | undefined): Record<string, string> {
  return (call?.init.headers ?? {}) as Record<string, string>;
}

const message: EmailMessage = {
  from: "Knight Armor <verify@knight-armor.com>",
  to: "ada@example.org",
  replyTo: "support@knight-armor.com",
  subject: "Your code",
  text: `code ${code}`,
  html: `<p>${code}</p>`,
  idempotencyKey: "email-verification/abc",
};

describe("Resend sender", () => {
  it("posts one message with the key only in the Authorization header", async () => {
    const fake = fakeFetch(() => Response.json({ id: "msg_1" }));
    const sender = createResendEmailSender({ apiKey: secret, fetch: fake.fetch });

    await expect(sender.send(message)).resolves.toEqual({ provider: "resend", messageId: "msg_1" });

    const call = fake.calls[0];
    expect(call?.url).toBe("https://api.resend.com/emails");
    expect(call?.init.method).toBe("POST");
    expect(call?.init.redirect).toBe("error");
    expect(headers(call)["Authorization"]).toBe(`Bearer ${secret}`);
    expect(headers(call)["Idempotency-Key"]).toBe("email-verification/abc");
    expect(jsonBody(call)).toEqual({
      from: message.from,
      to: ["ada@example.org"],
      subject: "Your code",
      text: message.text,
      html: message.html,
      reply_to: "support@knight-armor.com",
    });
    expect(String(call?.init.body)).not.toContain(secret);
  });

  it("never exposes the key through the sender object", () => {
    const sender = createResendEmailSender({ apiKey: secret });
    expect(JSON.stringify(sender)).not.toContain(secret);
    expect(Object.values(sender).map(String).join(" ")).not.toContain(secret);
  });

  it("reports a refusal without the response body", async () => {
    const fake = fakeFetch(
      () => new Response(JSON.stringify({ message: `bad ${secret} ada@example.org` }), { status: 422 }),
    );
    const sender = createResendEmailSender({ apiKey: secret, fetch: fake.fetch });
    const error = await sender.send(message).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(EmailDeliveryError);
    expect(error).toMatchObject({ provider: "resend", reason: "rejected", status: 422 });
    expect(String((error as Error).message)).not.toMatch(/SECRET|ada@/u);
  });

  it("classifies transport failures", async () => {
    const timeout = createResendEmailSender({
      apiKey: secret,
      fetch: () => Promise.reject(new DOMException("slow", "TimeoutError")),
    });
    await expect(timeout.send(message)).rejects.toMatchObject({ reason: "timeout" });
    const offline = createResendEmailSender({
      apiKey: secret,
      fetch: () => Promise.reject(new TypeError(`fetch failed ${secret}`)),
    });
    const error = await offline.send(message).catch((caught: unknown) => caught);
    expect(error).toMatchObject({ reason: "network", status: null });
    expect(String((error as Error).message)).not.toContain(secret);
  });

  it("refuses a missing key without echoing it and a non-https endpoint", () => {
    expect(() => createResendEmailSender({ apiKey: "  " })).toThrow(/Resend apiKey/u);
    expect(() => createResendEmailSender({ apiKey: "re_a b" })).toThrow(/^Resend apiKey is missing or malformed\.$/u);
    expect(() =>
      createResendEmailSender({ apiKey: secret, baseUrl: "http://api.resend.com" }),
    ).toThrow(/https/u);
  });
});

describe("Postmark sender", () => {
  it("maps the message onto Postmark's fields", async () => {
    const fake = fakeFetch(() => Response.json({ ErrorCode: 0, MessageID: "pm-1" }));
    const sender = createPostmarkEmailSender({ serverToken: "pm-token", fetch: fake.fetch });
    await expect(sender.send(message)).resolves.toEqual({ provider: "postmark", messageId: "pm-1" });
    const call = fake.calls[0];
    expect(call?.url).toBe("https://api.postmarkapp.com/email");
    expect(headers(call)["X-Postmark-Server-Token"]).toBe("pm-token");
    expect(jsonBody(call)).toMatchObject({
      From: message.from,
      To: "ada@example.org",
      ReplyTo: "support@knight-armor.com",
      MessageStream: "outbound",
    });
  });

  it("treats a non-zero ErrorCode as a refusal", async () => {
    const fake = fakeFetch(() => Response.json({ ErrorCode: 300, Message: "Invalid email" }));
    const sender = createPostmarkEmailSender({ serverToken: "pm-token", fetch: fake.fetch });
    await expect(sender.send(message)).rejects.toMatchObject({ reason: "rejected" });
  });
});

describe("SendGrid sender", () => {
  it("splits mailboxes and reads the id from the header", async () => {
    const fake = fakeFetch(
      () => new Response(null, { status: 202, headers: { "X-Message-Id": "sg-1" } }),
    );
    const sender = createSendGridEmailSender({ apiKey: "SG.key", fetch: fake.fetch });
    await expect(sender.send(message)).resolves.toEqual({ provider: "sendgrid", messageId: "sg-1" });
    const body = jsonBody(fake.calls[0]);
    expect(body["from"]).toEqual({ email: "verify@knight-armor.com", name: "Knight Armor" });
    expect(body["personalizations"]).toEqual([{ to: [{ email: "ada@example.org" }] }]);
    expect(body["reply_to"]).toEqual({ email: "support@knight-armor.com" });
  });
});

describe("createEmailSender", () => {
  it("selects the named provider", () => {
    expect(createEmailSender({ provider: "resend", apiKey: secret }).provider).toBe("resend");
    expect(createEmailSender({ provider: "postmark", serverToken: "t" }).provider).toBe("postmark");
    expect(createEmailSender({ provider: "sendgrid", apiKey: "k" }).provider).toBe("sendgrid");
    expect(() =>
      createEmailSender({ provider: "smtp", apiKey: "k" } as unknown as Parameters<
        typeof createEmailSender
      >[0]),
    ).toThrow(/Unknown email provider/u);
  });
});

describe("parseMailbox", () => {
  it("accepts bare and named addresses", () => {
    expect(parseMailbox("a@b.co")).toEqual({ name: null, email: "a@b.co" });
    expect(parseMailbox("Knight Armor <verify@knight-armor.com>")).toEqual({
      name: "Knight Armor",
      email: "verify@knight-armor.com",
    });
    expect(parseMailbox('"Armor, Knight" <v@k.com>')).toEqual({ name: "Armor, Knight", email: "v@k.com" });
  });

  it("refuses header smuggling and junk", () => {
    expect(() => parseMailbox("a@b.co\r\nBcc: x@y.z")).toThrow();
    expect(() => parseMailbox("not an address")).toThrow();
    expect(() => parseMailbox("<a@b>")).toThrow();
  });
});

describe("renderVerificationEmail", () => {
  const input = {
    code,
    formattedCode: formatVerificationCode(code),
    email: "ada@example.org",
    expiresAt: issued.expiresAt,
    expiresInMinutes: 15,
  };

  it("puts the code in both bodies and applies the theme", () => {
    const content = renderVerificationEmail(input, {
      productName: "Knight Armor",
      accentColor: "#d4b896",
      backgroundColor: "#1c1814",
    });
    expect(content.subject).toBe("Your Knight Armor verification code");
    expect(content.text).toContain("ABCD-2345");
    expect(content.text).toContain("15 minutes");
    expect(content.html).toContain("ABCD-2345");
    expect(content.html).toContain("#d4b896");
    expect(content.html).toContain("background-color:#1c1814");
    expect(content.html).not.toMatch(/<img|https?:\/\//u);
  });

  it("escapes host-supplied copy", () => {
    const content = renderVerificationEmail(input, {
      productName: "<script>x</script>",
      intro: `"quoted" & <b>`,
    });
    expect(content.html).not.toContain("<script>");
    expect(content.html).toContain("&lt;script&gt;");
    expect(content.html).toContain("&quot;quoted&quot; &amp; &lt;b&gt;");
  });

  it("refuses unsafe theme values", () => {
    expect(() => renderVerificationEmail(input, { productName: "X", accentColor: "red;x:y" })).toThrow();
    expect(() =>
      renderVerificationEmail(input, { productName: "X", bodyFontFamily: "a;background:url(x)" }),
    ).toThrow();
    expect(() => renderVerificationEmail(input, { productName: "X", logoUrl: "http://x.test/a.png" })).toThrow();
    expect(() => renderVerificationEmail(input, { productName: "X", subject: "a\r\nBcc: y" })).toThrow();
  });
});

function recordingSender(): { sender: EmailSender; sent: EmailMessage[] } {
  const sent: EmailMessage[] = [];
  return {
    sent,
    sender: {
      provider: "test",
      send: (value) => {
        sent.push(value);
        return Promise.resolve({ provider: "test", messageId: "t-1" });
      },
    },
  };
}

describe("deliverEmailVerification", () => {
  it("renders with a custom template and sends one idempotent message", async () => {
    const { sender, sent } = recordingSender();
    await deliverEmailVerification(
      {
        sender,
        from: "Ops <ops@example.org>",
        render: (value) => ({
          subject: "Code",
          text: `Use ${value.code} within ${String(value.expiresInMinutes)}m`,
          html: `<b>${value.formattedCode}</b>`,
        }),
      },
      issued,
      now,
    );
    expect(sent).toHaveLength(1);
    expect(sent[0]).toMatchObject({
      to: "ada@example.org",
      subject: "Code",
      text: "Use ABCD2345 within 15m",
      idempotencyKey: `email-verification/${issued.verificationId}`,
    });
  });

  it("refuses a template that drops the code", async () => {
    const { sender, sent } = recordingSender();
    const delivery: EmailVerificationDelivery = {
      sender,
      from: "ops@example.org",
      render: () => ({ subject: "Hi", text: "no code", html: "<p>no code</p>" }),
    };
    await expect(deliverEmailVerification(delivery, issued, now)).rejects.toMatchObject({
      reason: "render",
    });
    expect(sent).toHaveLength(0);
  });

  it("checks configuration up front", () => {
    const { sender } = recordingSender();
    expect(() => assertEmailVerificationDelivery({ sender, from: "ops@example.org" })).toThrow(
      /theme or a render/u,
    );
    expect(() =>
      assertEmailVerificationDelivery({ sender, from: "bad", theme: { productName: "X" } }),
    ).toThrow(/from/u);
  });
});

describe("router email delivery", () => {
  function stubService(): IdentityService {
    return {
      startEmailVerification: () => Promise.resolve(issued),
    } as unknown as IdentityService;
  }

  function startRequest(): Request {
    return new Request("https://id.example/identity/email-verifications", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "ada", email: "ada@example.org" }),
    });
  }

  it("sends the code and still withholds it from the response", async () => {
    const { sender, sent } = recordingSender();
    const router = createIdentityRouter(stubService(), {
      useCookies: false,
      emailVerification: { sender, from: "v@example.org", theme: { productName: "Example" } },
    });
    const response = await router(startRequest());
    expect(response.status).toBe(200);
    const text = await response.text();
    expect(text).not.toContain(code);
    expect(text).not.toContain("ABCD-2345");
    expect(sent).toHaveLength(1);
    expect(sent[0]?.text).toContain("ABCD-2345");
  });

  it("answers email-delivery-failed and reports only safe fields", async () => {
    const failures: EmailDeliveryFailure[] = [];
    const router = createIdentityRouter(stubService(), {
      useCookies: false,
      emailVerification: {
        sender: {
          provider: "resend",
          send: () => Promise.reject(new EmailDeliveryError("resend", "rejected", 403)),
        },
        from: "v@example.org",
        theme: { productName: "Example" },
        onFailure: (failure) => {
          failures.push(failure);
          throw new Error("reporter is broken");
        },
      },
    });
    const response = await router(startRequest());
    expect(response.status).toBe(502);
    const text = await response.text();
    expect(JSON.parse(text)).toMatchObject({ error: { code: "email-delivery-failed" } });
    expect(text).not.toContain(code);
    expect(failures).toEqual([{ provider: "resend", reason: "rejected", status: 403 }]);
  });

  it("refuses to build with a malformed delivery config", () => {
    expect(() =>
      createIdentityRouter(stubService(), {
        emailVerification: {
          sender: recordingSender().sender,
          from: "v@example.org",
        },
      }),
    ).toThrow(/theme or a render/u);
  });
});
