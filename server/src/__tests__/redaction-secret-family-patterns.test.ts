import { describe, expect, it } from "vitest";
import { REDACTED_EVENT_VALUE, redactRunLogText, redactSecretFamilyPatterns, redactSensitiveText } from "../redaction.js";

describe("secret family patterns (ACC-3241)", () => {
  it("masks pcp_board_ tokens by value shape under any header name (C7)", () => {
    const first = `pcp_board_${"362545d61d".repeat(5)}`;
    const second = `pcp_board_${"bfb1fd77f1".repeat(5)}`;
    expect(first.length).toBeGreaterThanOrEqual(56);
    const input = [
      `X-Paperclip-Api-Key: ${first}`,
      `X-Api-Key: ${second}`,
      `X-Paperclip-Board-Key: ${first}`,
      `X-Board-Key: ${second}`,
    ].join("\n");

    const out = redactRunLogText(input);
    expect(out).not.toContain(first);
    expect(out).not.toContain(second);
    expect(out).toContain(`X-Paperclip-Api-Key: ${REDACTED_EVENT_VALUE}`);
    expect(out).toContain(`X-Board-Key: ${REDACTED_EVENT_VALUE}`);
  });

  it("masks provider-prefixed tokens by shape (sk-, ghp_, github_pat_, pcp_)", () => {
    const tokens = [
      `sk-ant-${"ort01".repeat(8)}`,
      `sk-or-v1-${"abcdef".repeat(8)}`,
      `sk-proj-${"uvwxyz".repeat(8)}`,
      `ghp_${"Qm3xK9pL".repeat(4)}`,
      `github_pat_${"11ABCDEFGH0123456789".repeat(2)}`,
      `pcp_${"k7Qw9rT2xZ".repeat(4)}`,
    ];
    for (const token of tokens) {
      const out = redactRunLogText(`probe ${token} probe`);
      expect(out, token).not.toContain(token);
      expect(out, token).toContain(REDACTED_EVENT_VALUE);
    }
  });

  it("collapses PEM private key blocks including truncated ones (C7)", () => {
    const body = ["b3BlbnNzaC1rZXktdjEAAAAA", "b3BlbnNzaC1rZXktdjEAAAAA"].join("\n");
    const truncated = `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}`;
    expect(redactSecretFamilyPatterns(truncated))
      .toBe(`-----BEGIN OPENSSH PRIVATE KEY-----\n${REDACTED_EVENT_VALUE}`);

    const complete = `${truncated}\n-----END OPENSSH PRIVATE KEY-----`;
    expect(redactSecretFamilyPatterns(complete))
      .toBe(`-----BEGIN OPENSSH PRIVATE KEY-----\n${REDACTED_EVENT_VALUE}\n-----END OPENSSH PRIVATE KEY-----`);
  });

  it("leaves a lone PEM header unchanged so JSON-escaped text stays decodable", () => {
    const escaped = JSON.stringify("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA");
    expect(redactSecretFamilyPatterns(escaped)).toBe(escaped);
  });

  it("masks the password part of credential URLs", () => {
    const out = redactSecretFamilyPatterns("connect postgresql://admin:hunter2secret@db.internal:5432/app");
    expect(out).toBe(`connect postgresql://admin:${REDACTED_EVENT_VALUE}@db.internal:5432/app`);
  });

  it("masks JWT-shaped values (C7)", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const out = redactRunLogText(`cookie: session=${jwt}; Path=/`);
    expect(out).not.toContain(jwt);
    expect(out).toContain(REDACTED_EVENT_VALUE);
  });

  it("keeps masking Authorization credentials without regression", () => {
    const out = redactSensitiveText("Authorization: Bearer sk-ant-ort01-abcdefghijklmnopqrstuv");
    expect(out).not.toContain("sk-ant-ort01-abcdefghijklmnopqrstuv");
    expect(out).toContain(REDACTED_EVENT_VALUE);
  });

  it("leaves ordinary text untouched", () => {
    const input = "build succeeded in 42s for feature/acc-3241";
    expect(redactSecretFamilyPatterns(input)).toBe(input);
    expect(redactSensitiveText(input)).toBe(input);
    expect(redactRunLogText(input)).toBe(input);
  });

  it("masks authorization schemes only when followed by a credential-shaped value", () => {
    const basic = "dXNlcjpodW50ZXIyc2VjcmV0"; // base64 of a synthetic user:password pair
    expect(redactSecretFamilyPatterns(`curl -H 'Authorization: Basic ${basic}'`)).not.toContain(basic);
    expect(redactSecretFamilyPatterns("X-Upstream: Token 9f8e7d6c5b4a39281706")).not.toContain("9f8e7d6c5b4a39281706");
  });

  it("leaves prose around Basic/Bearer/Token untouched, in comments and in logs", () => {
    const prose = [
      "Basic troubleshooting first. Token authentication-required is returned.",
      "Bearer authentication was rejected by the upstream.",
      "Token authentication-required came back from the provider.",
    ];
    for (const input of prose) {
      expect(redactSensitiveText(input), input).toBe(input);
      expect(redactRunLogText(input), input).toBe(input);
    }
  });

  it("keeps secret family patterns out of agent prose redaction", () => {
    const pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA";
    expect(redactRunLogText(pem)).not.toContain("b3BlbnNzaC1rZXktdjEAAAAA");
    expect(redactSensitiveText("see docs/deploy/secrets.md for the pcp_board_keys_rotation runbook"))
      .toBe("see docs/deploy/secrets.md for the pcp_board_keys_rotation runbook");
  });
});
