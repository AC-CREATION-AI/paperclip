import { describe, expect, it } from "vitest";
import {
  GATEWAY_RESET_MARGIN_MS,
  readGatewayRateLimitWindow,
  readGatewayRateLimitWindowSeconds,
} from "./gateway-rate-limit-window.js";

const now = new Date("2026-11-12T17:42:30.000Z");

describe("readGatewayRateLimitWindowSeconds", () => {
  it.each([
    ["reset after 4m 28s", 268],
    ["reset after 10m", 600],
    ["reset after 1h 26m 15s", 5175],
    ["reset after 45s", 45],
    ["resets in 2h", 7200],
  ])("reads the countdown '%s'", (countdown, seconds) => {
    expect(
      readGatewayRateLimitWindowSeconds(
        `Request rejected (429) · all targets were skipped by pre-dispatch filters ${countdown}`,
      ),
    ).toBe(seconds);
  });

  it("ignores a countdown with no limit signal on its line", () => {
    expect(readGatewayRateLimitWindowSeconds("The cache will reset after 5m of inactivity.")).toBeNull();
  });

  it("ignores a limit signal with no countdown", () => {
    expect(
      readGatewayRateLimitWindowSeconds("Request rejected (429) · Service temporarily unavailable"),
    ).toBeNull();
  });

  it("ignores a countdown with no duration", () => {
    expect(
      readGatewayRateLimitWindowSeconds("Request rejected (429) · quota resets after soon"),
    ).toBeNull();
  });
});

describe("readGatewayRateLimitWindow", () => {
  it("adds the margin to the countdown", () => {
    expect(
      readGatewayRateLimitWindow(
        "Request rejected (429) · pre-dispatch filters reset after 4m 28s",
        now,
      )?.toISOString(),
    ).toBe(new Date(now.getTime() + 268_000 + GATEWAY_RESET_MARGIN_MS).toISOString());
  });

  it("requires the countdown to sit on the same line as the limit signal", () => {
    // The limit signal is on the first line; the countdown sits on the second
    // line, which carries no limit signal of its own. The countdown belongs
    // to another subject and must not delay the retry.
    const text = [
      "Request rejected (429) · Service temporarily unavailable",
      "the window closes reset after 9m 47s",
    ].join("\n");
    expect(readGatewayRateLimitWindow(text, now)).toBeNull();
  });

  it("keeps a same-line countdown when another line carries one too", () => {
    const text = [
      "Request rejected (429) · pre-dispatch filters reset after 9m 47s",
      "the other tenant's quota resets after 1h",
    ].join("\n");
    expect(readGatewayRateLimitWindow(text, now)?.toISOString()).toBe(
      new Date(now.getTime() + 587_000 + GATEWAY_RESET_MARGIN_MS).toISOString(),
    );
  });

  it("returns null for an empty or missing text", () => {
    expect(readGatewayRateLimitWindow(null, now)).toBeNull();
    expect(readGatewayRateLimitWindow("", now)).toBeNull();
    expect(readGatewayRateLimitWindow("Overloaded. Try again later.", now)).toBeNull();
  });
});
