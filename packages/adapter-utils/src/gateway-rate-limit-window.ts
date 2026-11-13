/**
 * A gateway rate-limit window, read from the provider's own message.
 *
 * OmniRoute answers a 429 with a countdown ("... pre-dispatch filters reset
 * after 4m 28s"). The window is expressed relative to the gateway's clock, so
 * the retry must wait for it to close plus a small margin.
 *
 * Two rules keep the reading honest:
 * - the limit signal and the countdown must sit on the **same line**. A
 *   countdown quoted on another line belongs to a different subject.
 * - the signal must come from a provider surface (the error message, the
 *   parsed provider result), never from the agent's own output. An agent that
 *   writes "the other tenant's quota resets after 1h" in its stdout must not
 *   push the retry an hour out.
 */

/** Words that mark a rate-limit window on the line that carries it. */
const LIMIT_SIGNAL_RE =
  /(?:\b429\b|rate[-\s]?limit|pre-dispatch\s+filters|temporarily\s+unavailable|quota\s+exhausted)/i;

/** The countdown itself: "reset after 4m 28s", "resets in 1h 26m 15s". */
const RELATIVE_RESET_RE =
  /\bresets?\s+(?:after|in)\s+(?:(\d+)\s*h(?![a-z])\s*)?(?:(\d+)\s*m(?![a-z])\s*)?(?:(\d+)\s*s(?![a-z]))?/i;

/**
 * The countdown is rounded down to the second and measured on the gateway's
 * clock: never retry on the boundary itself.
 */
export const GATEWAY_RESET_MARGIN_MS = 30_000;

/**
 * Read the rate-limit window from one line of provider text.
 *
 * Returns the number of seconds to wait, or null when the line carries no
 * limit signal or no usable countdown.
 */
export function readGatewayRateLimitWindowSeconds(line: string): number | null {
  if (!line) return null;
  const signal = LIMIT_SIGNAL_RE.exec(line);
  if (!signal) return null;
  // Only a countdown that follows the limit signal on the same line counts.
  const countdown = RELATIVE_RESET_RE.exec(line.slice(signal.index + signal[0].length));
  if (!countdown) return null;
  const hours = Number(countdown[1] ?? 0);
  const minutes = Number(countdown[2] ?? 0);
  const seconds = Number(countdown[3] ?? 0);
  if (!hours && !minutes && !seconds) return null;
  const total = hours * 3600 + minutes * 60 + seconds;
  if (!Number.isFinite(total) || total <= 0) return null;
  return total;
}

/**
 * Read the rate-limit window from a provider text made of several lines.
 *
 * Only a line that carries both a limit signal and a countdown is used.
 * Returns the absolute deadline, or null.
 */
export function readGatewayRateLimitWindow(
  text: string | null | undefined,
  now: Date,
): Date | null {
  if (typeof text !== "string" || !text) return null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const seconds = readGatewayRateLimitWindowSeconds(line);
    if (seconds === null) continue;
    return new Date(now.getTime() + seconds * 1000 + GATEWAY_RESET_MARGIN_MS);
  }
  return null;
}

/**
 * True when the text carries a gateway rate-limit signal at all.
 *
 * Generic "rate limit" wording stays out of the *quota* reading: a typed
 * provider `limit` also covers context, turn and budget limits, which must
 * not be read as a rate window.
 */
export function isGatewayRateLimitText(text: string | null | undefined): boolean {
  return typeof text === "string" && LIMIT_SIGNAL_RE.test(text);
}
