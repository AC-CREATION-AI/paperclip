import { createHash } from "node:crypto";
import { and, eq, inArray, or, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { companySecrets, companySecretVersions, heartbeatRuns } from "@paperclipai/db";
import { REDACTED_EVENT_VALUE, redactSecretFamilyPatterns } from "../redaction.js";
import { getSecretProvider } from "../secrets/provider-registry.js";
import type { StoredSecretVersionMaterial } from "../secrets/types.js";
import { credentialAccessConnectionNameSql } from "./credential-access-visibility.js";
import { secretService } from "./secrets.js";

const REGISTRY_KEY = "paperclipSecretRedactions";
// Project only the registry: run contexts can contain megabytes of prompt data.
const registrySnapshot = sql`jsonb_build_object('paperclipSecretRedactions', ${heartbeatRuns.contextSnapshot} -> 'paperclipSecretRedactions')`;

type RegistryEntry = {
  fingerprintSha256: string;
  material: StoredSecretVersionMaterial;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function registryEntries(contextSnapshot: unknown): RegistryEntry[] {
  const context = asRecord(contextSnapshot);
  const raw = context?.[REGISTRY_KEY];
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((value) => {
    const entry = asRecord(value);
    const material = asRecord(entry?.material);
    return typeof entry?.fingerprintSha256 === "string" && material
      ? [{ fingerprintSha256: entry.fingerprintSha256, material }]
      : [];
  });
}

function redactText(input: string, values: string[]) {
  return values.reduce(
    (result, value) => value.length > 0 ? result.split(value).join(REDACTED_EVENT_VALUE) : result,
    input,
  );
}

export function redactRegisteredSecretValues<T>(input: T, values: string[], credentialConnectionName: string | null = null): T {
  if (typeof input === "string") return redactText(input, values) as T;
  if (Array.isArray(input)) return input.map((value) => redactRegisteredSecretValues(value, values, credentialConnectionName)) as T;
  // Dates carry no redactable text; rebuilding them via Object.entries would
  // collapse them to `{}` and break every timestamp in redacted responses.
  if (input instanceof Date) return input;
  const record = asRecord(input);
  if (!record) return input;
  return Object.fromEntries(
    Object.entries(record)
      .filter(([key]) => key !== REGISTRY_KEY && key !== "nativeControllerRecovery" && key !== "nativeTaskSessionPublication")
      .map(([key, value]) => [key, key === "credentialAccess"
        ? (credentialConnectionName ? { connectionName: redactText(credentialConnectionName, values) } : {})
        : redactRegisteredSecretValues(value, values, credentialConnectionName)]),
  ) as T;
}

function mapRedactableStrings<T>(input: T, fn: (text: string) => string): T {
  if (typeof input === "string") return fn(input) as T;
  if (Array.isArray(input)) return input.map((value) => mapRedactableStrings(value, fn)) as T;
  if (input instanceof Date) return input;
  const record = asRecord(input);
  if (!record) return input;
  return Object.fromEntries(
    Object.entries(record).map(([key, value]) => [key, mapRedactableStrings(value, fn)]),
  ) as T;
}

// Candidate spans worth hashing for fingerprint matching. Label splits and
// span length are bounded so a minified JSON blob (one token, thousands of
// `:`) stays linear; quoted values inside it are still candidates.
const FINGERPRINT_CANDIDATE_MIN_LENGTH = 6;
const FINGERPRINT_CANDIDATE_MAX_LENGTH = 4096;
const FINGERPRINT_CANDIDATE_MAX_LABELS = 2;
const CANDIDATE_TOKEN_RE = /\S{6,}/g;
const CANDIDATE_QUOTED_RE = /"([^"\n]{6,})"|'([^'\n]{6,})'/g;
const CANDIDATE_LEADING_WRAP_RE = /^[("'`[{<]+/;
const CANDIDATE_TRAILING_WRAP_RE = /[)"'`\]}>,;:.]+$/;

// Shortest fragment of a known secret value worth masking on its own. Below
// this, fragments collide with ordinary log text too often to mask safely;
// whole values are still masked by the known-value pass.
const PARTIAL_SECRET_MIN_LENGTH = 24;

type Span = { start: number; end: number };

function fingerprint(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

/**
 * Candidate spans for fingerprint matching: every whitespace-delimited run,
 * its value part after each `KEY=` / `header:` label, the same without
 * wrapping quotes or trailing punctuation, and the contents of quoted strings,
 * which carry values with spaces.
 */
function candidateSpans(text: string): Array<Span & { value: string }> {
  const spans: Array<Span & { value: string }> = [];
  const push = (start: number, value: string) => {
    if (value.length >= FINGERPRINT_CANDIDATE_MIN_LENGTH && value.length <= FINGERPRINT_CANDIDATE_MAX_LENGTH) {
      spans.push({ start, end: start + value.length, value });
    }
  };
  for (const match of text.matchAll(CANDIDATE_TOKEN_RE)) {
    const token = match[0];
    const starts = [0];
    for (let index = 0; index < token.length && starts.length <= FINGERPRINT_CANDIDATE_MAX_LABELS; index += 1) {
      if (token[index] === "=" || token[index] === ":") starts.push(index + 1);
    }
    for (const offset of starts) {
      const part = token.slice(offset);
      const leading = CANDIDATE_LEADING_WRAP_RE.exec(part)?.[0].length ?? 0;
      const unwrapped = part.slice(leading).replace(CANDIDATE_TRAILING_WRAP_RE, "");
      push(match.index + offset, part);
      if (unwrapped !== part) push(match.index + offset + leading, unwrapped);
    }
  }
  for (const match of text.matchAll(CANDIDATE_QUOTED_RE)) {
    push(match.index + 1, match[1] ?? match[2]!);
  }
  return spans;
}

/** Mask spans, merging overlaps so a nested candidate never splits a mask. */
function maskSpans(text: string, spans: Span[]): string {
  if (spans.length === 0) return text;
  const ordered = [...spans].sort((left, right) => left.start - right.start || right.end - left.end);
  let out = "";
  let cursor = 0;
  for (const span of ordered) {
    if (span.end <= cursor) continue;
    out += `${text.slice(cursor, Math.max(cursor, span.start))}${REDACTED_EVENT_VALUE}`;
    cursor = span.end;
  }
  return out + text.slice(cursor);
}

/**
 * Mask candidate spans whose sha256 matches a stored secret-version
 * fingerprint (ACC-3241). The comparison is done by hash only: no secret
 * value is resolved, displayed, or logged, and a candidate that does not
 * match is left byte-identical. Only whole values match - truncated material
 * is covered by the partial-value pass and the family patterns.
 */
function redactFingerprintMatchesInText(text: string, fingerprints: ReadonlySet<string>): string {
  if (fingerprints.size === 0 || text.length === 0) return text;
  const hashed = new Map<string, boolean>();
  const spans = candidateSpans(text).filter((span) => {
    let matched = hashed.get(span.value);
    if (matched === undefined) {
      matched = fingerprints.has(fingerprint(span.value));
      hashed.set(span.value, matched);
    }
    return matched;
  });
  return maskSpans(text, spans);
}

type PartialSecretIndex = { values: string[]; windows: Set<string> };

function partialSecretIndex(values: readonly string[]): PartialSecretIndex {
  const normalized = [...new Set(values.map((value) => value.replace(/\s+/g, "")))]
    .filter((value) => value.length >= PARTIAL_SECRET_MIN_LENGTH);
  const windows = new Set<string>();
  for (const value of normalized) {
    for (let index = 0; index + PARTIAL_SECRET_MIN_LENGTH <= value.length; index += 1) {
      windows.add(value.slice(index, index + PARTIAL_SECRET_MIN_LENGTH));
    }
  }
  return { values: normalized, windows };
}

/**
 * Mask fragments of known secret values (ACC-3241 C7): debug dumps and
 * truncated reads leak a prefix of a key without ever carrying the whole
 * value, wherever it sits (`API_TOKEN=<prefix>`, `<prefix>...`, mid-line).
 * Text and values are compared whitespace-free so line-wrapped key material
 * still matches; each run of at least PARTIAL_SECRET_MIN_LENGTH characters
 * shared with a known value is masked on its original span.
 */
function redactPartialMatchesInText(text: string, index: PartialSecretIndex): string {
  if (index.windows.size === 0 || text.length < PARTIAL_SECRET_MIN_LENGTH) return text;
  const positions: number[] = [];
  const kept: string[] = [];
  for (let position = 0; position < text.length; position += 1) {
    if (/\s/.test(text[position]!)) continue;
    positions.push(position);
    kept.push(text[position]!);
  }
  const stripped = kept.join("");
  const spans: Span[] = [];
  let cursor = 0;
  while (cursor + PARTIAL_SECRET_MIN_LENGTH <= stripped.length) {
    const seed = stripped.slice(cursor, cursor + PARTIAL_SECRET_MIN_LENGTH);
    if (!index.windows.has(seed)) {
      cursor += 1;
      continue;
    }
    let length = PARTIAL_SECRET_MIN_LENGTH;
    for (const value of index.values) {
      for (let from = value.indexOf(seed); from !== -1; from = value.indexOf(seed, from + 1)) {
        let matched = PARTIAL_SECRET_MIN_LENGTH;
        while (cursor + matched < stripped.length && from + matched < value.length
          && stripped[cursor + matched] === value[from + matched]) matched += 1;
        length = Math.max(length, matched);
      }
    }
    spans.push({ start: positions[cursor]!, end: positions[cursor + length - 1]! + 1 });
    cursor += length;
  }
  return maskSpans(text, spans);
}

/**
 * Decode a JSON string body, redact the decoded text and re-encode it. A body
 * the redaction leaves unchanged keeps its original bytes. A body cut by the
 * page window may end inside an escape sequence; that tail is kept raw.
 */
function redactJsonStringBody(body: string, redact: (text: string) => string): string {
  for (let cut = body.length; cut >= Math.max(0, body.length - 6); cut -= 1) {
    let decoded: string;
    try {
      decoded = JSON.parse(`"${body.slice(0, cut)}"`) as string;
    } catch {
      continue;
    }
    const redacted = redact(decoded);
    return redacted === decoded ? body : `${JSON.stringify(redacted).slice(1, -1)}${body.slice(cut)}`;
  }
  return redact(body);
}

/** Redact every string literal of a (possibly cut) JSON record line. */
function redactJsonRecordLine(line: string, startsInString: boolean, redact: (text: string) => string): string {
  let out = "";
  let cursor = 0;
  let inString = startsInString;
  while (cursor < line.length) {
    if (!inString) {
      const quote = line.indexOf("\"", cursor);
      if (quote === -1) return out + line.slice(cursor);
      out += line.slice(cursor, quote + 1);
      cursor = quote + 1;
      inString = true;
      continue;
    }
    let end = cursor;
    while (end < line.length && line[end] !== "\"") end += line[end] === "\\" ? 2 : 1;
    end = Math.min(end, line.length);
    out += redactJsonStringBody(line.slice(cursor, end), redact);
    if (end < line.length) out += "\"";
    cursor = end + 1;
    inString = false;
  }
  return out;
}

/** A page that starts mid-record begins inside a string literal: `…text","seq":3}`. */
function startsInsideJsonString(line: string) {
  for (let index = 0; index < line.length; index += 1) {
    if (line[index] === "\\") {
      index += 1;
    } else if (line[index] === "\"") {
      return /^(?:,"|:|\})/.test(line.slice(index + 1));
    }
  }
  return false;
}

/**
 * Apply `redact` to the text a served run log actually carries (ACC-3241).
 * The log store writes NDJSON records (run-log-store.ts) whose tool output is
 * JSON-escaped inside string fields, so redaction runs on each decoded string
 * literal and the record is re-encoded, staying valid JSON. Records cut by the
 * page window (`offset` / `limitBytes`) are handled the same way. Consecutive
 * lines that are not records are redacted together as plain text, so
 * multi-line material (PEM blocks) still matches.
 */
export function redactRunLogContent(content: string, redact: (text: string) => string): string {
  const lines = content.split("\n");
  const out: string[] = [];
  let plain: string[] = [];
  const flushPlain = () => {
    if (plain.length > 0) out.push(redact(plain.join("\n")));
    plain = [];
  };
  lines.forEach((line, index) => {
    if (line.startsWith("{\"")) {
      flushPlain();
      out.push(redactJsonRecordLine(line, false, redact));
    } else if (index === 0 && startsInsideJsonString(line)) {
      out.push(redactJsonRecordLine(line, true, redact));
    } else {
      plain.push(line);
    }
  });
  flushPlain();
  return out.join("\n");
}

export function createRunSecretRedactionRegistry(db: Db) {
  const provider = getSecretProvider("local_encrypted");

  async function valuesForRuns(rows: Array<{ contextSnapshot: unknown }>) {
    const entries = rows.flatMap((row) => registryEntries(row.contextSnapshot));
    const unique = new Map(entries.map((entry) => [entry.fingerprintSha256, entry]));
    const values = await Promise.all(
      [...unique.values()].map((entry) => provider.resolveVersion({
        material: entry.material,
        externalRef: null,
      })),
    );
    return values.sort((left, right) => right.length - left.length);
  }

  async function valuesForRun(companyId: string, runId: string, viewerUserId: string | null) {
    const rows = await db.select({ contextSnapshot: registrySnapshot, credentialConnectionName: credentialAccessConnectionNameSql(viewerUserId) })
      .from(heartbeatRuns)
      .where(and(eq(heartbeatRuns.companyId, companyId), eq(heartbeatRuns.id, runId)));
    return { values: await valuesForRuns(rows), credentialConnectionName: rows[0]?.credentialConnectionName ?? null };
  }

  async function valuesForIssue(companyId: string, issueId: string) {
    const rows = await db.select({ contextSnapshot: registrySnapshot })
      .from(heartbeatRuns)
      .where(and(
        eq(heartbeatRuns.companyId, companyId),
        or(
          sql`${heartbeatRuns.contextSnapshot} ->> 'issueId' = ${issueId}`,
          sql`${heartbeatRuns.contextSnapshot} -> 'paperclipIssue' ->> 'id' = ${issueId}`,
        ),
      ));
    return valuesForRuns(rows);
  }

  // Every stored version of every company secret: a rotated, revoked or
  // deleted value printed before the change is still a leak. Only digests are
  // read, so widening the set discloses nothing.
  async function companySecretFingerprints(companyId: string): Promise<Set<string>> {
    const rows = await db.select({
      fingerprintSha256: companySecretVersions.fingerprintSha256,
      valueSha256: companySecretVersions.valueSha256,
    })
      .from(companySecretVersions)
      .innerJoin(companySecrets, eq(companySecretVersions.secretId, companySecrets.id))
      .where(eq(companySecrets.companyId, companyId));
    const fingerprints = new Set<string>();
    for (const row of rows) {
      if (row.fingerprintSha256) fingerprints.add(row.fingerprintSha256);
      if (row.valueSha256) fingerprints.add(row.valueSha256);
    }
    return fingerprints;
  }

  return {
    redactionValuesForRun: async (companyId: string, runId: string) => valuesForRuns(await db
      .select({ contextSnapshot: registrySnapshot }).from(heartbeatRuns)
      .where(and(eq(heartbeatRuns.companyId, companyId), eq(heartbeatRuns.id, runId)))),
    register: async (companyId: string, runId: string, value: string) => {
      const fingerprintSha256 = createHash("sha256").update(value).digest("hex");
      await db.transaction(async (tx) => {
        const row = await tx.select({ contextSnapshot: heartbeatRuns.contextSnapshot })
          .from(heartbeatRuns)
          .where(and(eq(heartbeatRuns.companyId, companyId), eq(heartbeatRuns.id, runId)))
          .for("update")
          .then((rows) => rows[0] ?? null);
        if (!row) throw new Error("Heartbeat run redaction registration failed");
        if (registryEntries(row.contextSnapshot).some((entry) => entry.fingerprintSha256 === fingerprintSha256)) {
          return;
        }
        const prepared = await provider.createSecret({ value });
        const entry: RegistryEntry = { fingerprintSha256, material: prepared.material };
        const contextSnapshot = asRecord(row.contextSnapshot) ?? {};
        const currentEntries = Array.isArray(contextSnapshot[REGISTRY_KEY])
          ? contextSnapshot[REGISTRY_KEY]
          : [];
        await tx.update(heartbeatRuns)
          .set({
            contextSnapshot: { ...contextSnapshot, [REGISTRY_KEY]: [...currentEntries, entry] },
            updatedAt: new Date(),
          })
          .where(and(eq(heartbeatRuns.companyId, companyId), eq(heartbeatRuns.id, runId)));
      });
    },
    redactForRuns: async <T extends { id: string }>(companyId: string, runs: T[], viewerUserId: string | null = null): Promise<T[]> => {
      if (runs.length === 0) return [];
      const rows = await db.select({ id: heartbeatRuns.id, contextSnapshot: registrySnapshot, credentialConnectionName: credentialAccessConnectionNameSql(viewerUserId) })
        .from(heartbeatRuns)
        .where(and(eq(heartbeatRuns.companyId, companyId), inArray(heartbeatRuns.id, runs.map((run) => run.id))));
      // Resolve each encrypted value once per request, but apply only each run's
      // own registry. Do not retain plaintext secrets across requests.
      const resolved = new Map<string, Promise<string>>();
      const valuesByRun = new Map(await Promise.all(rows.map(async (row) => {
        const values = await Promise.all(registryEntries(row.contextSnapshot).map((entry) => {
          let value = resolved.get(entry.fingerprintSha256);
          if (!value) {
            value = provider.resolveVersion({ material: entry.material, externalRef: null });
            resolved.set(entry.fingerprintSha256, value);
          }
          return value;
        }));
        return [row.id, { values: values.sort((a, b) => b.length - a.length), credentialConnectionName: row.credentialConnectionName ?? null }] as const;
      })));
      return runs.map((run) => {
        const disclosure = valuesByRun.get(run.id);
        return redactRegisteredSecretValues(run, disclosure?.values ?? [], disclosure?.credentialConnectionName ?? null);
      });
    },
    redactForRun: async <T>(companyId: string, runId: string, value: T, viewerUserId: string | null = null): Promise<T> => {
      const disclosure = await valuesForRun(companyId, runId, viewerUserId);
      return redactRegisteredSecretValues(value, disclosure.values, disclosure.credentialConnectionName);
    },
    /**
     * Run-log redaction (ACC-3241): masks registered values, the current
     * values of the secrets bound to the run's agent (env injection and agent
     * access), fragments of those known values, every stored company secret
     * version matched by fingerprint, and the secret family patterns. The
     * passes run on the decoded text of each NDJSON record, not on its
     * JSON-escaped form. Resolved values are request-scoped and never
     * displayed; the fingerprint pass compares sha256 digests only.
     */
    redactRunLog: async <T>(
      companyId: string,
      run: { id: string; agentId?: string | null },
      value: T,
    ): Promise<T> => {
      const [disclosure, boundValues, fingerprints] = await Promise.all([
        valuesForRun(companyId, run.id, null),
        secretService(db).resolveSecretValuesForRunRedaction(companyId, {
          agentId: run.agentId ?? null,
          runId: run.id,
        }),
        companySecretFingerprints(companyId),
      ]);
      const values = [...new Set([...disclosure.values, ...boundValues])]
        .sort((left, right) => right.length - left.length);
      const partialIndex = partialSecretIndex(values);
      const redact = (text: string) => redactSecretFamilyPatterns(redactFingerprintMatchesInText(
        redactPartialMatchesInText(redactText(text, values), partialIndex),
        fingerprints,
      ));
      return mapRedactableStrings(value, (text) => redactRunLogContent(text, redact));
    },
    redactForIssue: async <T>(companyId: string, issueId: string, value: T): Promise<T> =>
      redactRegisteredSecretValues(value, await valuesForIssue(companyId, issueId)),
  };
}
