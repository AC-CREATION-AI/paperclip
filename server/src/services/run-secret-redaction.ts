import { createHash } from "node:crypto";
import { and, eq, inArray, isNull, or, sql } from "drizzle-orm";
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

// Candidate spans for fingerprint and partial-value matching: bare
// value-shaped tokens and the contents of quoted strings, which carry values
// with spaces.
const FINGERPRINT_CANDIDATE_RE = /"((?:[^"\\\n]|\\.)*)"|'([^'\n]{4,})'|[A-Za-z0-9+/=_~.\-]{6,}/g;

// Shortest fragment of a known secret value worth masking on its own. Below
// this, fragments collide with ordinary log text too often to mask safely;
// whole values are still masked by the known-value pass.
const PARTIAL_SECRET_MIN_LENGTH = 24;

function fingerprint(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function candidateSpans(text: string): Array<{ start: number; end: number; value: string }> {
  const spans: Array<{ start: number; end: number; value: string }> = [];
  FINGERPRINT_CANDIDATE_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = FINGERPRINT_CANDIDATE_RE.exec(text)) !== null) {
    const quoted = match[1] ?? match[2];
    const candidate = quoted ?? match[0];
    const base = match.index + (quoted !== undefined ? 1 : 0);
    const trimmed = candidate.trim();
    for (const variant of trimmed === candidate ? [candidate] : [candidate, trimmed]) {
      if (variant.length === 0) continue;
      const offset = base + candidate.indexOf(variant);
      spans.push({ start: offset, end: offset + variant.length, value: variant });
      break;
    }
  }
  return spans;
}

function maskSpans(text: string, spans: Array<{ start: number; end: number }>): string {
  if (spans.length === 0) return text;
  const ordered = [...spans].sort((left, right) => right.start - left.start);
  let out = text;
  for (const span of ordered) {
    out = `${out.slice(0, span.start)}${REDACTED_EVENT_VALUE}${out.slice(span.end)}`;
  }
  return out;
}

/**
 * Mask candidate spans whose sha256 matches a stored secret-version
 * fingerprint (ACC-3241). The comparison is done by hash only: no secret
 * value is resolved, displayed, or logged, and a candidate that does not
 * match is left byte-identical. Only whole candidate spans match - truncated
 * material is covered by the partial-value pass and the family patterns.
 */
export function redactSecretFingerprintMatches<T>(input: T, fingerprints: ReadonlySet<string>): T {
  if (fingerprints.size === 0) return input;
  return mapRedactableStrings(input, (text) => {
    if (text.length === 0) return text;
    const spans = candidateSpans(text)
      .filter((span) => fingerprints.has(fingerprint(span.value)))
      .map(({ start, end }) => ({ start, end }));
    return maskSpans(text, spans);
  });
}

/**
 * Mask fragments of known secret values (ACC-3241 C7): debug dumps and
 * truncated reads leak a prefix of a key without ever carrying the whole
 * value, which the known-value pass cannot catch. Comparison is done on
 * whitespace-normalized copies so line-wrapped key material still matches;
 * the masked span stays the original one.
 */
export function redactPartialSecretMatches<T>(input: T, values: readonly string[]): T {
  const normalized = values
    .map((value) => value.replace(/\s+/g, ""))
    .filter((value) => value.length >= PARTIAL_SECRET_MIN_LENGTH);
  if (normalized.length === 0) return input;
  return mapRedactableStrings(input, (text) => {
    if (text.length === 0) return text;
    const spans = candidateSpans(text)
      .filter((span) => {
        if (span.value.length < PARTIAL_SECRET_MIN_LENGTH) return false;
        const stripped = span.value.replace(/\s+/g, "");
        return normalized.some((value) => value.includes(stripped));
      })
      .map(({ start, end }) => ({ start, end }));
    return maskSpans(text, spans);
  });
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

  async function activeCompanySecretFingerprints(companyId: string): Promise<Set<string>> {
    const rows = await db.select({
      fingerprintSha256: companySecretVersions.fingerprintSha256,
      valueSha256: companySecretVersions.valueSha256,
    })
      .from(companySecretVersions)
      .innerJoin(companySecrets, eq(companySecretVersions.secretId, companySecrets.id))
      .where(and(
        eq(companySecrets.companyId, companyId),
        eq(companySecrets.scope, "company"),
        eq(companySecrets.status, "active"),
        eq(companySecretVersions.status, "current"),
        isNull(companySecretVersions.revokedAt),
      ));
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
     * access), fragments of those known values, every active company secret
     * value matched by fingerprint, and the secret family patterns. Resolved
     * values are request-scoped and never displayed; the fingerprint pass
     * compares sha256 digests only.
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
        activeCompanySecretFingerprints(companyId),
      ]);
      const values = [...new Set([...disclosure.values, ...boundValues])]
        .sort((left, right) => right.length - left.length);
      const knownMasked = redactRegisteredSecretValues(value, values);
      const partialMasked = redactPartialSecretMatches(knownMasked, values);
      const fingerprintMasked = redactSecretFingerprintMatches(partialMasked, fingerprints);
      return mapRedactableStrings(fingerprintMasked, redactSecretFamilyPatterns);
    },
    redactForIssue: async <T>(companyId: string, issueId: string, value: T): Promise<T> =>
      redactRegisteredSecretValues(value, await valuesForIssue(companyId, issueId)),
  };
}
