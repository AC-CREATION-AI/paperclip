import { createHash } from "node:crypto";
import path from "node:path";
import { and, eq, notInArray, sql } from "drizzle-orm";
import {
  agents,
  heartbeatRuns,
  issueThreadInteractions,
  issues,
  pushGrantReceipts,
  pushGrantRepositories,
  pushGrants,
  type Db,
} from "@paperclipai/db";
import {
  PUSH_GRANT_PROTECTED_REFS,
  PUSH_GRANT_REUSABLE_OUTCOMES,
  pushGrantAgreementSchema,
  type ConsumePushGrantInput,
  type CreatePushGrantInput,
  type PushGrantMode,
} from "@paperclipai/shared";
import { conflict, forbidden, HttpError, notFound, unprocessable } from "../errors.js";
import { resolvePaperclipInstanceRoot } from "../home-paths.js";
import type { RuntimeToolsTokenClaims } from "../runtime-tools-token.js";
import { createGitRemoteAuthProvider } from "./git-credentials.js";
import {
  assertConfinedPushSource,
  githubPushGrantForge,
  PushGrantForgeError,
  type PushGrantForgeClient,
} from "./push-grant-executor.js";
import { isLowTrustQuarantined } from "./source-trust.js";

/** Maximum lifetime of an execution grant, whatever the caller asks (ACC-3655 §6.1). */
export const PUSH_GRANT_MAX_TTL_SECONDS = 120;
const MAX_ANCESTOR_DEPTH = 32;
const AGREEMENT_FIELDS = ["kind", "repository", "ref", "mode", "expectedOldSha", "newSha"] as const;
const AGREEMENT_MARKER_RE = /"kind"\s*:\s*"push_grant"/g;

type PushGrantClaims = Pick<RuntimeToolsTokenClaims, "sub" | "company_id" | "run_id" | "scope">;

/** Instance directories a run workspace may live in (ACC-4966 B3). */
export function defaultPushGrantWorkspaceRoots() {
  const root = resolvePaperclipInstanceRoot();
  return ["isolated-workspaces", "projects", "workspaces"].map((dir) => path.resolve(root, dir));
}

export type PushGrantDeps = {
  /** Forge client for a run. Defaults to the managed GitHub client. */
  forgeFor?: (context: { companyId: string; issueId: string; agentId: string; runId: string }) => PushGrantForgeClient;
  /** Allowed roots for the run workspace used as the object source. Defaults to the instance workspace roots. */
  workspaceRoots?: () => readonly string[];
  now?: () => Date;
};

type PushTuple = { repository: string; ref: string; mode: PushGrantMode; expectedOldSha: string; newSha: string };

export type PushGrantConsumeResult = {
  grantId: string;
  requestId: string;
  status: "completed" | "unknown";
  pushed: boolean;
  outcome: string;
  errorCode?: string;
  remoteHead?: string | null;
};

function sha256(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function text(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function record(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function serviceUnavailable(message: string) {
  return new HttpError(503, message);
}

function uniqueViolation(error: unknown): { constraint: string } | null {
  const direct = error as { code?: unknown; constraint_name?: unknown; cause?: { code?: unknown; constraint_name?: unknown } } | null;
  const source = direct?.code === "23505" ? direct : direct?.cause?.code === "23505" ? direct.cause : null;
  if (!source) return null;
  return { constraint: typeof source.constraint_name === "string" ? source.constraint_name : "" };
}

function agreementUsed() {
  return conflict("This human push agreement was already used by another grant", { code: "agreement_used" });
}

/**
 * Parse the structured agreement (ACC-4966 H1.a). The details must be one JSON
 * object and nothing else, with each field exactly once, and the agreement text
 * as a whole (prompt, details, human answer) must carry exactly one block.
 * Returns null when the agreement is not a valid structured push agreement.
 */
export function parsePushGrantAgreement(input: { prompt: string; details: string; answer: string }) {
  const details = input.details.trim();
  const markers = [input.prompt, details, input.answer]
    .reduce((count, part) => count + (part.match(AGREEMENT_MARKER_RE)?.length ?? 0), 0);
  if (markers !== 1) return null;
  if (!details.startsWith("{") || !details.endsWith("}")) return null;
  // JSON.parse keeps the last duplicate key: refuse duplicates instead of guessing.
  for (const field of AGREEMENT_FIELDS) {
    if ((details.match(new RegExp(`"${field}"\\s*:`, "g"))?.length ?? 0) !== 1) return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(details);
  } catch {
    return null;
  }
  const result = pushGrantAgreementSchema.safeParse(parsed);
  return result.success ? result.data : null;
}

function sameTuple(agreed: PushTuple, requested: PushTuple) {
  return agreed.repository.toLowerCase() === requested.repository.toLowerCase()
    && agreed.ref === requested.ref
    && agreed.mode === requested.mode
    && agreed.expectedOldSha.toLowerCase() === requested.expectedOldSha.toLowerCase()
    && agreed.newSha.toLowerCase() === requested.newSha.toLowerCase();
}

function assertRefPolicy(ref: string, mode: PushGrantMode) {
  if (mode !== "fast-forward" && (PUSH_GRANT_PROTECTED_REFS as readonly string[]).includes(ref)) {
    throw unprocessable("Only fast-forward pushes are allowed on a default branch", { code: "protected_ref" });
  }
}

export function pushGrantArgumentsHash(input: {
  issueId: string; interactionId: string; agentId: string; runId: string; repository: string;
  forge: string; ref: string; expectedOldSha: string; newSha: string; mode: string;
}) {
  return sha256([
    "push_grant.v1", input.issueId, input.interactionId, input.agentId, input.runId, input.repository,
    input.forge, input.ref, input.expectedOldSha.toLowerCase(), input.newSha.toLowerCase(), input.mode,
  ]);
}

export function pushGrantConsumeHash(grantId: string, input: ConsumePushGrantInput) {
  return sha256([
    "push_grant_consume.v1", grantId, input.repository, input.ref,
    input.expectedOldSha.toLowerCase(), input.newSha.toLowerCase(),
  ]);
}

/**
 * Server authority for bounded git publication (ACC-4931).
 *
 * Default is deny: nothing is published without an unexpired, unconsumed grant
 * tied to an accepted, human-only confirmation that names both SHAs, held by
 * the same live run and agent, and whose lease the server read on the forge.
 */
export function pushGrantService(db: Db, deps: PushGrantDeps = {}) {
  const now = deps.now ?? (() => new Date());
  const forgeFor = deps.forgeFor ?? ((context) => githubPushGrantForge(createGitRemoteAuthProvider(db, context.companyId, {
    issueId: context.issueId, heartbeatRunId: context.runId, agentId: context.agentId,
  })));
  const workspaceRoots = deps.workspaceRoots ?? defaultPushGrantWorkspaceRoots;

  /** Server-side repository allowlist (ACC-4966 M2): table `push_grant_repositories`. */
  async function assertRepositoryAllowed(companyId: string, forge: string, repository: string, executor: Pick<Db, "select"> = db) {
    const allowed = await executor.select({ id: pushGrantRepositories.id }).from(pushGrantRepositories)
      .where(and(
        eq(pushGrantRepositories.companyId, companyId),
        eq(pushGrantRepositories.forge, forge as typeof pushGrantRepositories.$inferSelect["forge"]),
        sql`lower(${pushGrantRepositories.repository}) = lower(${repository})`,
      ))
      .then((rows) => rows[0] ?? null);
    if (!allowed) throw unprocessable("This repository is not allowed for push grants", { code: "repository_not_allowed" });
  }

  async function loadLiveRun(claims: PushGrantClaims) {
    if (claims.scope !== "push_grant") throw forbidden("A push_grant runtime capability is required");
    const run = await db
      .select({
        id: heartbeatRuns.id,
        companyId: heartbeatRuns.companyId,
        agentId: heartbeatRuns.agentId,
        status: heartbeatRuns.status,
        contextSnapshot: heartbeatRuns.contextSnapshot,
        nativeIssueId: heartbeatRuns.nativeIssueId,
      })
      .from(heartbeatRuns)
      .where(eq(heartbeatRuns.id, claims.run_id))
      .then((rows) => rows[0] ?? null);
    if (!run || run.companyId !== claims.company_id || run.agentId !== claims.sub) {
      throw forbidden("Runtime capability does not match its heartbeat run");
    }
    if (run.status !== "running") throw forbidden("Runtime capability is no longer active");
    const snapshot = record(run.contextSnapshot);
    const issueId = text(snapshot?.issueId) ?? text(snapshot?.taskId) ?? run.nativeIssueId;
    if (!issueId) throw unprocessable("Push grants require a task-bound heartbeat run");
    const [issue, agent] = await Promise.all([
      db.select({
        id: issues.id, status: issues.status, assigneeAgentId: issues.assigneeAgentId, sourceTrust: issues.sourceTrust,
      }).from(issues).where(and(eq(issues.id, issueId), eq(issues.companyId, run.companyId))).then((rows) => rows[0] ?? null),
      db.select({ id: agents.id, status: agents.status }).from(agents)
        .where(and(eq(agents.id, run.agentId), eq(agents.companyId, run.companyId))).then((rows) => rows[0] ?? null),
    ]);
    if (!issue || !agent) throw notFound("Runtime task or agent was not found");
    if (issue.assigneeAgentId !== agent.id) throw forbidden("The requesting agent no longer owns this task");
    if (issue.status === "done" || issue.status === "cancelled") throw conflict("Push grants cannot be used on a closed task");
    if (isLowTrustQuarantined(issue.sourceTrust)) throw forbidden("Push grants are not available to low-trust executions");
    const workspace = record(snapshot?.paperclipWorkspace);
    return { run, issueId: issue.id, workspaceCwd: text(workspace?.cwd) };
  }

  async function isSelfOrAncestor(companyId: string, candidateIssueId: string, issueId: string) {
    let current: string | null = issueId;
    for (let depth = 0; current && depth <= MAX_ANCESTOR_DEPTH; depth += 1) {
      if (current === candidateIssueId) return true;
      const parent: { parentId: string | null } | null = await db.select({ parentId: issues.parentId }).from(issues)
        .where(and(eq(issues.id, current), eq(issues.companyId, companyId)))
        .then((rows) => rows[0] ?? null);
      current = parent?.parentId ?? null;
    }
    return false;
  }

  /**
   * The human agreement must still be accepted, human-only, not dismissed, and
   * carry one structured block equal to the requested tuple (ACC-4966 H1.a).
   */
  async function assertAgreement(input: { companyId: string; interactionId: string; issueId: string } & PushTuple) {
    const interaction = await db.select().from(issueThreadInteractions)
      .where(and(eq(issueThreadInteractions.id, input.interactionId), eq(issueThreadInteractions.companyId, input.companyId)))
      .then((rows) => rows[0] ?? null);
    if (
      !interaction
      || interaction.kind !== "request_confirmation"
      || interaction.status !== "accepted"
      || interaction.dismissedAt
      || !interaction.resolvedByUserId
      || interaction.effectiveResolverPolicy !== "human_only"
    ) throw forbidden("No accepted human push agreement covers this request");
    if (!await isSelfOrAncestor(input.companyId, interaction.issueId, input.issueId)) {
      throw forbidden("The push agreement does not belong to this task or its ancestors");
    }
    const payload = record(interaction.payload);
    const answer = record(interaction.result);
    const agreed = parsePushGrantAgreement({
      prompt: typeof payload?.prompt === "string" ? payload.prompt : "",
      details: typeof payload?.detailsMarkdown === "string" ? payload.detailsMarkdown : "",
      answer: typeof answer?.reason === "string" ? answer.reason : "",
    });
    if (!agreed) throw forbidden("The push agreement is not a single structured push_grant block");
    if (!sameTuple(agreed, input)) throw forbidden("The push agreement does not cover this exact repository, ref, mode and SHAs");
    return interaction;
  }

  async function readLease(forge: PushGrantForgeClient, repository: string, ref: string) {
    try {
      return await forge.readRemoteHead({ repository, ref });
    } catch (error) {
      if (error instanceof PushGrantForgeError && error.code === "invalid_repository") throw unprocessable(error.message);
      throw serviceUnavailable("The forge could not confirm the lease; refusing");
    }
  }

  async function issue(claims: PushGrantClaims, input: CreatePushGrantInput) {
    if (input.forge !== "github") throw unprocessable("Only GitHub repositories are supported by push grants v1");
    assertRefPolicy(input.ref, input.mode);
    const { run, issueId } = await loadLiveRun(claims);
    if (input.issueId !== issueId) throw forbidden("Push grants can only be requested for the run's own task");
    const expectedOldSha = input.expectedOldSha.toLowerCase();
    const newSha = input.newSha.toLowerCase();
    if (expectedOldSha === newSha) throw unprocessable("newSha must differ from expectedOldSha");
    const argumentsHash = pushGrantArgumentsHash({ ...input, expectedOldSha, newSha, agentId: run.agentId, runId: run.id });
    const existing = await db.select().from(pushGrants)
      .where(and(eq(pushGrants.companyId, run.companyId), eq(pushGrants.requestId, input.requestId)))
      .then((rows) => rows[0] ?? null);
    if (existing) {
      if (existing.argumentsHash !== argumentsHash) throw conflict("requestId was already used with different arguments.");
      return present(existing);
    }
    await assertRepositoryAllowed(run.companyId, input.forge, input.repository);
    await assertAgreement({
      companyId: run.companyId, interactionId: input.interactionId, issueId,
      repository: input.repository, ref: input.ref, mode: input.mode, expectedOldSha, newSha,
    });
    if (await activeGrantFor(db, input.interactionId)) throw agreementUsed();
    const forge = forgeFor({ companyId: run.companyId, issueId, agentId: run.agentId, runId: run.id });
    const remoteHead = await readLease(forge, input.repository, input.ref);
    if (remoteHead !== expectedOldSha) throw conflict("Remote head does not match expectedOldSha", { code: "lease_mismatch" });
    const issuedAt = now();
    const ttl = Math.min(input.ttlSeconds ?? PUSH_GRANT_MAX_TTL_SECONDS, PUSH_GRANT_MAX_TTL_SECONDS);
    try {
      const grant = await db.transaction(async (tx) => {
        // Same-transaction guard; the partial unique index closes the race.
        if (await activeGrantFor(tx, input.interactionId)) throw agreementUsed();
        const [row] = await tx.insert(pushGrants).values({
          companyId: run.companyId,
          issueId,
          interactionId: input.interactionId,
          agentId: run.agentId,
          runId: run.id,
          repository: input.repository,
          forge: input.forge,
          ref: input.ref,
          expectedOldSha,
          newSha,
          mode: input.mode,
          issuedAt,
          expiresAt: new Date(issuedAt.getTime() + ttl * 1000),
          outcome: "issued",
          requestId: input.requestId,
          argumentsHash,
        }).returning();
        return row!;
      });
      return present(grant);
    } catch (error) {
      const violation = uniqueViolation(error);
      if (violation?.constraint === "push_grants_active_interaction_uq") throw agreementUsed();
      if (violation) throw conflict("requestId was already used with different arguments.");
      throw error;
    }
  }

  async function activeGrantFor(executor: Pick<Db, "select">, interactionId: string) {
    return executor.select({ id: pushGrants.id }).from(pushGrants)
      .where(and(
        eq(pushGrants.interactionId, interactionId),
        notInArray(pushGrants.outcome, [...PUSH_GRANT_REUSABLE_OUTCOMES]),
      ))
      .then((rows) => rows[0] ?? null);
  }

  function present(grant: typeof pushGrants.$inferSelect) {
    return {
      grantId: grant.id,
      issueId: grant.issueId,
      interactionId: grant.interactionId,
      repository: grant.repository,
      forge: grant.forge,
      ref: grant.ref,
      expectedOldSha: grant.expectedOldSha,
      newSha: grant.newSha,
      mode: grant.mode,
      issuedAt: grant.issuedAt.toISOString(),
      expiresAt: grant.expiresAt.toISOString(),
      outcome: grant.outcome,
      requestId: grant.requestId,
    };
  }

  function storedResult(receipt: typeof pushGrantReceipts.$inferSelect): PushGrantConsumeResult {
    if (receipt.status === "reserved") throw conflict("This push is already in progress");
    if (receipt.status === "unknown") {
      throw conflict("The outcome of this push is unknown; manual reconciliation is required", {
        code: "push_outcome_unknown", grantId: receipt.grantId,
      });
    }
    return receipt.result as unknown as PushGrantConsumeResult;
  }

  async function finish(receiptId: string, grantId: string, result: PushGrantConsumeResult) {
    const at = now();
    await db.transaction(async (tx) => {
      await tx.update(pushGrantReceipts).set({
        status: result.status, result: result as unknown as Record<string, unknown>, errorCode: result.errorCode ?? null, updatedAt: at,
      }).where(eq(pushGrantReceipts.id, receiptId));
      // An unknown outcome keeps the agreement blocked: never record it as a reusable failure.
      const outcome = result.status === "unknown" ? "unknown" : result.outcome as typeof pushGrants.$inferSelect["outcome"];
      await tx.update(pushGrants).set({ outcome, updatedAt: at })
        .where(eq(pushGrants.id, grantId));
    });
    return result;
  }

  async function consume(claims: PushGrantClaims, grantId: string, input: ConsumePushGrantInput): Promise<PushGrantConsumeResult> {
    const { run, issueId, workspaceCwd } = await loadLiveRun(claims);
    const consumeHash = pushGrantConsumeHash(grantId, input);
    const previous = await db.select().from(pushGrantReceipts)
      .where(and(eq(pushGrantReceipts.companyId, run.companyId), eq(pushGrantReceipts.requestId, input.requestId)))
      .then((rows) => rows[0] ?? null);
    if (previous) {
      // A replay is only answered to the same grant, agent and run (ACC-4966 B4).
      if (previous.grantId !== grantId || previous.agentId !== run.agentId || previous.runId !== run.id) {
        throw conflict("requestId was already used.");
      }
      if (previous.argumentsHash !== consumeHash) throw conflict("requestId was already used with different arguments.");
      return storedResult(previous);
    }

    // Phase 1 — one transaction: lock, verify, mark consumed, reserve the receipt.
    let expired = false;
    let claimed: { grant: typeof pushGrants.$inferSelect; receiptId: string } | null = null;
    try {
      claimed = await db.transaction(async (tx) => {
        const [grant] = await tx.select().from(pushGrants)
          .where(and(eq(pushGrants.id, grantId), eq(pushGrants.companyId, run.companyId)))
          .for("update");
        if (!grant) throw notFound("Push grant not found");
        if (grant.agentId !== run.agentId || grant.runId !== run.id) throw forbidden("This grant belongs to another agent or run");
        if (grant.issueId !== issueId) throw forbidden("This grant belongs to another task");
        if (grant.consumedAt || grant.outcome !== "issued") throw conflict("Push grant was already consumed", { code: "grant_consumed" });
        if (grant.revokedAt) throw forbidden("Push grant was revoked");
        if (grant.expiresAt.getTime() <= now().getTime()) {
          expired = true;
          throw new HttpError(410, "Push grant expired");
        }
        if (
          grant.repository.toLowerCase() !== input.repository.toLowerCase()
          || grant.ref !== input.ref
          || grant.expectedOldSha !== input.expectedOldSha.toLowerCase()
          || grant.newSha !== input.newSha.toLowerCase()
        ) throw conflict("Request does not match the grant", { code: "grant_mismatch" });
        assertRefPolicy(grant.ref, grant.mode);
        await assertRepositoryAllowed(run.companyId, grant.forge, grant.repository, tx);
        const at = now();
        await tx.update(pushGrants).set({ consumedAt: at, outcome: "consumed", updatedAt: at })
          .where(and(eq(pushGrants.id, grant.id), eq(pushGrants.outcome, "issued")));
        const [receipt] = await tx.insert(pushGrantReceipts).values({
          companyId: run.companyId, grantId: grant.id, agentId: run.agentId, runId: run.id,
          requestId: input.requestId, argumentsHash: consumeHash, status: "reserved",
        }).returning({ id: pushGrantReceipts.id });
        return { grant, receiptId: receipt!.id };
      });
    } catch (error) {
      if (expired) {
        await db.update(pushGrants).set({ outcome: "expired", updatedAt: now() })
          .where(and(eq(pushGrants.id, grantId), eq(pushGrants.outcome, "issued")));
      }
      if (uniqueViolation(error)) throw conflict("requestId was already used with different arguments.");
      throw error;
    }
    const { grant, receiptId } = claimed!;
    const base = { grantId: grant.id, requestId: input.requestId };

    // Phase 2 — side effects. The grant is spent: no path below re-opens it.
    try {
      await assertAgreement({
        companyId: run.companyId, interactionId: grant.interactionId, issueId,
        repository: grant.repository, ref: grant.ref, mode: grant.mode, expectedOldSha: grant.expectedOldSha, newSha: grant.newSha,
      });
    } catch {
      return finish(receiptId, grant.id, { ...base, status: "completed", pushed: false, outcome: "rejected", errorCode: "agreement_withdrawn" });
    }
    const forge = forgeFor({ companyId: run.companyId, issueId, agentId: run.agentId, runId: run.id });
    let before: string | null;
    try {
      before = await forge.readRemoteHead({ repository: grant.repository, ref: grant.ref });
    } catch {
      return finish(receiptId, grant.id, { ...base, status: "completed", pushed: false, outcome: "failed", errorCode: "remote_unavailable" });
    }
    if (before !== grant.expectedOldSha) {
      return finish(receiptId, grant.id, {
        ...base, status: "completed", pushed: false, outcome: "rejected", errorCode: "lease_mismatch", remoteHead: before,
      });
    }
    if (!workspaceCwd) {
      return finish(receiptId, grant.id, { ...base, status: "completed", pushed: false, outcome: "failed", errorCode: "source_missing" });
    }
    let sourceCwd: string;
    try {
      sourceCwd = await assertConfinedPushSource(workspaceCwd, workspaceRoots());
    } catch {
      return finish(receiptId, grant.id, { ...base, status: "completed", pushed: false, outcome: "failed", errorCode: "source_unavailable" });
    }
    try {
      await forge.push({
        repository: grant.repository, ref: grant.ref, expectedOldSha: grant.expectedOldSha, newSha: grant.newSha,
        mode: grant.mode, sourceCwd,
      });
    } catch (error) {
      const code = error instanceof PushGrantForgeError ? error.code : "push_failed";
      if (code === "source_missing" || code === "not_fast_forward" || code === "invalid_repository") {
        return finish(receiptId, grant.id, { ...base, status: "completed", pushed: false, outcome: "failed", errorCode: code });
      }
      // The remote may or may not have applied the update: read back once.
      let after: string | null | undefined;
      try { after = await forge.readRemoteHead({ repository: grant.repository, ref: grant.ref }); } catch { after = undefined; }
      if (after === grant.newSha) {
        return finish(receiptId, grant.id, { ...base, status: "completed", pushed: true, outcome: "consumed", remoteHead: after });
      }
      if (after === grant.expectedOldSha) {
        return finish(receiptId, grant.id, { ...base, status: "completed", pushed: false, outcome: "failed", errorCode: "push_failed", remoteHead: after });
      }
      return finish(receiptId, grant.id, { ...base, status: "unknown", pushed: false, outcome: "unknown", errorCode: "push_outcome_unknown" });
    }
    return finish(receiptId, grant.id, { ...base, status: "completed", pushed: true, outcome: "consumed", remoteHead: grant.newSha });
  }

  return { issue, consume, loadLiveRun };
}
