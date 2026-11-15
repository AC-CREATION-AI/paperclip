import { createHash } from "node:crypto";
import { and, eq } from "drizzle-orm";
import {
  agents,
  heartbeatRuns,
  issueThreadInteractions,
  issues,
  pushGrantReceipts,
  pushGrants,
  type Db,
} from "@paperclipai/db";
import type { ConsumePushGrantInput, CreatePushGrantInput } from "@paperclipai/shared";
import { conflict, forbidden, HttpError, notFound, unprocessable } from "../errors.js";
import type { RuntimeToolsTokenClaims } from "../runtime-tools-token.js";
import { createGitRemoteAuthProvider } from "./git-credentials.js";
import { githubPushGrantForge, PushGrantForgeError, type PushGrantForgeClient } from "./push-grant-executor.js";
import { isLowTrustQuarantined } from "./source-trust.js";

/** Maximum lifetime of an execution grant, whatever the caller asks (ACC-3655 §6.1). */
export const PUSH_GRANT_MAX_TTL_SECONDS = 120;
const MAX_ANCESTOR_DEPTH = 32;

type PushGrantClaims = Pick<RuntimeToolsTokenClaims, "sub" | "company_id" | "run_id" | "scope">;

export type PushGrantDeps = {
  /** Forge client for a run. Defaults to the managed GitHub client. */
  forgeFor?: (context: { companyId: string; issueId: string; agentId: string; runId: string }) => PushGrantForgeClient;
  now?: () => Date;
};

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

function isUniqueViolation(error: unknown) {
  const code = (error as { code?: unknown; cause?: { code?: unknown } } | null)?.code
    ?? (error as { cause?: { code?: unknown } } | null)?.cause?.code;
  return code === "23505";
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

  /** The human agreement must still be accepted, human-only, not dismissed, and name both SHAs. */
  async function assertAgreement(input: {
    companyId: string; interactionId: string; issueId: string; expectedOldSha: string; newSha: string;
  }) {
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
    const agreed = `${text(payload?.prompt) ?? ""}\n${text(payload?.detailsMarkdown) ?? ""}`.toLowerCase();
    if (!agreed.includes(input.expectedOldSha.toLowerCase()) || !agreed.includes(input.newSha.toLowerCase())) {
      throw forbidden("The push agreement does not name this exact lease and target SHA");
    }
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
    await assertAgreement({ companyId: run.companyId, interactionId: input.interactionId, issueId, expectedOldSha, newSha });
    const forge = forgeFor({ companyId: run.companyId, issueId, agentId: run.agentId, runId: run.id });
    const remoteHead = await readLease(forge, input.repository, input.ref);
    if (remoteHead !== expectedOldSha) throw conflict("Remote head does not match expectedOldSha", { code: "lease_mismatch" });
    const issuedAt = now();
    const ttl = Math.min(input.ttlSeconds ?? PUSH_GRANT_MAX_TTL_SECONDS, PUSH_GRANT_MAX_TTL_SECONDS);
    try {
      const [grant] = await db.insert(pushGrants).values({
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
      return present(grant!);
    } catch (error) {
      if (isUniqueViolation(error)) throw conflict("requestId was already used with different arguments.");
      throw error;
    }
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
      await tx.update(pushGrants).set({ outcome: result.outcome as typeof pushGrants.$inferSelect["outcome"], updatedAt: at })
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
      if (previous.argumentsHash !== consumeHash || previous.grantId !== grantId) {
        throw conflict("requestId was already used with different arguments.");
      }
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
          grant.repository !== input.repository
          || grant.ref !== input.ref
          || grant.expectedOldSha !== input.expectedOldSha.toLowerCase()
          || grant.newSha !== input.newSha.toLowerCase()
        ) throw conflict("Request does not match the grant", { code: "grant_mismatch" });
        const at = now();
        await tx.update(pushGrants).set({ consumedAt: at, outcome: "consumed", updatedAt: at })
          .where(and(eq(pushGrants.id, grant.id), eq(pushGrants.outcome, "issued")));
        const [receipt] = await tx.insert(pushGrantReceipts).values({
          companyId: run.companyId, grantId: grant.id, requestId: input.requestId, argumentsHash: consumeHash, status: "reserved",
        }).returning({ id: pushGrantReceipts.id });
        return { grant, receiptId: receipt!.id };
      });
    } catch (error) {
      if (expired) {
        await db.update(pushGrants).set({ outcome: "expired", updatedAt: now() })
          .where(and(eq(pushGrants.id, grantId), eq(pushGrants.outcome, "issued")));
      }
      if (isUniqueViolation(error)) throw conflict("requestId was already used with different arguments.");
      throw error;
    }
    const { grant, receiptId } = claimed!;
    const base = { grantId: grant.id, requestId: input.requestId };

    // Phase 2 — side effects. The grant is spent: no path below re-opens it.
    try {
      await assertAgreement({
        companyId: run.companyId, interactionId: grant.interactionId, issueId, expectedOldSha: grant.expectedOldSha, newSha: grant.newSha,
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
    try {
      await forge.push({
        repository: grant.repository, ref: grant.ref, expectedOldSha: grant.expectedOldSha, newSha: grant.newSha,
        mode: grant.mode, sourceCwd: workspaceCwd,
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
      return finish(receiptId, grant.id, { ...base, status: "unknown", pushed: false, outcome: "failed", errorCode: "push_outcome_unknown" });
    }
    return finish(receiptId, grant.id, { ...base, status: "completed", pushed: true, outcome: "consumed", remoteHead: grant.newSha });
  }

  return { issue, consume, loadLiveRun };
}
