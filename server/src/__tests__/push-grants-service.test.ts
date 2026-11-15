import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { eq } from "drizzle-orm";
import express from "express";
import request from "supertest";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  agents,
  companies,
  createDb,
  goals,
  heartbeatRuns,
  issueThreadInteractions,
  issues,
  pushGrantReceipts,
  pushGrantRepositories,
  pushGrants,
} from "@paperclipai/db";
import { errorHandler } from "../middleware/index.js";
import { pushGrantRoutes } from "../routes/push-grants.js";
import { createRuntimeToolsToken } from "../runtime-tools-token.js";
import type { PushGrantForgeClient } from "../services/push-grant-executor.js";
import { PushGrantForgeError } from "../services/push-grant-executor.js";
import { pushGrantService } from "../services/push-grants.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

const OLD = "1f602c24618f89215bf714c0b80aee3447866efd";
const NEW = "2aba7b069562445dd71316b61e5328de3bd53362";
const OTHER = "a".repeat(40);
const REPO = "AC-CREATION-AI/AC-NativeNX";
const REF = "refs/heads/fix/guards";

class FakeForge implements PushGrantForgeClient {
  head: string | null = OLD;
  pushes: Array<Record<string, unknown>> = [];
  readFails = false;
  pushError: Error | null = null;
  headAfterFailedPush: string | null | undefined = undefined;
  pushDelayMs = 0;
  async readRemoteHead() {
    if (this.readFails) throw new PushGrantForgeError("remote_unavailable", "down");
    return this.head;
  }
  async push(input: Parameters<PushGrantForgeClient["push"]>[0]) {
    if (this.pushDelayMs) await new Promise((resolve) => setTimeout(resolve, this.pushDelayMs));
    this.pushes.push(input);
    if (this.pushError) {
      if (this.headAfterFailedPush === undefined) this.readFails = true;
      else this.head = this.headAfterFailedPush;
      throw this.pushError;
    }
    this.head = input.newSha;
  }
}

describeEmbeddedPostgres("pushGrantService (ACC-4931)", () => {
  let db!: ReturnType<typeof createDb>;
  let cleanup: (() => Promise<void>) | undefined;
  let companyId!: string;
  let otherCompanyId!: string;
  let agentId!: string;
  let otherAgentId!: string;
  let parentIssueId!: string;
  let issueId!: string;
  let otherIssueId!: string;
  let goalId!: string;
  let forge!: FakeForge;
  let seq = 0;
  let workspaceRoot!: string;
  let workspaceCwd!: string;

  const service = () => pushGrantService(db, { forgeFor: () => forge, workspaceRoots: () => [workspaceRoot] });

  async function liveRun(input: { agent?: string; issue?: string; status?: string; cwd?: string | null } = {}) {
    const id = randomUUID();
    await db.insert(heartbeatRuns).values({
      id,
      companyId,
      agentId: input.agent ?? agentId,
      status: input.status ?? "running",
      contextSnapshot: {
        issueId: input.issue ?? issueId,
        ...(input.cwd === null ? {} : { paperclipWorkspace: { cwd: input.cwd ?? workspaceCwd } }),
      },
    });
    return id;
  }

  function claimsFor(runId: string, agent = agentId) {
    return { sub: agent, company_id: companyId, run_id: runId, scope: "push_grant" as const };
  }

  /** Structured agreement block (ACC-4966 H1.a); defaults match `grantInput()`. */
  function block(overrides: Record<string, unknown> = {}) {
    return JSON.stringify({
      kind: "push_grant", repository: REPO, ref: REF, mode: "force-with-lease", expectedOldSha: OLD, newSha: NEW, ...overrides,
    });
  }

  async function agreement(input: {
    issue?: string; status?: string; dismissed?: boolean; kind?: string; policy?: "human_only" | "anyone"; details?: string;
    prompt?: string; reason?: string;
  } = {}) {
    const id = randomUUID();
    await db.insert(issueThreadInteractions).values({
      id,
      companyId,
      issueId: input.issue ?? parentIssueId,
      kind: input.kind ?? "request_confirmation",
      status: input.status ?? "accepted",
      requestedResolverPolicy: input.policy ?? "human_only",
      effectiveResolverPolicy: input.policy ?? "human_only",
      resolvedByUserId: "human-user",
      dismissedAt: input.dismissed ? new Date() : null,
      payload: {
        version: 1,
        prompt: input.prompt ?? "Autorises-tu la mise à jour de la PR ?",
        detailsMarkdown: input.details ?? block(),
      } as never,
      result: input.reason === undefined ? null : { version: 1, outcome: "accepted", reason: input.reason } as never,
    });
    return id;
  }

  function grantInput(interactionId: string, overrides: Record<string, unknown> = {}) {
    seq += 1;
    return {
      issueId,
      interactionId,
      repository: REPO,
      forge: "github" as const,
      ref: REF,
      expectedOldSha: OLD,
      newSha: NEW,
      mode: "force-with-lease" as const,
      ttlSeconds: 120,
      requestId: `grant-${seq}-${randomUUID()}`,
      ...overrides,
    };
  }

  function consumeInput(overrides: Record<string, unknown> = {}) {
    seq += 1;
    return { repository: REPO, ref: REF, expectedOldSha: OLD, newSha: NEW, requestId: `consume-${seq}-${randomUUID()}`, ...overrides };
  }

  async function grantCount() {
    return (await db.select({ id: pushGrants.id }).from(pushGrants)).length;
  }

  beforeAll(async () => {
    const tempDb = await startEmbeddedPostgresTestDatabase("paperclip-push-grants-");
    cleanup = tempDb.cleanup;
    db = createDb(tempDb.connectionString);
    companyId = randomUUID();
    otherCompanyId = randomUUID();
    agentId = randomUUID();
    otherAgentId = randomUUID();
    goalId = randomUUID();
    parentIssueId = randomUUID();
    issueId = randomUUID();
    otherIssueId = randomUUID();
    await db.insert(companies).values([
      { id: companyId, name: "Push tests", issuePrefix: "PUSH", requireBoardApprovalForNewAgents: false },
      { id: otherCompanyId, name: "Other", issuePrefix: "OTHR", requireBoardApprovalForNewAgents: false },
    ]);
    await db.insert(goals).values({ id: goalId, companyId, title: "Publish", level: "task", status: "active" });
    await db.insert(agents).values([
      { id: agentId, companyId, name: "Dev", role: "engineer", status: "active", adapterType: "codex_local", adapterConfig: {}, runtimeConfig: {}, permissions: {} },
      { id: otherAgentId, companyId, name: "Other dev", role: "engineer", status: "active", adapterType: "codex_local", adapterConfig: {}, runtimeConfig: {}, permissions: {} },
    ]);
    await db.insert(issues).values({ id: parentIssueId, companyId, goalId, title: "Parent", status: "blocked", priority: "medium" });
    await db.insert(issues).values([
      { id: issueId, companyId, goalId, parentId: parentIssueId, title: "Publish heads", status: "in_progress", priority: "high", assigneeAgentId: agentId },
      { id: otherIssueId, companyId, goalId, title: "Unrelated", status: "in_progress", priority: "low", assigneeAgentId: agentId },
    ]);
    // Server-side allowlist (ACC-4966 M2): only REPO and the default-branch fixture are allowed.
    await db.insert(pushGrantRepositories).values([
      { companyId, forge: "github", repository: REPO },
      { companyId, forge: "github", repository: "AC-CREATION-AI/paperclip" },
    ]);
    workspaceRoot = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-push-grant-roots-"));
    workspaceCwd = path.join(workspaceRoot, "repo");
    await fs.mkdir(path.join(workspaceCwd, ".git", "objects", "info"), { recursive: true });
  }, 60_000);

  afterAll(async () => {
    await cleanup?.();
    if (workspaceRoot) await fs.rm(workspaceRoot, { recursive: true, force: true });
  });

  beforeEach(() => {
    forge = new FakeForge();
  });

  it("issues a ≤120 s grant from an accepted human agreement after reading the lease, then pushes exactly once", async () => {
    const runId = await liveRun();
    const interactionId = await agreement();
    const grant = await service().issue(claimsFor(runId), grantInput(interactionId, { ttlSeconds: 120 }));
    expect(new Date(grant.expiresAt).getTime() - new Date(grant.issuedAt).getTime()).toBeLessThanOrEqual(120_000);
    expect(grant.outcome).toBe("issued");
    const result = await service().consume(claimsFor(runId), grant.grantId, consumeInput());
    expect(result).toMatchObject({ status: "completed", pushed: true, outcome: "consumed", remoteHead: NEW });
    expect(forge.pushes).toHaveLength(1);
    expect(forge.pushes[0]).toMatchObject({ repository: REPO, ref: REF, expectedOldSha: OLD, newSha: NEW, mode: "force-with-lease", sourceCwd: await fs.realpath(workspaceCwd) });
    const [row] = await db.select().from(pushGrants).where(eq(pushGrants.id, grant.grantId));
    expect(row!.consumedAt).not.toBeNull();
    expect(row!.outcome).toBe("consumed");
  });

  // §7 #1
  it("refuses without an accepted agreement and issues nothing", async () => {
    const runId = await liveRun();
    const before = await grantCount();
    const pending = await agreement({ status: "pending" });
    await expect(service().issue(claimsFor(runId), grantInput(pending))).rejects.toMatchObject({ status: 403 });
    await expect(service().issue(claimsFor(runId), grantInput(randomUUID()))).rejects.toMatchObject({ status: 403 });
    const agentResolvable = await agreement({ policy: "anyone" });
    await expect(service().issue(claimsFor(runId), grantInput(agentResolvable))).rejects.toMatchObject({ status: 403 });
    const otherKind = await agreement({ kind: "ask_user_questions" });
    await expect(service().issue(claimsFor(runId), grantInput(otherKind))).rejects.toMatchObject({ status: 403 });
    const otherShas = await agreement({ details: block({ newSha: OTHER }) });
    await expect(service().issue(claimsFor(runId), grantInput(otherShas))).rejects.toMatchObject({ status: 403 });
    const unrelatedTask = await agreement({ issue: otherIssueId });
    await expect(service().issue(claimsFor(runId), grantInput(unrelatedTask))).rejects.toMatchObject({ status: 403 });
    expect(await grantCount()).toBe(before);
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #2
  it("refuses a dismissed or rejected agreement, and a withdrawn agreement at consumption", async () => {
    const runId = await liveRun();
    await expect(service().issue(claimsFor(runId), grantInput(await agreement({ dismissed: true })))).rejects.toMatchObject({ status: 403 });
    await expect(service().issue(claimsFor(runId), grantInput(await agreement({ status: "rejected" })))).rejects.toMatchObject({ status: 403 });
    const interactionId = await agreement();
    const grant = await service().issue(claimsFor(runId), grantInput(interactionId));
    await db.update(issueThreadInteractions).set({ dismissedAt: new Date() }).where(eq(issueThreadInteractions.id, interactionId));
    const result = await service().consume(claimsFor(runId), grant.grantId, consumeInput());
    expect(result).toMatchObject({ pushed: false, outcome: "rejected", errorCode: "agreement_withdrawn" });
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #3
  it("refuses an expired grant and records it as expired", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement(), { ttlSeconds: 1 }));
    const later = pushGrantService(db, { forgeFor: () => forge, workspaceRoots: () => [workspaceRoot], now: () => new Date(Date.now() + 5_000) });
    await expect(later.consume(claimsFor(runId), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 410 });
    const [row] = await db.select().from(pushGrants).where(eq(pushGrants.id, grant.grantId));
    expect(row!.outcome).toBe("expired");
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #4
  it("refuses when the forge head differs from the lease, at issue and at consumption", async () => {
    const runId = await liveRun();
    const interactionId = await agreement();
    forge.head = OTHER;
    await expect(service().issue(claimsFor(runId), grantInput(interactionId))).rejects.toMatchObject({ status: 409 });
    forge.head = OLD;
    const grant = await service().issue(claimsFor(runId), grantInput(interactionId));
    forge.head = OTHER;
    const result = await service().consume(claimsFor(runId), grant.grantId, consumeInput());
    expect(result).toMatchObject({ pushed: false, outcome: "rejected", errorCode: "lease_mismatch", remoteHead: OTHER });
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #5, #6
  it("refuses a consumption whose newSha, repository or ref differ from the grant, without spending it", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    for (const overrides of [{ newSha: OTHER }, { repository: "AC-CREATION-AI/letsgo" }, { ref: "refs/heads/main" }, { expectedOldSha: OTHER }]) {
      await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput(overrides))).rejects.toMatchObject({ status: 409 });
    }
    const [row] = await db.select().from(pushGrants).where(eq(pushGrants.id, grant.grantId));
    expect(row!.consumedAt).toBeNull();
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #8, #9
  it("replays the stored result for the same requestId and refuses a divergent reuse", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    const input = consumeInput();
    const first = await service().consume(claimsFor(runId), grant.grantId, input);
    const second = await service().consume(claimsFor(runId), grant.grantId, input);
    expect(second).toEqual(first);
    expect(forge.pushes).toHaveLength(1);
    await expect(service().consume(claimsFor(runId), grant.grantId, { ...input, newSha: OTHER }))
      .rejects.toMatchObject({ status: 409, message: "requestId was already used with different arguments." });
    await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput()))
      .rejects.toMatchObject({ status: 409 });
    expect(forge.pushes).toHaveLength(1);
  });

  it("is idempotent on the issue requestId and refuses divergent issue arguments", async () => {
    const runId = await liveRun();
    const interactionId = await agreement();
    const input = grantInput(interactionId);
    const first = await service().issue(claimsFor(runId), input);
    expect(await service().issue(claimsFor(runId), input)).toEqual(first);
    await expect(service().issue(claimsFor(runId), { ...input, mode: "fast-forward" })).rejects.toMatchObject({ status: 409 });
  });

  // §7 #10
  it("lets only one of two concurrent consumptions push", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    forge.pushDelayMs = 50;
    const results = await Promise.allSettled([
      service().consume(claimsFor(runId), grant.grantId, consumeInput()),
      service().consume(claimsFor(runId), grant.grantId, consumeInput()),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(forge.pushes).toHaveLength(1);
    const receipts = await db.select().from(pushGrantReceipts).where(eq(pushGrantReceipts.grantId, grant.grantId));
    expect(receipts).toHaveLength(1);
  });

  // §7 #11, #12
  it("records an unknown outcome when the push result cannot be read back, and never allows a retry", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    forge.pushError = new PushGrantForgeError("push_failed", "connection reset");
    const input = consumeInput();
    const result = await service().consume(claimsFor(runId), grant.grantId, input);
    expect(result).toMatchObject({ status: "unknown", pushed: false, errorCode: "push_outcome_unknown" });
    await expect(service().consume(claimsFor(runId), grant.grantId, input)).rejects.toMatchObject({ status: 409 });
    await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 409 });
    forge.readFails = false;
    expect(forge.pushes).toHaveLength(1);
  });

  it("keeps a crash-reserved receipt blocking: no new grant consumption, no replay", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    const input = consumeInput();
    await db.update(pushGrants).set({ consumedAt: new Date(), outcome: "consumed" }).where(eq(pushGrants.id, grant.grantId));
    await db.insert(pushGrantReceipts).values({
      companyId, grantId: grant.grantId, agentId, runId, requestId: input.requestId,
      argumentsHash: (await import("../services/push-grants.js")).pushGrantConsumeHash(grant.grantId, input), status: "reserved",
    });
    await expect(service().consume(claimsFor(runId), grant.grantId, input)).rejects.toMatchObject({ status: 409 });
    await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 409 });
    expect(forge.pushes).toHaveLength(0);
  });

  it("confirms a push whose transport failed but whose remote head shows the new SHA", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    forge.pushError = new PushGrantForgeError("push_failed", "timeout");
    forge.headAfterFailedPush = NEW;
    const result = await service().consume(claimsFor(runId), grant.grantId, consumeInput());
    expect(result).toMatchObject({ status: "completed", pushed: true, outcome: "consumed" });
  });

  // §7 #13
  it("fails closed when the forge cannot confirm the lease", async () => {
    const runId = await liveRun();
    forge.readFails = true;
    await expect(service().issue(claimsFor(runId), grantInput(await agreement()))).rejects.toMatchObject({ status: 503 });
    forge.readFails = false;
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    forge.readFails = true;
    const result = await service().consume(claimsFor(runId), grant.grantId, consumeInput());
    expect(result).toMatchObject({ pushed: false, outcome: "failed", errorCode: "remote_unavailable" });
    expect(forge.pushes).toHaveLength(0);
  });

  it("fails closed for Gitea in v1 and when the run has no workspace", async () => {
    const runId = await liveRun();
    await expect(service().issue(claimsFor(runId), grantInput(await agreement(), { forge: "gitea" }))).rejects.toMatchObject({ status: 422 });
    const noCwd = await liveRun({ cwd: null });
    const grant = await service().issue(claimsFor(noCwd), grantInput(await agreement()));
    const result = await service().consume(claimsFor(noCwd), grant.grantId, consumeInput());
    expect(result).toMatchObject({ pushed: false, outcome: "failed", errorCode: "source_missing" });
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #17
  it("refuses when the run is no longer running at consumption", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    await db.update(heartbeatRuns).set({ status: "succeeded" }).where(eq(heartbeatRuns.id, runId));
    await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 403 });
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #18
  it("refuses another agent or another run of the same agent", async () => {
    const runId = await liveRun();
    const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
    await db.update(issues).set({ assigneeAgentId: otherAgentId }).where(eq(issues.id, issueId));
    try {
      const otherRun = await liveRun({ agent: otherAgentId });
      await expect(service().consume(claimsFor(otherRun, otherAgentId), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 403 });
      await expect(service().consume(claimsFor(otherRun, agentId), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 403 });
    } finally {
      await db.update(issues).set({ assigneeAgentId: agentId }).where(eq(issues.id, issueId));
    }
    const sameAgentNewRun = await liveRun();
    await expect(service().consume(claimsFor(sameAgentNewRun), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 403 });
    expect(forge.pushes).toHaveLength(0);
  });

  // §7 #19
  it("refuses a grant request or consumption from another task", async () => {
    const runId = await liveRun();
    const interactionId = await agreement();
    await expect(service().issue(claimsFor(runId), grantInput(interactionId, { issueId: otherIssueId }))).rejects.toMatchObject({ status: 403 });
    const grant = await service().issue(claimsFor(runId), grantInput(interactionId));
    await db.update(heartbeatRuns).set({ contextSnapshot: { issueId: otherIssueId, paperclipWorkspace: { cwd: workspaceCwd } } })
      .where(eq(heartbeatRuns.id, runId));
    await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput())).rejects.toMatchObject({ status: 403 });
    expect(forge.pushes).toHaveLength(0);
  });

  it("refuses a non push_grant scope at the service boundary", async () => {
    const runId = await liveRun();
    await expect(service().issue({ ...claimsFor(runId), scope: "github_credentials" as never }, grantInput(await agreement())))
      .rejects.toMatchObject({ status: 403 });
  });

  // ACC-4966 H1.c — negative cases: none consumes a grant or touches the forge's push.
  describe("structured, single-use human agreement (ACC-4966 H1)", () => {
    it("#1 refuses a second grant on the same agreement after a successful consume", async () => {
      const runId = await liveRun();
      const interactionId = await agreement();
      const grant = await service().issue(claimsFor(runId), grantInput(interactionId));
      await service().consume(claimsFor(runId), grant.grantId, consumeInput());
      forge.pushes = [];
      forge.head = OLD;
      const before = await grantCount();
      await expect(service().issue(claimsFor(runId), grantInput(interactionId)))
        .rejects.toMatchObject({ status: 409, details: { code: "agreement_used" } });
      expect(await grantCount()).toBe(before);
      expect(forge.pushes).toHaveLength(0);
    });

    it("#2 refuses a rollback grant (expectedOldSha=NEW, newSha=OLD) on the same agreement", async () => {
      const runId = await liveRun();
      const interactionId = await agreement();
      const grant = await service().issue(claimsFor(runId), grantInput(interactionId));
      await service().consume(claimsFor(runId), grant.grantId, consumeInput());
      forge.pushes = [];
      const before = await grantCount();
      await expect(service().issue(claimsFor(runId), grantInput(interactionId, { expectedOldSha: NEW, newSha: OLD })))
        .rejects.toMatchObject({ status: 403 });
      expect(await grantCount()).toBe(before);
      expect(forge.pushes).toHaveLength(0);
    });

    it("#3 #4 #5 #10 refuses a request whose repository, ref, SHA direction or mode differ from the agreement", async () => {
      const runId = await liveRun();
      const interactionId = await agreement();
      const before = await grantCount();
      for (const overrides of [
        { repository: "AC-CREATION-AI/paperclip" },
        { ref: "refs/heads/fix/other" },
        { expectedOldSha: NEW, newSha: OLD },
        { mode: "fast-forward" },
      ]) {
        await expect(service().issue(claimsFor(runId), grantInput(interactionId, overrides))).rejects.toMatchObject({ status: 403 });
      }
      expect(await grantCount()).toBe(before);
      expect(forge.pushes).toHaveLength(0);
      // The agreement itself stays usable for its exact tuple.
      await expect(service().issue(claimsFor(runId), grantInput(interactionId))).resolves.toMatchObject({ outcome: "issued" });
    });

    it("#6 #7 refuses prose agreements citing both SHAs, including a refusal", async () => {
      const runId = await liveRun();
      const before = await grantCount();
      for (const details of [
        `Pousser ${REPO} ${REF} de ${OLD} vers ${NEW} en force-with-lease.`,
        `Ne pas pousser ${OLD} → ${NEW} sur ${REPO}.`,
      ]) {
        await expect(service().issue(claimsFor(runId), grantInput(await agreement({ details })))).rejects.toMatchObject({ status: 403 });
      }
      await expect(service().issue(claimsFor(runId), grantInput(await agreement({ details: "", reason: `Refusé : ne pas pousser ${OLD} ${NEW}` }))))
        .rejects.toMatchObject({ status: 403 });
      expect(await grantCount()).toBe(before);
      expect(forge.pushes).toHaveLength(0);
    });

    it("#8 refuses a block with an extra field, a missing kind, a duplicated key or surrounding prose", async () => {
      const runId = await liveRun();
      const before = await grantCount();
      const full = JSON.parse(block()) as Record<string, unknown>;
      const { kind: _kind, ...withoutKind } = full;
      for (const details of [
        block({ note: "x" }),
        JSON.stringify(withoutKind),
        block().replace("}", `,"newSha":"${OTHER}"}`),
        `Accord : ${block()}`,
        "```json\n" + block() + "\n```",
      ]) {
        await expect(service().issue(claimsFor(runId), grantInput(await agreement({ details })))).rejects.toMatchObject({ status: 403 });
      }
      expect(await grantCount()).toBe(before);
      expect(forge.pushes).toHaveLength(0);
    });

    it("#9 refuses two divergent blocks in the same agreement text", async () => {
      const runId = await liveRun();
      const before = await grantCount();
      const twoInPrompt = await agreement({ prompt: `Variante : ${block({ newSha: OTHER })}` });
      await expect(service().issue(claimsFor(runId), grantInput(twoInPrompt))).rejects.toMatchObject({ status: 403 });
      const twoInAnswer = await agreement({ reason: block({ expectedOldSha: NEW, newSha: OLD }) });
      await expect(service().issue(claimsFor(runId), grantInput(twoInAnswer))).rejects.toMatchObject({ status: 403 });
      expect(await grantCount()).toBe(before);
      expect(forge.pushes).toHaveLength(0);
    });

    it("accepts a pretty-printed block and compares SHAs and repository case-insensitively", async () => {
      const runId = await liveRun();
      const details = JSON.stringify({
        kind: "push_grant", repository: REPO.toLowerCase(), ref: REF, mode: "force-with-lease",
        expectedOldSha: OLD.toUpperCase(), newSha: NEW.toUpperCase(),
      }, null, 2);
      await expect(service().issue(claimsFor(runId), grantInput(await agreement({ details })))).resolves.toMatchObject({ outcome: "issued" });
    });

    it("keeps an agreement blocked after an unknown outcome, and reusable after a failure without external effect", async () => {
      const runId = await liveRun();
      const unknownAgreement = await agreement();
      const grant = await service().issue(claimsFor(runId), grantInput(unknownAgreement));
      forge.pushError = new PushGrantForgeError("push_failed", "connection reset");
      await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput())).resolves.toMatchObject({ status: "unknown" });
      const [row] = await db.select().from(pushGrants).where(eq(pushGrants.id, grant.grantId));
      expect(row!.outcome).toBe("unknown");
      forge.readFails = false;
      forge.pushError = null;
      forge.head = OLD;
      await expect(service().issue(claimsFor(runId), grantInput(unknownAgreement))).rejects.toMatchObject({ status: 409 });

      const failedAgreement = await agreement();
      const failed = await service().issue(claimsFor(runId), grantInput(failedAgreement));
      forge.readFails = true;
      await expect(service().consume(claimsFor(runId), failed.grantId, consumeInput())).resolves.toMatchObject({ outcome: "failed" });
      forge.readFails = false;
      await expect(service().issue(claimsFor(runId), grantInput(failedAgreement))).resolves.toMatchObject({ outcome: "issued" });
    });

    it("lets only one of two concurrent grant requests use the same agreement", async () => {
      const runId = await liveRun();
      const interactionId = await agreement();
      const results = await Promise.allSettled([
        service().issue(claimsFor(runId), grantInput(interactionId)),
        service().issue(claimsFor(runId), grantInput(interactionId)),
      ]);
      expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
      expect(results.find((result) => result.status === "rejected")).toMatchObject({ reason: { status: 409 } });
      const rows = await db.select().from(pushGrants).where(eq(pushGrants.interactionId, interactionId));
      expect(rows).toHaveLength(1);
    });
  });

  // ACC-4966 M2 — server-side repository allowlist and default-branch policy.
  describe("repository and ref policy (ACC-4966 M2)", () => {
    it("refuses a repository outside the company allowlist at issue, before any write", async () => {
      const runId = await liveRun();
      const repository = "AC-CREATION-AI/letsgo";
      const interactionId = await agreement({ details: block({ repository }) });
      const before = await grantCount();
      await expect(service().issue(claimsFor(runId), grantInput(interactionId, { repository })))
        .rejects.toMatchObject({ status: 422, details: { code: "repository_not_allowed" } });
      expect(await grantCount()).toBe(before);
    });

    it("re-checks the allowlist at consumption and leaves the grant unspent when it was withdrawn", async () => {
      const runId = await liveRun();
      const repository = "AC-CREATION-AI/allowlist-probe";
      const [entry] = await db.insert(pushGrantRepositories).values({ companyId, forge: "github", repository }).returning();
      const grant = await service().issue(claimsFor(runId), grantInput(await agreement({ details: block({ repository }) }), { repository }));
      await db.delete(pushGrantRepositories).where(eq(pushGrantRepositories.id, entry!.id));
      await expect(service().consume(claimsFor(runId), grant.grantId, consumeInput({ repository })))
        .rejects.toMatchObject({ status: 422, details: { code: "repository_not_allowed" } });
      const [row] = await db.select().from(pushGrants).where(eq(pushGrants.id, grant.grantId));
      expect(row!.consumedAt).toBeNull();
      expect(row!.outcome).toBe("issued");
      expect(forge.pushes).toHaveLength(0);
    });

    it("refuses another company's allowlist entry", async () => {
      const runId = await liveRun();
      const repository = "AC-CREATION-AI/other-company-repo";
      await db.insert(pushGrantRepositories).values({ companyId: otherCompanyId, forge: "github", repository });
      await expect(service().issue(claimsFor(runId), grantInput(await agreement({ details: block({ repository }) }), { repository })))
        .rejects.toMatchObject({ status: 422 });
    });

    it("refuses force-with-lease on main, master and trunk, and accepts a fast-forward there", async () => {
      const runId = await liveRun();
      const before = await grantCount();
      for (const ref of ["refs/heads/main", "refs/heads/master", "refs/heads/trunk"]) {
        const interactionId = await agreement({ details: block({ ref }) });
        await expect(service().issue(claimsFor(runId), grantInput(interactionId, { ref })))
          .rejects.toMatchObject({ status: 422, details: { code: "protected_ref" } });
      }
      expect(await grantCount()).toBe(before);
      const ref = "refs/heads/main";
      const fastForward = await agreement({ details: block({ ref, mode: "fast-forward" }) });
      await expect(service().issue(claimsFor(runId), grantInput(fastForward, { ref, mode: "fast-forward" })))
        .resolves.toMatchObject({ outcome: "issued", mode: "fast-forward" });
    });
  });

  // ACC-4966 B3 — the object source is confined to the instance workspace roots.
  describe("push source confinement (ACC-4966 B3)", () => {
    async function consumeFrom(cwd: string) {
      const runId = await liveRun({ cwd });
      const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
      return service().consume(claimsFor(runId), grant.grantId, consumeInput());
    }

    it("refuses a workspace whose .git is a gitdir file", async () => {
      const cwd = path.join(workspaceRoot, "gitdir-file");
      await fs.mkdir(cwd, { recursive: true });
      await fs.writeFile(path.join(cwd, ".git"), `gitdir: ${path.join(workspaceCwd, ".git")}\n`);
      await expect(consumeFrom(cwd)).resolves.toMatchObject({ pushed: false, outcome: "failed", errorCode: "source_unavailable" });
      expect(forge.pushes).toHaveLength(0);
    });

    it("refuses a workspace that borrows objects through objects/info/alternates", async () => {
      const cwd = path.join(workspaceRoot, "alternates");
      await fs.mkdir(path.join(cwd, ".git", "objects", "info"), { recursive: true });
      await fs.writeFile(path.join(cwd, ".git", "objects", "info", "alternates"), "/elsewhere/objects\n");
      await expect(consumeFrom(cwd)).resolves.toMatchObject({ pushed: false, outcome: "failed", errorCode: "source_unavailable" });
      expect(forge.pushes).toHaveLength(0);
    });

    it("refuses a workspace outside the allowed roots, including through a symlink", async () => {
      const outside = await fs.mkdtemp(path.join(os.tmpdir(), "paperclip-push-grant-outside-"));
      try {
        await fs.mkdir(path.join(outside, ".git", "objects", "info"), { recursive: true });
        await expect(consumeFrom(outside)).resolves.toMatchObject({ errorCode: "source_unavailable" });
        const link = path.join(workspaceRoot, "escape-link");
        await fs.symlink(outside, link);
        await expect(consumeFrom(link)).resolves.toMatchObject({ errorCode: "source_unavailable" });
        expect(forge.pushes).toHaveLength(0);
      } finally {
        await fs.rm(outside, { recursive: true, force: true });
      }
    });
  });

  // ACC-4966 B4 — a consume replay is answered only to the same grant, agent and run.
  describe("consume replay binding (ACC-4966 B4)", () => {
    it("refuses a replay from another run of the same agent, then from another agent, without effect", async () => {
      const runId = await liveRun();
      const grant = await service().issue(claimsFor(runId), grantInput(await agreement()));
      const input = consumeInput();
      const first = await service().consume(claimsFor(runId), grant.grantId, input);
      expect(first).toMatchObject({ pushed: true });
      const sameAgentOtherRun = await liveRun();
      await expect(service().consume(claimsFor(sameAgentOtherRun), grant.grantId, input))
        .rejects.toMatchObject({ status: 409, message: "requestId was already used." });
      await db.update(issues).set({ assigneeAgentId: otherAgentId }).where(eq(issues.id, issueId));
      try {
        const otherAgentRun = await liveRun({ agent: otherAgentId });
        await expect(service().consume(claimsFor(otherAgentRun, otherAgentId), grant.grantId, input))
          .rejects.toMatchObject({ status: 409, message: "requestId was already used." });
      } finally {
        await db.update(issues).set({ assigneeAgentId: agentId }).where(eq(issues.id, issueId));
      }
      expect(forge.pushes).toHaveLength(1);
      const receipts = await db.select().from(pushGrantReceipts).where(eq(pushGrantReceipts.grantId, grant.grantId));
      expect(receipts).toHaveLength(1);
      expect(receipts[0]).toMatchObject({ agentId, runId });
      expect(await service().consume(claimsFor(runId), grant.grantId, input)).toEqual(first);
    });
  });

  describe("HTTP routes", () => {
    const company = () => companyId;
    function app() {
      const instance = express();
      instance.use(express.json());
      instance.use("/api", pushGrantRoutes(db, { forgeFor: () => forge, workspaceRoots: () => [workspaceRoot] }));
      instance.use(errorHandler);
      return instance;
    }
    function token(runId: string, scope: "push_grant" | "github_credentials" | "connection_intents" = "push_grant", companyOverride?: string) {
      return createRuntimeToolsToken({ agentId, companyId: companyOverride ?? company(), runId, responsibleUserId: "u", scope })!.token;
    }

    beforeEach(() => {
      vi.stubEnv("PAPERCLIP_AGENT_JWT_SECRET", "push-grant-test-secret");
    });
    afterEach(() => {
      vi.useRealTimers();
      vi.unstubAllEnvs();
    });

    it("mints push_grant capabilities that expire after 120 s", () => {
      const minted = createRuntimeToolsToken({ agentId, companyId, runId: randomUUID(), responsibleUserId: "u", scope: "push_grant" })!;
      expect(new Date(minted.expiresAt).getTime() - Date.now()).toBeLessThanOrEqual(120_000);
    });

    it("issues and consumes through the routes with no-store responses", async () => {
      const runId = await liveRun();
      const interactionId = await agreement();
      const created = await request(app()).post(`/api/companies/${companyId}/push-grants`)
        .set("Authorization", `Bearer ${token(runId)}`).send(grantInput(interactionId));
      expect(created.status).toBe(201);
      expect(created.headers["cache-control"]).toBe("no-store");
      const consumed = await request(app()).post(`/api/companies/${companyId}/push-grants/${created.body.grantId}/consume`)
        .set("Authorization", `Bearer ${token(runId)}`).send(consumeInput());
      expect(consumed.status).toBe(200);
      expect(consumed.body).toMatchObject({ pushed: true, outcome: "consumed" });
    });

    // §7 #7, #14
    it("rejects invalid bodies, forbidden modes, tags and wildcards before any allocation", async () => {
      const runId = await liveRun();
      const interactionId = await agreement();
      const before = await grantCount();
      for (const body of [
        {},
        "not json",
        grantInput(interactionId, { mode: "force" }),
        grantInput(interactionId, { mode: "delete" }),
        grantInput(interactionId, { mode: "mirror" }),
        grantInput(interactionId, { ref: "refs/tags/v1" }),
        grantInput(interactionId, { ref: "refs/heads/*" }),
        grantInput(interactionId, { ref: "main" }),
        grantInput(interactionId, { newSha: "abc" }),
        grantInput(interactionId, { ttlSeconds: 121 }),
        { ...grantInput(interactionId), extra: true },
      ]) {
        const response = await request(app()).post(`/api/companies/${companyId}/push-grants`)
          .set("Authorization", `Bearer ${token(runId)}`).send(body as never);
        expect(response.status).toBeGreaterThanOrEqual(400);
        expect(response.status).toBeLessThan(500);
      }
      expect(await grantCount()).toBe(before);
      expect(forge.pushes).toHaveLength(0);
    });

    // §7 #15
    it("rejects browser headers", async () => {
      const runId = await liveRun();
      for (const [name, value] of [["Origin", "https://evil.example"], ["Cookie", "session=1"], ["Sec-Fetch-Site", "same-origin"]]) {
        const response = await request(app()).post(`/api/companies/${companyId}/push-grants`)
          .set("Authorization", `Bearer ${token(runId)}`).set(name!, value!).send(grantInput(await agreement()));
        expect(response.status).toBe(403);
      }
    });

    // §7 #16
    it("rejects missing, wrong-scope, foreign-company and expired capabilities", async () => {
      const runId = await liveRun();
      const body = grantInput(await agreement());
      const url = `/api/companies/${companyId}/push-grants`;
      expect((await request(app()).post(url).send(body)).status).toBe(401);
      expect((await request(app()).post(url).set("Authorization", `Bearer ${token(runId, "github_credentials")}`).send(body)).status).toBe(401);
      expect((await request(app()).post(url).set("Authorization", `Bearer ${token(runId, "connection_intents")}`).send(body)).status).toBe(401);
      expect((await request(app()).post(url).set("Authorization", `Bearer ${token(runId, "push_grant", otherCompanyId)}`).send(body)).status).toBe(403);
      const expired = token(runId);
      vi.useFakeTimers({ toFake: ["Date"] });
      vi.setSystemTime(new Date(Date.now() + 121_000));
      expect((await request(app()).post(url).set("Authorization", `Bearer ${expired}`).send(body)).status).toBe(401);
    });
  });
});
