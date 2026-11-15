import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { and, eq } from "drizzle-orm";
import { agents, companies, createDb, heartbeatRuns, issues, issueRecoveryActions, type Db } from "@paperclipai/db";
import { getEmbeddedPostgresTestSupport, startEmbeddedPostgresTestDatabase } from "../__tests__/helpers/embedded-postgres.js";
import { conversationRecoveryActionPredicate, getConversationOwnershipBlocker, isConversationAdapter } from "./conversation-continuation.js";
import { legacyControllerBootId } from "./legacy-controller-lease.js";
import { deliverExecutionStatuses } from "./execution-status-delivery.js";

const support = await getEmbeddedPostgresTestSupport();
const describePostgres = support.supported ? describe : describe.skip;
if (!support.supported) console.warn(`Skipping execution identity regressions: ${support.reason}`);

describePostgres("execution identity query contracts", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let db: Db;
  beforeAll(async () => { database = await startEmbeddedPostgresTestDatabase("execution-identity-"); db = createDb(database.connectionString); }, 20_000);
  afterAll(async () => { await db?.$client.end({ timeout: 0 }); await database?.cleanup(); });
  async function fixture() {
    const companyId = randomUUID(), agentId = randomUUID(), issueId = randomUUID(), otherIssueId = randomUUID();
    await db.insert(companies).values({ id: companyId, name: "Identity", issuePrefix: `I${companyId.slice(0, 7)}` });
    await db.insert(agents).values({ id: agentId, companyId, name: "Fixture", adapterType: "codex_local" });
    await db.insert(issues).values([{ id: issueId, companyId, title: "Target" }, { id: otherIssueId, companyId, title: "Other" }]);
    return { companyId, agentId, issueId, otherIssueId };
  }
  async function run(f: Awaited<ReturnType<typeof fixture>>, context: Record<string, unknown> | null, nativeIssueId: string | null = null, pid: number | null = null) {
    const [row] = await db.insert(heartbeatRuns).values({ companyId: f.companyId, agentId: f.agentId, nativeIssueId,
      status: "interrupted", runtimeMode: "legacy", contextSnapshot: context, processPid: pid,
      runnerProfileJson: { adapterDispatch: { adapterType: "codex_local" } } }).returning();
    return row;
  }
  it("matches only canonical evidence IDs and keeps source issue and company scope", async () => {
    const f = await fixture(), foreign = await fixture();
    const ours = await run(f, { issueId: f.issueId });
    const elsewhere = await run(f, { issueId: f.otherIssueId });
    const foreignRun = await run(foreign, { issueId: f.issueId });
    const ids: unknown[] = [ours.id, ours.id.toUpperCase(), ours.id.replaceAll("-", ""), `{${ours.id}}`, "bad", "", null, 42, {}, [ours.id], elsewhere.id, foreignRun.id];
    const actions = await db.insert(issueRecoveryActions).values(ids.map((runId, index) => ({
      companyId: f.companyId, sourceIssueId: f.issueId, kind: "active_run_watchdog", status: "resolved", ownerType: "board",
      cause: "legacy_execution_requires_reconciliation", fingerprint: `fixture-${index}`, evidence: { runId }, nextAction: "Fixture",
    }))).returning();
    const matches = await db.select({ id: issueRecoveryActions.id }).from(issueRecoveryActions)
      .where(and(eq(issueRecoveryActions.companyId, f.companyId), conversationRecoveryActionPredicate()));
    expect(matches).toEqual([{ id: actions[0].id }]);
  });
  it("preserves native issue precedence and does not broaden legacy spellings", async () => {
    const f = await fixture();
    await run(f, { issueId: f.issueId }, f.otherIssueId, process.pid);
    const uppercase = await run(f, { issueId: f.issueId.toUpperCase() }, null, process.pid);
    const malformed = await run(f, { issueId: "bad" }, null, process.pid);
    expect(await getConversationOwnershipBlocker(db, f.companyId, f.issueId)).toBeNull();
    const native = await run(f, { issueId: f.otherIssueId }, f.issueId, process.pid);
    expect(await getConversationOwnershipBlocker(db, f.companyId, f.issueId)).toMatchObject({ runId: native.id, cause: "execution_owner_active" });
    expect(await getConversationOwnershipBlocker(db, f.companyId, f.issueId.toUpperCase())).toMatchObject({ runId: uppercase.id });
    expect(await getConversationOwnershipBlocker(db, f.companyId, "bad")).toMatchObject({ runId: malformed.id });
  });
  it("retains legacy ownership holds and releases only after ownership ends", async () => {
    const f = await fixture();
    const legacy = await run(f, { issueId: f.issueId }, null, process.pid);
    expect(await getConversationOwnershipBlocker(db, f.companyId, f.issueId)).toMatchObject({ runId: legacy.id });
    await db.update(heartbeatRuns).set({ processPid: null }).where(eq(heartbeatRuns.id, legacy.id));
    expect(await getConversationOwnershipBlocker(db, f.companyId, f.issueId)).toBeNull();
  });
  // ACC-4454: the in-process OmniRoute adapter accepts a conversation turn and
  // has no PID. Its abnormal ends must fold like other conversation adapters
  // instead of leaving a permanent replay=blocked hold. Webhooks stay held.
  it("folds in-process omniroute_native holds and keeps webhook adapters held", async () => {
    const f = await fixture();
    const cases = [
      { adapterType: "omniroute_native", status: "cancelled", errorCode: "cancelled",
        resultJson: { executionCancellation: { state: "acknowledged" } }, folds: true },
      { adapterType: "omniroute_native", status: "failed", errorCode: "omniroute_output_truncated",
        resultJson: { conversationContinuation: "continue_conversation_v1" }, folds: true },
      { adapterType: "omniroute_native", status: "failed", errorCode: "process_lost", resultJson: {}, folds: true },
      { adapterType: "http", status: "failed", errorCode: "process_lost", resultJson: {}, folds: false },
      // Stop proof: a lease the controller did not clear still holds unless it
      // expired under another boot. This boot may still be running the call.
      { adapterType: "omniroute_native", status: "failed", errorCode: "process_lost", resultJson: {},
        bootId: legacyControllerBootId, leaseMs: 60_000, folds: false },
      { adapterType: "omniroute_native", status: "failed", errorCode: "process_lost", resultJson: {},
        bootId: legacyControllerBootId, leaseMs: -60_000, folds: false },
      { adapterType: "omniroute_native", status: "failed", errorCode: "process_lost", resultJson: {},
        bootId: randomUUID(), leaseMs: 60_000, folds: false },
      { adapterType: "omniroute_native", status: "failed", errorCode: "process_lost", resultJson: {},
        bootId: randomUUID(), leaseMs: -60_000, folds: true },
      { adapterType: "omniroute_native", status: "cancelled", errorCode: "cancelled",
        resultJson: { executionCancellation: { state: "acknowledged" } }, bootId: legacyControllerBootId, leaseMs: null, folds: true },
      // PID-based adapters keep their existing contract; the lease is not their stop proof.
      { adapterType: "codex_local", status: "failed", errorCode: "process_lost", resultJson: {},
        bootId: legacyControllerBootId, leaseMs: 60_000, folds: true },
    ];
    const expected: string[] = [];
    for (const [index, item] of cases.entries()) {
      const [row] = await db.insert(heartbeatRuns).values({ companyId: f.companyId, agentId: f.agentId,
        status: item.status, errorCode: item.errorCode, runtimeMode: "legacy", contextSnapshot: { issueId: f.issueId },
        resultJson: item.resultJson, runnerProfileJson: { adapterDispatch: { adapterType: item.adapterType } },
        controllerBootId: "bootId" in item ? item.bootId : null,
        controllerLeaseExpiresAt: "leaseMs" in item && item.leaseMs != null ? new Date(Date.now() + item.leaseMs) : null }).returning();
      const [action] = await db.insert(issueRecoveryActions).values({ companyId: f.companyId, sourceIssueId: f.issueId,
        kind: "active_run_watchdog", status: "resolved", outcome: "blocked", ownerType: "board",
        cause: "legacy_execution_requires_reconciliation", fingerprint: `omniroute-${index}`,
        evidence: { runId: row.id, automaticRecovery: { policy: "preserve_without_replay_v1", replay: "blocked" } },
        nextAction: "Fixture" }).returning();
      if (item.folds) expected.push(action.id);
    }
    const matches = await db.select({ id: issueRecoveryActions.id }).from(issueRecoveryActions)
      .where(and(eq(issueRecoveryActions.companyId, f.companyId), conversationRecoveryActionPredicate()));
    expect(matches.map(m => m.id).sort()).toEqual(expected.sort());
    // No PID and no lease: a terminal in-process run owns nothing after it settled.
    expect(await getConversationOwnershipBlocker(db, f.companyId, f.issueId)).toBeNull();
    expect(isConversationAdapter("omniroute_native")).toBe(true);
    expect(isConversationAdapter("http")).toBe(false);
  });
  it("delivers canonical same-company task IDs and keeps malformed IDs private", async () => {
    const f = await fixture(), foreign = await fixture();
    const contexts: unknown[] = [f.issueId, f.issueId.toUpperCase(), "bad", `{${f.issueId}}`, f.issueId.replaceAll("-", ""), null, 42, {}, [f.issueId], foreign.issueId];
    const expected = new Map<string, string | null>();
    for (const [index, issueId] of contexts.entries()) {
      const row = await run(f, { issueId });
      await db.update(heartbeatRuns).set({ executionStatusDeliveryId: randomUUID() }).where(eq(heartbeatRuns.id, row.id));
      expected.set(row.id, index === 0 ? f.issueId : null);
    }
    const native = await run(f, { issueId: f.otherIssueId }, f.issueId);
    await db.update(heartbeatRuns).set({ executionStatusDeliveryId: randomUUID() }).where(eq(heartbeatRuns.id, native.id));
    expected.set(native.id, f.issueId);
    const seen = new Map<string, string | null>();
    const result = await deliverExecutionStatuses(db, { publish: event => { seen.set(event.payload!.runId as string, event.payload!.issueId as string | null); return { ...event, id: 0, payload: event.payload ?? {}, createdAt: new Date().toISOString() }; } });
    expect(result.delivered).toBe(expected.size);
    expect(seen).toEqual(expected);
    expect(await deliverExecutionStatuses(db, { publish: () => { throw new Error("duplicate delivery"); } })).toEqual({ scanned: 0, delivered: 0 });
  });
});
