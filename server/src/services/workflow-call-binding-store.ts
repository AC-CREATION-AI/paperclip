import { isDeepStrictEqual } from "node:util";
import { and, eq } from "drizzle-orm";
import { toolInvocations, workflowCallBindings, type Db } from "@paperclipai/db";
import type { ToolAccessDecisionInput, ToolAccessDecision } from "@paperclipai/shared";
import type { ToolApprovalClaim } from "./tool-approval-execution.js";
import { toolAccessPolicyService } from "./tool-access-policy.js";
import { canonicalizeWorkflowEnvelope, type WorkflowLimits } from "./workflow-client-v1.js";
import type { WorkflowCallBinding } from "./workflow-call-admission.js";

const unavailable = (): never => { throw new Error("workflow admission unavailable"); };
export interface WorkflowBindingAuthority {
  /** Re-resolve principal, live run, connection, grant and gateway authority in tx.
   * Return only server-derived input and the gateway's existing exact claim.
   * No dispatch, approval claiming, or external side effects in this callback.
   */
  resolve(tx: Db, binding: Readonly<WorkflowCallBinding>): Promise<{
    input: ToolAccessDecisionInput;
    claim?: ToolApprovalClaim;
  } | null>;
  /** Composed caller/target policy must use this transaction-local policy service.
   * No cached positive decisions; return false/deny by throwing or denying.
   */
  evaluate(policy: Pick<ReturnType<typeof toolAccessPolicyService>, "decide" | "writeAudit">,
    input: ToolAccessDecisionInput, invocationId: string, tx: Db): Promise<ToolAccessDecision>;
}

/** Unregistered adapter. Authority is deliberately mandatory, with no permissive default. */
export function workflowCallBindingStore(db: Db, limits: WorkflowLimits, authority: WorkflowBindingAuthority,
  nowSeconds = () => Math.floor(Date.now() / 1000)) {
  function valid(binding: WorkflowCallBinding, invocation: typeof toolInvocations.$inferSelect) {
    const now = nowSeconds();
    const envelope = JSON.parse(canonicalizeWorkflowEnvelope(binding.canonical, limits));
    return Number.isSafeInteger(now) && Number.isSafeInteger(binding.expiresAt) && binding.expiresAt > now
      && binding.canonical === canonicalizeWorkflowEnvelope(binding.canonical, limits)
      && envelope.operation === "call" && envelope.connectionId === binding.connectionId && envelope.route === binding.route
      && !!binding.assertion && !!binding.issuer && !!binding.jti && !!binding.grantId
      && invocation.id === binding.invocationId && invocation.companyId === binding.companyId
      && invocation.runId === binding.runId && !!binding.runId
      && invocation.connectionId === binding.connectionId
      && invocation.actorType === binding.owner.type && invocation.actorId === binding.owner.id
      && ["executing", "awaiting_approval"].includes(invocation.status);
  }
  async function loadBinding(invocationId: string): Promise<WorkflowCallBinding | null> {
    const [row] = await db.select().from(workflowCallBindings).where(eq(workflowCallBindings.invocationId, invocationId));
    if (!row) return null;
    const [invocation] = await db.select().from(toolInvocations).where(and(
      eq(toolInvocations.id, invocationId), eq(toolInvocations.companyId, row.companyId)));
    const binding = row.binding as unknown as WorkflowCallBinding;
    return invocation && row.issuer === binding.issuer && row.jti === binding.jti && valid(binding, invocation) ? binding : null;
  }
  async function persistBinding(binding: WorkflowCallBinding): Promise<void> {
    // Snapshot before the first await; callers cannot mutate what will be persisted.
    const snapshot = structuredClone(binding);
    await db.transaction(async tx => {
      const [invocation] = await tx.select().from(toolInvocations).where(and(
        eq(toolInvocations.id, snapshot.invocationId), eq(toolInvocations.companyId, snapshot.companyId))).for("update");
      if (!invocation || !valid(snapshot, invocation)) unavailable();
      const [existing] = await tx.select().from(workflowCallBindings)
        .where(eq(workflowCallBindings.invocationId, snapshot.invocationId)).for("update");
      if (existing) {
        if (!isDeepStrictEqual(existing.binding, snapshot)) unavailable();
        return;
      }
      await tx.insert(workflowCallBindings).values({ invocationId: snapshot.invocationId,
        companyId: snapshot.companyId, issuer: snapshot.issuer, jti: snapshot.jti,
        binding: snapshot as unknown as Record<string, unknown> });
    });
  }
  async function admitBoundCall(expected: Readonly<WorkflowCallBinding>): Promise<boolean> {
    const snapshot = Object.freeze({ ...structuredClone(expected), owner: Object.freeze({ ...expected.owner }) });
    try {
      return await db.transaction(async tx => {
        // Same invocation-first lock order as dispatch and approval admission.
        const [invocation] = await tx.select().from(toolInvocations).where(and(
          eq(toolInvocations.id, snapshot.invocationId), eq(toolInvocations.companyId, snapshot.companyId))).for("update");
        const [row] = await tx.select().from(workflowCallBindings)
          .where(eq(workflowCallBindings.invocationId, snapshot.invocationId)).for("update");
        if (!invocation || !row || row.companyId !== snapshot.companyId
          || row.issuer !== snapshot.issuer || row.jti !== snapshot.jti
          || !isDeepStrictEqual(row.binding, snapshot) || !valid(snapshot, invocation)) unavailable();
        const resolved = await authority.resolve(tx as unknown as Db, snapshot);
        if (!resolved || resolved.input.companyId !== snapshot.companyId
          || resolved.input.actor.actorType !== snapshot.owner.type || resolved.input.actor.actorId !== snapshot.owner.id
          || resolved.input.runContext?.heartbeatRunId !== snapshot.runId
          || resolved.input.request.connectionId !== snapshot.connectionId) unavailable();
        // Approval-backed calls must carry the gateway's exact execution claim.
        // admitInvocation verifies its ownership and timestamp when supplied.
        if (invocation.policyDecision === "require_approval" && !resolved.claim) unavailable();
        // Reuse invocation/claim locks and durable quota receipts, never executeTool.
        const result = await toolAccessPolicyService(tx).admitInvocation(resolved.input, snapshot.invocationId,
          resolved.claim, async (policy, input, admissionTx) => {
            const decision = await authority.evaluate(policy, input, snapshot.invocationId, admissionTx);
            if (!decision.allowed) unavailable(); // rollback even require_approval
            return decision;
          });
        if (!result.allowed || !valid(snapshot, invocation)) unavailable();
        return true; // visible to the caller only after outer commit
      });
    } catch {
      return false;
    }
  }
  return { persistBinding, loadBinding, admitBoundCall };
}
