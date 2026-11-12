import { test, expect, vi } from "vitest";
import type { Db } from "@paperclipai/db";
import { workflowCallBindingStore, type WorkflowBindingAuthority } from "../services/workflow-call-binding-store.js";
import type { WorkflowCallBinding } from "../services/workflow-call-admission.js";
import { canonicalizeWorkflowEnvelope } from "../services/workflow-client-v1.js";

const policy = vi.hoisted(() => ({ admitInvocation: vi.fn() }));
vi.mock("../services/tool-access-policy.js", () => ({ toolAccessPolicyService: () => policy }));
const limits = { maxBytes: 4096, maxDepth: 8 };
const binding: WorkflowCallBinding = {
  invocationId: "invocation", companyId: "company", runId: "run", connectionId: "connection",
  owner: { type: "agent", id: "agent" }, grantId: "grant", route: "/rea", assertion: "signed",
  issuer: "issuer", jti: "jti", expiresAt: 120,
  canonical: canonicalizeWorkflowEnvelope(JSON.stringify({ version: 1, operation: "call", requestId: "request",
    connectionId: "connection", route: "/rea", handle: "handle", tool: "read", arguments: {} }), limits),
};
function fixture(options: { changed?: boolean; status?: string; commitFailure?: boolean; allowed?: boolean;
  approvalBacked?: boolean } = {}) {
  const invocation = { id: "invocation", companyId: "company", runId: "run", connectionId: "connection",
    actorType: "agent", actorId: "agent", status: options.status ?? "executing",
    policyDecision: options.approvalBacked ? "require_approval" : "allow",
    approvalState: options.approvalBacked ? "approved" : "not_required" };
  const row = { companyId: "company", issuer: "issuer", jti: "jti",
    binding: { ...binding, assertion: options.changed ? "changed" : binding.assertion } };
  const results = [[invocation], [row]];
  const locks: string[] = [];
  const tx = { select: () => ({ from: () => ({ where: () => ({ for: async (lock: string) => {
    locks.push(lock); return results.shift();
  } }) }) }) };
  const db = { transaction: async (fn: (tx: unknown) => Promise<unknown>) => {
    const result = await fn(tx);
    if (options.commitFailure) throw new Error("commit failed");
    return result;
  } } as unknown as Db;
  const authority = { resolve: vi.fn(async () => ({ input: { companyId: "company",
    actor: { actorType: "agent", actorId: "agent" }, runContext: { heartbeatRunId: "run" },
    request: { connectionId: "connection" } } })),
    evaluate: vi.fn(async () => ({ allowed: options.allowed ?? true })) } as unknown as WorkflowBindingAuthority;
  policy.admitInvocation.mockReset();
  policy.admitInvocation.mockImplementation(async (input, id, _claim, evaluate) => evaluate({}, input, tx));
  return { store: workflowCallBindingStore(db, limits, authority, () => 100), authority, locks };
}
test("locks invocation then binding and resolves authority before transaction-local policy", async () => {
  const f = fixture();
  expect(await f.store.admitBoundCall(binding)).toBe(true);
  expect(f.locks).toEqual(["update", "update"]);
  expect(f.authority.resolve).toHaveBeenCalledTimes(1);
  expect(policy.admitInvocation).toHaveBeenCalledTimes(1);
  expect(f.authority.evaluate).toHaveBeenCalledTimes(1);
});
test("rejects an approved approval-backed invocation without a claim before policy admission", async () => {
  const f = fixture({ approvalBacked: true });
  expect(await f.store.admitBoundCall(binding)).toBe(false);
  expect(f.authority.resolve).toHaveBeenCalledTimes(1);
  expect(policy.admitInvocation).not.toHaveBeenCalled();
  expect(f.authority.evaluate).not.toHaveBeenCalled();
});
test.each([{ changed: true }, { status: "completed" }])("rejects stale/terminal bindings before authority", async options => {
  const f = fixture(options);
  expect(await f.store.admitBoundCall(binding)).toBe(false);
  expect(f.authority.resolve).not.toHaveBeenCalled();
  expect(policy.admitInvocation).not.toHaveBeenCalled();
});
test.each([{ commitFailure: true }, { allowed: false }])("never returns positive before commit or on policy rejection", async options => {
  const f = fixture(options);
  expect(await f.store.admitBoundCall(binding)).toBe(false);
});
