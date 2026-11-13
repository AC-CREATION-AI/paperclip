import { and, eq } from "drizzle-orm";
import { toolPolicies, type Db } from "@paperclipai/db";
import type { ToolAccessDecisionInput } from "@paperclipai/shared";
import { forbidden } from "../errors.js";
import { toolAccessPolicyService } from "./tool-access-policy.js";

type Policy = typeof toolPolicies.$inferSelect;

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

function targets(value: unknown, values: unknown, expected: string): boolean {
  return (value === undefined || value === expected)
    && (values === undefined || (Array.isArray(values) && values.includes(expected)));
}

/** Only explicitly agent-and-connection-scoped argument policies opt into bounded access. */
export function isBoundedGitHubPolicy(policy: Policy, agentId: string, connectionId: string): boolean {
  const selectors = record(policy.selectors);
  const conditions = record(policy.conditions);
  const actor = record(conditions.actor);
  const scope = record(conditions.credentialScope);
  const namesAgent = selectors.agentId !== undefined || selectors.agentIds !== undefined
    || actor.agentId !== undefined || actor.agentIds !== undefined;
  const namesConnection = selectors.connectionId !== undefined || selectors.connectionIds !== undefined
    || scope.connectionId !== undefined || scope.connectionIds !== undefined;
  return policy.enabled && namesAgent && namesConnection
    && targets(selectors.agentId, selectors.agentIds, agentId)
    && targets(actor.agentId, actor.agentIds, agentId)
    && targets(selectors.connectionId, selectors.connectionIds, connectionId)
    && targets(scope.connectionId, scope.connectionIds, connectionId)
    && Object.keys(record(conditions.arguments ?? conditions.args)).length > 0;
}

export async function boundedGitHubPolicies(db: Db, companyId: string, agentId: string, connectionId: string) {
  const policies = await db.select().from(toolPolicies).where(and(
    eq(toolPolicies.companyId, companyId), eq(toolPolicies.enabled, true),
  ));
  return policies.filter(policy => isBoundedGitHubPolicy(policy, agentId, connectionId));
}

/** Raw bearer export cannot enforce argument conditions after the process receives it. */
export async function assertUnboundedGitHubCredentialExport(db: Db, companyId: string, agentId: string, connectionId: string) {
  if ((await boundedGitHubPolicies(db, companyId, agentId, connectionId)).length) {
    throw forbidden("Argument-scoped GitHub access requires governed tools; raw credentials cannot enforce repository conditions.");
  }
}

/** Recheck the actual provider arguments at dispatch, not a caller-supplied preflight receipt. */
export async function assertBoundedGitHubMutation(db: Db, input: {
  companyId: string;
  agentId: string;
  connectionId: string;
  grant: { connectionId: string; status: string; providerTenant: { github?: { userId: string; login: string } } | null };
  decisionInput: ToolAccessDecisionInput;
}) {
  const bounds = await boundedGitHubPolicies(db, input.companyId, input.agentId, input.connectionId);
  if (!bounds.length) return; // Existing unbounded consumers retain their current contract.
  if (input.decisionInput.companyId !== input.companyId
    || input.decisionInput.actor.actorType !== "agent"
    || input.decisionInput.actor.actorId !== input.agentId
    || input.decisionInput.actor.agentId !== input.agentId
    || input.decisionInput.request.connectionId !== input.connectionId) {
    throw forbidden("The bounded GitHub decision does not match this dispatch principal.");
  }
  const github = input.grant.providerTenant?.github;
  if (input.grant.status !== "active" || input.grant.connectionId !== input.connectionId
    || !github?.userId?.trim() || !github.login?.trim()) {
    throw forbidden("The bounded GitHub operation has no resolved managed identity.");
  }
  const args = record(input.decisionInput.request.arguments);
  if (typeof args.owner !== "string" || typeof args.repo !== "string"
    || !/^[A-Za-z0-9_-]+$/.test(args.owner) || !/^[A-Za-z0-9_.-]+$/.test(args.repo)
    || args.repo === "." || args.repo === "..") {
    throw forbidden("The bounded GitHub operation requires an exact owner and repository.");
  }
  const decision = await toolAccessPolicyService(db).decide({ ...input.decisionInput, consumeRateLimit: false });
  const explicitPair = bounds.some(policy => {
    const conditions = record(policy.conditions);
    const equals = record(record(conditions.arguments ?? conditions.args).fieldEquals);
    return policy.policyType === "allow" && decision.matchedPolicyIds.includes(policy.id)
      && equals.owner === args.owner && equals.repo === args.repo;
  });
  if (!decision.allowed || decision.reasonCode !== "allow_policy" || !explicitPair) {
    throw forbidden("The bounded GitHub mutation requires an explicit allow for this owner and repository.");
  }
}
