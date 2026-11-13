import type { toolPolicies } from "@paperclipai/db";

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
