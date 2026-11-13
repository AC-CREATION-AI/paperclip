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

// Reviewed read-only tools of the GitHub MCP server. The bounded broker does not
// trust provider annotations or the generic verb classifier: GitHub has no
// reviewed classifier, so merge/fork/push/comment tools may be stored as `read`.
// Anything not listed here, including unknown or renamed tools, is a mutation.
const REVIEWED_GITHUB_READ_TOOLS = new Set([
  "get_me", "get_teams", "get_team_members",
  "get_file_contents", "get_commit", "list_commits", "list_branches", "list_tags", "get_tag",
  "list_releases", "get_latest_release", "get_release_by_tag",
  "get_issue", "get_issue_comments", "issue_read", "list_issues", "list_issue_fields", "list_issue_types", "list_sub_issues",
  "get_pull_request", "get_pull_request_comments", "get_pull_request_diff", "get_pull_request_files",
  "get_pull_request_reviews", "get_pull_request_status", "list_pull_requests", "pull_request_read",
  "list_repository_collaborators", "search_code", "search_commits", "search_issues", "search_orgs", "search_pull_requests", "search_repositories", "search_users",
  "list_notifications", "get_notification_details",
  "actions_get", "actions_list", "list_workflows", "list_workflow_runs", "get_workflow_run", "get_workflow_run_usage", "list_workflow_jobs",
  "get_job_logs", "list_workflow_run_artifacts",
  "list_code_scanning_alerts", "get_code_scanning_alert", "list_secret_scanning_alerts",
  "get_secret_scanning_alert", "list_dependabot_alerts", "get_dependabot_alert",
  "list_discussions", "get_discussion", "get_discussion_comments", "list_discussion_categories",
  "list_gists", "list_starred_repositories", "list_label", "get_label",
]);

/** Fail closed: a stored or annotated `read` alone never exempts a GitHub tool from the bounded broker. */
export function isBoundedGitHubMutationCandidate(toolName: string, riskLevel: string | null | undefined): boolean {
  return riskLevel !== "read" || !REVIEWED_GITHUB_READ_TOOLS.has(toolName);
}
