import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Db } from "@paperclipai/db";
import { assertBoundedGitHubMutation, assertUnboundedGitHubCredentialExport, isBoundedGitHubMutationCandidate } from "../services/git-broker.js";
import { classifyRisk } from "../services/tool-access/catalog/descriptors.js";
import { readFile } from "node:fs/promises";

const decide = vi.hoisted(() => vi.fn());
vi.mock("../services/tool-access-policy.js", () => ({ toolAccessPolicyService: () => ({ decide }) }));
const policy = { id: "bounded", enabled: true, policyType: "allow",
  selectors: { agentId: "agent", connectionId: "connection" },
  conditions: { arguments: { fieldEquals: { owner: "example-upstream", repo: "widgets.dev" } } } };
const database = (policies: unknown[]) => ({ select: () => ({ from: () => ({ where: async () => policies }) }) }) as unknown as Db;
const input = () => ({ companyId: "company", agentId: "agent", connectionId: "connection",
  grant: { connectionId: "connection", status: "active", providerTenant: { github: { userId: "123", login: "bot" } } },
  decisionInput: { companyId: "company", actor: { actorType: "agent" as const, actorId: "agent", agentId: "agent" },
    request: { connectionId: "connection", toolName: "create_branch", arguments: { owner: "example-upstream", repo: "widgets.dev" } } },
});
beforeEach(() => { decide.mockReset(); decide.mockResolvedValue({ allowed: true, decision: "allow", reasonCode: "allow_policy", matchedPolicyIds: ["bounded"] }); });
describe("bounded GitHub dispatch and credential boundary", () => {
  it("admits the exact pair through an explicit matched policy", async () => {
    await expect(assertBoundedGitHubMutation(database([policy]), input())).resolves.toBeUndefined();
    expect(decide).toHaveBeenCalledWith(expect.objectContaining({ consumeRateLimit: false }));
  });
  it("does not turn a broad profile allow into bounded mutation authority", async () => {
    decide.mockResolvedValue({ allowed: true, decision: "allow", reasonCode: "allow_profile", matchedPolicyIds: [] });
    await expect(assertBoundedGitHubMutation(database([policy]), input())).rejects.toThrow("explicit allow");
  });
  it("rejects a Cartesian owner/repo swap even if another policy allowed it", async () => {
    const request = input(); request.decisionInput.request.arguments.repo = "router";
    await expect(assertBoundedGitHubMutation(database([policy]), request)).rejects.toThrow("explicit allow");
  });
  it("refuses unresolved identity before policy or provider dispatch", async () => {
    const request = input(); request.grant.providerTenant.github.userId = "";
    await expect(assertBoundedGitHubMutation(database([policy]), request)).rejects.toThrow("identity");
    expect(decide).not.toHaveBeenCalled();
  });
  it("refuses unresolved owner/repo before policy or provider dispatch", async () => {
    const request = input(); request.decisionInput.request.arguments.owner = "";
    await expect(assertBoundedGitHubMutation(database([policy]), request)).rejects.toThrow("exact owner");
    expect(decide).not.toHaveBeenCalled();
  });
  it("refuses a require-approval verdict rather than dispatching", async () => {
    decide.mockResolvedValue({ allowed: false, decision: "require_approval", matchedPolicyIds: ["bounded"] });
    await expect(assertBoundedGitHubMutation(database([policy]), input())).rejects.toThrow("explicit allow");
  });
  it("never exports a bearer when argument-scoped authorization is required", async () => {
    await expect(assertUnboundedGitHubCredentialExport(database([policy]), "company", "agent", "connection")).rejects.toThrow("raw credentials");
  });
  it("leaves unrelated existing consumers unchanged", async () => {
    await expect(assertUnboundedGitHubCredentialExport(database([policy]), "company", "other-agent", "connection")).resolves.toBeUndefined();
    await expect(assertBoundedGitHubMutation(database([]), input())).resolves.toBeUndefined();
    expect(decide).not.toHaveBeenCalled();
  });
});
const fixture = JSON.parse(await readFile(new URL("./fixtures/github-consultant-policy-cases.json", import.meta.url), "utf8")) as {
  catalog: { write: string[] };
};
describe("bounded GitHub mutation candidates", () => {
  const misleading = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
  it.each(["merge_pull_request", "fork_repository", "push_files", "add_issue_comment"])(
    "treats %s as a mutation although the generic classifier calls it read", toolName => {
      expect(classifyRisk({ name: toolName }, "github")).toBe("read");
      expect(classifyRisk({ name: toolName, annotations: misleading }, "github")).toBe("read");
      expect(isBoundedGitHubMutationCandidate(toolName, classifyRisk({ name: toolName }, "github"))).toBe(true);
      expect(isBoundedGitHubMutationCandidate(toolName, classifyRisk({ name: toolName, annotations: misleading }, "github"))).toBe(true);
    });
  it("covers every reference write tool even when its catalog row is stored as read", () => {
    for (const toolName of fixture.catalog.write) expect(isBoundedGitHubMutationCandidate(toolName, "read")).toBe(true);
  });
  it("fails closed for unknown or unreviewed reads and for any escalated risk", () => {
    expect(isBoundedGitHubMutationCandidate("frobnicate_repository", "read")).toBe(true);
    expect(isBoundedGitHubMutationCandidate("run_secret_scanning", "read")).toBe(true);
    expect(isBoundedGitHubMutationCandidate("get_file_contents", "write")).toBe(true);
    expect(isBoundedGitHubMutationCandidate("get_file_contents", "read")).toBe(false);
    expect(isBoundedGitHubMutationCandidate("get_me", "read")).toBe(false);
  });
});
