import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Db } from "@paperclipai/db";
import { assertBoundedGitHubMutation, assertUnboundedGitHubCredentialExport } from "../services/git-broker.js";

const decide = vi.hoisted(() => vi.fn());
vi.mock("../services/tool-access-policy.js", () => ({ toolAccessPolicyService: () => ({ decide }) }));
const policy = { id: "bounded", enabled: true, policyType: "allow",
  selectors: { agentId: "agent", connectionId: "connection" },
  conditions: { arguments: { fieldEquals: { owner: "anomalyco", repo: "models.dev" } } } };
const database = (policies: unknown[]) => ({ select: () => ({ from: () => ({ where: async () => policies }) }) }) as unknown as Db;
const input = () => ({ companyId: "company", agentId: "agent", connectionId: "connection",
  grant: { connectionId: "connection", status: "active", providerTenant: { github: { userId: "123", login: "bot" } } },
  decisionInput: { companyId: "company", actor: { actorType: "agent" as const, actorId: "agent", agentId: "agent" },
    request: { connectionId: "connection", toolName: "create_branch", arguments: { owner: "anomalyco", repo: "models.dev" } } },
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
    const request = input(); request.decisionInput.request.arguments.repo = "OmniRoute";
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
