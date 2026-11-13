import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  agents,
  connectionGrants,
  createDb,
  toolCatalogEntries,
  toolConnectionInstalls,
  toolConnections,
  toolInvocations,
  toolPolicies,
  toolProfileBindings,
  toolProfiles,
} from "@paperclipai/db";
import type { ToolAccessDecisionInput } from "@paperclipai/shared";
import { assertBoundedGitHubMutation } from "../services/git-broker.js";
import {
  resolveManagedGitHubCredential,
  resolveManagedGitHubIdentitySelection,
} from "../services/git-credentials.js";
import { secretService } from "../services/secrets.js";
import { toolAccessPolicyService } from "../services/tool-access-policy.js";
import { createToolGatewayService } from "../services/tool-gateway.js";
import { githubCredentialsFixture } from "./helpers/github-credentials-fixture.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

// Only credential values are synthetic. Identity selection, policy persistence,
// policy decisions, the broker guard and gateway dispatch all use real services.
// Import services directly: the boundary unit suite mocks the policy engine.
const vault = vi.hoisted(() => ({
  resolveUserSecretValue: vi.fn(async (_companyId: string, input: { responsibleUserId: string }) => ({
    value: `test-personal-token-${input.responsibleUserId}`,
  })),
  resolveSecretValue: vi.fn(async () => "test-dedicated-token"),
}));
vi.mock("../services/secrets.js", () => ({ secretService: () => vault }));

const support = await getEmbeddedPostgresTestSupport();
if (!support.supported) console.warn(`Skipping ACC-4308 GitHub broker integration: ${support.reason}`);

// Never borrow DATABASE_URL or an external credential-test database. The standard
// helper creates a unique disposable cluster/database and owns its cleanup.
(support.supported ? describe : describe.skip)("ACC-4308 GitHub broker database integration", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | undefined;
  let db: ReturnType<typeof createDb>;
  const { seed, grant } = githubCredentialsFixture(() => db);
  type Seed = Awaited<ReturnType<typeof seed>>;
  type Grant = Awaited<ReturnType<typeof grant>>;
  const pairs = [
    { owner: "anomalyco", repo: "models.dev" },
    { owner: "cheaper-inference", repo: "OmniRoute" },
  ];

  beforeAll(async () => {
    database = await startEmbeddedPostgresTestDatabase("paperclip-github-broker-integration-");
    db = createDb(database.connectionString);
  }, 90_000);
  afterAll(async () => {
    try { await db?.$client.end({ timeout: 1 }); }
    finally { await database?.cleanup(); }
  }, 60_000);
  beforeEach(() => { vi.clearAllMocks(); });

  function credential(input: Seed) {
    return resolveManagedGitHubCredential(db, secretService(db), input.companyId, {
      agentId: input.agentId,
      responsibleUserId: "A",
    });
  }

  async function bound(input: Seed, selected: Grant) {
    return db.insert(toolPolicies).values(pairs.map((pair) => ({
      companyId: input.companyId,
      name: `Allow create_branch ${pair.owner}/${pair.repo}`,
      policyType: "allow" as const,
      selectors: { agentId: input.agentId, connectionId: selected.connectionId, toolName: "create_branch" },
      conditions: { arguments: { fieldEquals: pair } },
    }))).returning();
  }

  function decisionInput(input: Seed, selected: Grant, args: Record<string, unknown>): ToolAccessDecisionInput {
    return {
      companyId: input.companyId,
      actor: { actorType: "agent", actorId: input.agentId, agentId: input.agentId },
      request: { connectionId: selected.connectionId, toolName: "create_branch", riskLevel: "write", arguments: args },
      consumeRateLimit: false,
      writeAuditEvent: false,
    };
  }

  async function mutation(input: Seed, selected: Grant, args: Record<string, unknown>) {
    // Use the actual persisted grant, including live status changes, rather than
    // inventing an identity-shaped object or supplying a preflight verdict.
    const [stored] = await db.select().from(connectionGrants).where(eq(connectionGrants.id, selected.id));
    expect(stored).toBeDefined();
    return assertBoundedGitHubMutation(db, {
      companyId: input.companyId,
      agentId: input.agentId,
      connectionId: selected.connectionId,
      grant: stored!,
      decisionInput: decisionInput(input, selected, args),
    });
  }

  async function broadProfile(input: Seed) {
    const [profile] = await db.insert(toolProfiles).values({
      companyId: input.companyId, profileKey: randomUUID(), name: "Existing broad app profile", defaultAction: "allow",
    }).returning();
    await db.insert(toolProfileBindings).values({
      companyId: input.companyId, profileId: profile.id, targetType: "agent", targetId: input.agentId,
    });
    return profile;
  }

  function expectNoVaultRead() {
    expect(vault.resolveUserSecretValue).not.toHaveBeenCalled();
    expect(vault.resolveSecretValue).not.toHaveBeenCalled();
  }

  it.each([false, true])("denies bounded raw export before vault access (dedicated=%s)", async (dedicated) => {
    const input = await seed();
    const selected = await grant(input, dedicated ? "robot" : "A", dedicated);
    await bound(input, selected);
    const identity = await resolveManagedGitHubIdentitySelection(db, input.companyId, {
      agentId: input.agentId, responsibleUserId: "A",
    });
    expect(identity.grant?.id).toBe(selected.id); // A real eligible identity, not a missing-grant denial.
    const result = await credential(input);
    expect(result).toMatchObject({
      configured: true, error: "Argument-scoped GitHub access requires governed tools, not raw credentials",
    });
    expect(result.credential).toBeUndefined();
    expectNoVaultRead();
  });

  it("keeps another agent's existing grant and credential on the same connection untouched", async () => {
    const input = await seed();
    const selected = await grant(input, "robot", true);
    const [other] = await db.insert(agents).values({
      companyId: input.companyId, name: "Existing unbounded consumer", role: "engineer", adapterType: "process",
    }).returning();
    await db.insert(toolConnectionInstalls).values({
      companyId: input.companyId, connectionId: selected.connectionId, targetType: "agent", targetId: other.id,
    });
    const [existing] = await db.insert(connectionGrants).values({
      companyId: input.companyId, connectionId: selected.connectionId, kind: "agent", subjectAgentId: other.id,
      status: "active", credentialSecretRefs: [{ secretId: selected.secretId, configPath: "oauth.access_token" }],
      providerTenant: { github: {
        userId: "existing-robot", login: "existing-robot", installationCount: 1, repositoryCount: 1,
        repositorySelection: "selected", installationIds: ["1"], installationOwnerLogins: ["existing-robot"],
      } },
    }).returning();
    await bound(input, selected);
    expect((await credential(input)).credential).toBeUndefined();
    expectNoVaultRead();
    expect(await credential({ ...input, agentId: other.id })).toMatchObject({
      configured: true, credential: {
        token: "test-dedicated-token", source: "managed_connection", grantId: existing.id,
        connectionId: selected.connectionId, githubIdentity: { userId: "existing-robot", login: "existing-robot" },
      },
    });
    expect(vault.resolveSecretValue).toHaveBeenCalledTimes(1);
    expect(vault.resolveSecretValue).toHaveBeenCalledWith(input.companyId, selected.secretId, "latest", expect.any(Object));
    expect((await db.select().from(connectionGrants).where(eq(connectionGrants.id, existing.id)))[0]).toEqual(existing);
  });

  it("preserves baseline credentials with no bounded policy and rechecks policy removal", async () => {
    const input = await seed();
    const selected = await grant(input, "A");
    const expected = { configured: true, identitySource: "personal", credential: {
      token: "test-personal-token-A", source: "managed_connection", grantId: selected.id,
      connectionId: selected.connectionId, githubIdentity: { userId: "A", login: "A" },
    } };
    expect(await credential(input)).toMatchObject(expected);
    expect(vault.resolveUserSecretValue).toHaveBeenCalledWith(input.companyId, {
      definitionId: selected.definitionId, responsibleUserId: "A", version: "latest", required: true,
    }, expect.any(Object));
    await bound(input, selected);
    vi.clearAllMocks();
    expect((await credential(input)).credential).toBeUndefined();
    expectNoVaultRead();
    await db.delete(toolPolicies).where(eq(toolPolicies.companyId, input.companyId));
    expect(await credential(input)).toMatchObject(expected);
    expect(vault.resolveUserSecretValue).toHaveBeenCalledTimes(1);
  });

  it("uses the real policy engine for exact pairs and denies Cartesian owner/repository swaps", async () => {
    const input = await seed();
    const selected = await grant(input, "robot", true);
    const policies = await bound(input, selected);
    for (const [index, pair] of pairs.entries()) {
      expect(await toolAccessPolicyService(db).decide(decisionInput(input, selected, pair))).toMatchObject({
        allowed: true, reasonCode: "allow_policy", matchedPolicyIds: [policies[index].id],
      });
      await expect(mutation(input, selected, pair)).resolves.toBeUndefined();
    }
    for (const pair of [
      { owner: pairs[0].owner, repo: pairs[1].repo },
      { owner: pairs[1].owner, repo: pairs[0].repo },
    ]) {
      expect(await toolAccessPolicyService(db).decide(decisionInput(input, selected, pair))).toMatchObject({
        allowed: false, reasonCode: "deny_default", matchedPolicyIds: [],
      });
      await expect(mutation(input, selected, pair)).rejects.toMatchObject({ status: 403, message: expect.stringContaining("explicit allow") });
    }
    expectNoVaultRead();
  });

  it("does not let a real broad profile substitute for the bounded pair allow", async () => {
    const input = await seed();
    const selected = await grant(input, "robot", true);
    await bound(input, selected);
    const profile = await broadProfile(input);
    const swapped = { owner: pairs[0].owner, repo: pairs[1].repo };
    expect(await toolAccessPolicyService(db).decide(decisionInput(input, selected, swapped))).toMatchObject({
      allowed: true, reasonCode: "allow_profile", effectiveProfileIds: [profile.id], matchedPolicyIds: [],
    });
    await expect(mutation(input, selected, swapped)).rejects.toMatchObject({ status: 403, message: expect.stringContaining("explicit allow") });
    await expect(mutation(input, selected, pairs[0])).resolves.toBeUndefined();
    expectNoVaultRead();
  });

  it("rejects a revoked persisted identity even when the pair policy still allows", async () => {
    const input = await seed();
    const selected = await grant(input, "robot", true);
    // First prove this credential is valid without bounds, then revoke it after
    // a successful governed preflight. Neither path may return a stale identity.
    expect((await credential(input)).credential?.grantId).toBe(selected.id);
    await bound(input, selected);
    await expect(mutation(input, selected, pairs[0])).resolves.toBeUndefined();
    await db.update(connectionGrants).set({ status: "revoked", revokedAt: new Date() }).where(eq(connectionGrants.id, selected.id));
    vi.clearAllMocks();
    expect(await credential(input)).toMatchObject({ configured: true, error: "The managed GitHub identity must be reconnected" });
    expect((await credential(input)).credential).toBeUndefined();
    expect(await toolAccessPolicyService(db).decide(decisionInput(input, selected, pairs[0]))).toMatchObject({ allowed: true, reasonCode: "allow_policy" });
    await expect(mutation(input, selected, pairs[0])).rejects.toMatchObject({ status: 403, message: expect.stringContaining("no resolved managed identity") });
    expectNoVaultRead();
  });

  it("blocks an otherwise profile-allowed call at the actual gateway dispatch before provider I/O", async () => {
    const input = await seed();
    const selected = await grant(input, "robot", true);
    await bound(input, selected);
    await broadProfile(input);
    const [connection] = await db.update(toolConnections).set({
      healthStatus: "ok", config: { sourceTemplateKey: "github", url: "https://8.8.8.8/mcp" },
    }).where(eq(toolConnections.id, selected.connectionId)).returning();
    await db.insert(toolCatalogEntries).values({
      companyId: input.companyId, applicationId: connection.applicationId, connectionId: connection.id,
      entryKind: "tool", name: "create_branch", toolName: "create_branch", status: "active",
      riskLevel: "write", isReadOnly: false, isWrite: true, versionHash: "broker-integration-v1",
      inputSchema: { type: "object", properties: { owner: { type: "string" }, repo: { type: "string" } } },
    });
    const remoteHttpRequest = vi.fn(async (_url: string, _init: RequestInit): Promise<Response> => {
      throw new Error("Denied bounded call reached the provider");
    });
    const gateway = createToolGatewayService(db, {
      remoteHttpRequest, toolActionSigningSecret: "github-broker-integration-test-only",
    });
    const session = await gateway.createSession(input);
    const tools = await gateway.listToolsForSession(session.token);
    const tool = tools.find((candidate) => candidate.connectionId === selected.connectionId && candidate.upstreamToolName === "create_branch");
    expect(tool).toBeDefined();
    const swapped = { owner: pairs[0].owner, repo: pairs[1].repo };
    await expect(gateway.executeTool({
      sessionToken: session.token, tool: tool!.name, parameters: swapped, idempotencyKey: randomUUID(),
    })).rejects.toMatchObject({ status: 403, message: expect.stringContaining("explicit allow for this owner and repository") });
    // A failed, profile-admitted invocation with the broker's exact error proves
    // this reached final dispatch, not merely listing/preflight default denial.
    expect(await db.select().from(toolInvocations).where(eq(toolInvocations.companyId, input.companyId))).toMatchObject([{
      toolName: tool!.name, connectionId: selected.connectionId, policyDecision: "allow", matchedPolicyIds: [],
      status: "failed", errorMessage: expect.stringContaining("explicit allow for this owner and repository"),
    }]);
    expect(remoteHttpRequest).not.toHaveBeenCalled();
    // Identity-aware gateway lookup may acquire server-side headers before this
    // guard. Only raw-export tests above assert denial before any vault read.
  });
});
