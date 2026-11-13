import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  activityLog, agents, companies, createDb, toolAccessAuditEvents, toolActionRequests,
  toolApplications, toolCallEvents, toolCatalogEntries, toolConnections, toolInvocations,
  toolProfileBindings, toolProfileEntries, toolProfiles, toolRateLimitCounters,
} from "@paperclipai/db";
import { errorHandler } from "../middleware/error-handler.js";
import { toolAccessRoutes } from "../routes/tool-access.js";
import { toolAccessPolicyService } from "../services/tool-access-policy.js";
import { isBoundedGitHubPolicy } from "../services/github-policy-scope.js";
import { getEmbeddedPostgresTestSupport, startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";

type Policy = {
  name: string;
  stage: "A" | "B";
  policyType: "allow" | "block";
  priority: number;
  toolName?: string;
  toolNames?: string[];
  conditions?: Record<string, unknown>;
};
type Case = {
  name: string;
  // "hub" is the Consultant calling the second GitHub route, outside the broker.
  actor?: "unrelated" | "consumer" | "hub";
  request: { toolName: string; arguments: Record<string, unknown> };
  reasonCode: "allow_policy" | "allow_profile" | "deny_default" | "deny_policy_block";
};
// The candidate is data: the profile and policies below are created from the
// fixture exactly as they would be submitted, so the bench tests that payload.
const fixture = JSON.parse(await readFile(new URL("./fixtures/github-consultant-candidate-cases.json", import.meta.url), "utf8")) as {
  catalog: { read: string[]; write: string[] };
  profile: { profileKey: string; defaultAction: "deny"; includeTools: string[] };
  policies: Policy[];
  hub: { catalog: Array<{ name: string; riskLevel: "read" | "write" }>; policy: Policy };
  cases: Case[];
};
const support = await getEmbeddedPostgresTestSupport();
if (!support.supported) console.warn(`Skipping candidate bench: ${support.reason}`);
const describeDatabase = support.supported ? describe : describe.skip;

describeDatabase("GitHub Consultant candidate policy bench", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | undefined;
  let db: ReturnType<typeof createDb>;
  let app: express.Express;
  let companyId: string;
  let connectionId: string;
  let hubConnectionId: string;
  let hubCatalog: Array<typeof toolCatalogEntries.$inferSelect>;
  let hubBlockId: string;
  const consultantId = randomUUID();
  const unrelatedId = randomUUID();
  const consumerId = randomUUID();
  let catalog: Array<typeof toolCatalogEntries.$inferSelect>;
  let baseline: Awaited<ReturnType<typeof mutationCounts>>;
  const allowIds = new Set<string>();
  let blockId: string;
  let createdPolicies: Array<Awaited<ReturnType<ReturnType<typeof toolAccessPolicyService>["createPolicy"]>>> = [];

  async function mutationCounts() {
    return Promise.all([
      toolRateLimitCounters, toolAccessAuditEvents, toolCallEvents, toolInvocations,
      toolActionRequests, activityLog,
    ].map(table => db.select({ count: sql<number>`count(*)::int` }).from(table)
      .where(sql`company_id = ${companyId}`)));
  }

  beforeAll(async () => {
    database = await startEmbeddedPostgresTestDatabase("paperclip-github-consultant-candidate-");
    db = createDb(database.connectionString);
    const [company] = await db.insert(companies).values({
      name: "Disposable candidate bench", issuePrefix: `GC${randomUUID().slice(0, 6)}`,
    }).returning();
    companyId = company.id;
    await db.insert(agents).values([
      { id: consultantId, companyId, name: "Consultant technique", adapterType: "process", status: "active" },
      { id: unrelatedId, companyId, name: "Unrelated agent", adapterType: "process", status: "active" },
      { id: consumerId, companyId, name: "Existing consumer", adapterType: "process", status: "active" },
    ]);
    const [application] = await db.insert(toolApplications).values({
      companyId, name: "GitHub offline catalog", applicationKey: "github", type: "mcp_http", status: "active",
    }).returning();
    const [connection] = await db.insert(toolConnections).values({
      companyId, applicationId: application.id, name: "GitHub disposable", uid: randomUUID(),
      transport: "mcp_remote", enabled: true, status: "active",
      config: { url: "https://github-bench.invalid/mcp", sourceTemplateKey: "github" },
    }).returning();
    connectionId = connection.id;
    catalog = await db.insert(toolCatalogEntries).values([
      ...fixture.catalog.read.map(toolName => ({ toolName, riskLevel: "read" as const })),
      ...fixture.catalog.write.map(toolName => ({ toolName, riskLevel: "write" as const })),
    ].map(tool => ({ ...tool, companyId, applicationId: application.id, connectionId,
      name: tool.toolName, isReadOnly: tool.riskLevel === "read", isWrite: tool.riskLevel === "write",
      status: "active" as const, versionHash: "bounded-offline-v1" }))).returning();
    const entryFor = (toolName: string) => catalog.find(entry => entry.toolName === toolName)!.id;

    // Candidate profile: reads only, bound to the Consultant alone.
    const [profile] = await db.insert(toolProfiles).values({
      companyId, profileKey: fixture.profile.profileKey, name: "Consultant GitHub bounded", defaultAction: "deny",
    }).returning();
    await db.insert(toolProfileBindings).values({ companyId, profileId: profile.id, targetType: "agent", targetId: consultantId });
    await db.insert(toolProfileEntries).values(fixture.profile.includeTools.map(toolName => ({
      companyId, profileId: profile.id, selectorType: "catalog_entry" as const, effect: "include" as const,
      catalogEntryId: entryFor(toolName),
    })));

    // Existing consumer: the full app profile every installed agent has today.
    const [appProfile] = await db.insert(toolProfiles).values({
      companyId, profileKey: `app:${connectionId}`, name: "GitHub app", defaultAction: "deny",
    }).returning();
    await db.insert(toolProfileBindings).values({ companyId, profileId: appProfile.id, targetType: "agent", targetId: consumerId });
    await db.insert(toolProfileEntries).values(catalog.map(entry => ({
      companyId, profileId: appProfile.id, selectorType: "catalog_entry" as const, effect: "include" as const,
      catalogEntryId: entry.id,
    })));

    const svc = toolAccessPolicyService(db);
    const selectors = { actorType: "agent", agentId: consultantId, connectionId };
    // An exercised rate rule makes consumeRateLimit:false meaningful, even for allowed calls.
    await svc.createPolicy(companyId, {
      name: "Non-consuming replay sentinel", policyType: "rate_limit", priority: 0, selectors,
      config: { limit: 1, windowSeconds: 3600, keyBy: ["agent", "tool"] },
    });
    for (const policy of fixture.policies) {
      const created = await svc.createPolicy(companyId, {
        name: policy.name, policyType: policy.policyType, priority: policy.priority,
        selectors: { ...selectors, ...(policy.toolName ? { toolName: policy.toolName } : { toolNames: policy.toolNames }) },
        ...(policy.conditions ? { conditions: policy.conditions } : {}),
      });
      createdPolicies.push(created);
      if (policy.policyType === "allow") allowIds.add(created.id);
      else blockId = created.id;
    }

    // Second GitHub route (hub), outside the bounded broker, with the live
    // catalog risk levels: several writes are stored as `read` there.
    const [hubApplication] = await db.insert(toolApplications).values({
      companyId, name: "GitHub hub route", applicationKey: "hub-github", type: "mcp_http", status: "active",
    }).returning();
    const [hubConnection] = await db.insert(toolConnections).values({
      companyId, applicationId: hubApplication.id, name: "Hub GitHub disposable", uid: randomUUID(),
      transport: "mcp_remote", enabled: true, status: "active",
      config: { url: "https://hub-bench.invalid/github/mcp" },
    }).returning();
    hubConnectionId = hubConnection.id;
    hubCatalog = await db.insert(toolCatalogEntries).values(fixture.hub.catalog.map(tool => ({
      companyId, applicationId: hubApplication.id, connectionId: hubConnectionId, name: tool.name,
      toolName: tool.name, riskLevel: tool.riskLevel, isReadOnly: tool.riskLevel === "read",
      isWrite: tool.riskLevel === "write", status: "active" as const, versionHash: "bounded-offline-v1",
    }))).returning();
    // Worst case: a future profile opening the whole hub connection to the Consultant.
    const [hubProfile] = await db.insert(toolProfiles).values({
      companyId, profileKey: "consultant-hub-worst-case", name: "Consultant hub worst case", defaultAction: "deny",
    }).returning();
    await db.insert(toolProfileBindings).values({ companyId, profileId: hubProfile.id, targetType: "agent", targetId: consultantId });
    await db.insert(toolProfileEntries).values({
      companyId, profileId: hubProfile.id, selectorType: "connection", effect: "include", connectionId: hubConnectionId,
    });
    const hubBlock = await svc.createPolicy(companyId, {
      name: fixture.hub.policy.name, policyType: "block", priority: fixture.hub.policy.priority,
      selectors: { actorType: "agent", agentId: consultantId, connectionId: hubConnectionId, toolNames: fixture.hub.policy.toolNames },
    });
    hubBlockId = hubBlock.id;

    app = express();
    app.use(express.json());
    app.use((req, _res, next) => {
      req.actor = { type: "board", userId: "bench-board", source: "local_implicit", isInstanceAdmin: true };
      next();
    });
    app.use("/api", toolAccessRoutes(db));
    app.use(errorHandler);
    baseline = await mutationCounts();
  }, 90_000);

  afterAll(async () => {
    try { await db?.$client.end({ timeout: 1 }); }
    finally { await database?.cleanup(); }
  });

  it("serializes atomic owner/repo tuples the broker accepts", () => {
    // Every allow names owner and repo in the same fieldEquals: the git broker
    // requires that pair, and independent lists would form a cartesian product.
    for (const policy of fixture.policies.filter(item => item.policyType === "allow")) {
      const equals = (policy.conditions?.arguments as { fieldEquals?: Record<string, unknown> })?.fieldEquals ?? {};
      expect(typeof equals.owner, policy.name).toBe("string");
      expect(typeof equals.repo, policy.name).toBe("string");
    }
    // The real GitHub MCP create_branch schema exposes from_branch, not base_ref.
    const branchSchemaField = fixture.policies.filter(item => item.toolName === "create_branch")
      .map(item => Object.keys((item.conditions?.arguments as { fieldEquals: Record<string, unknown> }).fieldEquals));
    for (const fields of branchSchemaField) expect(fields).toContain("from_branch");
    // Every created policy opts the Consultant into the bounded, block-first broker path.
    for (const policy of createdPolicies) {
      expect(isBoundedGitHubPolicy(policy, consultantId, connectionId), policy.name)
        .toBe(Boolean(policy.conditions && Object.keys(policy.conditions).length));
    }
  });

  it("replays every candidate case through the real route without side effects", async () => {
    expect(new Set(fixture.cases.map(test => test.name)).size).toBe(fixture.cases.length);
    expect(catalog).toHaveLength(50);
    const observed: Array<{ name: string; expected: string; actual: string }> = [];
    try {
      for (const test of fixture.cases) {
        const onHub = test.actor === "hub";
        const entry = (onHub ? hubCatalog : catalog).find(tool => tool.toolName === test.request.toolName);
        expect(entry, test.name).toBeDefined();
        const agentId = test.actor === "unrelated" ? unrelatedId : test.actor === "consumer" ? consumerId : consultantId;
        const response = await request(app).post(`/api/companies/${companyId}/tools/policy/test`).send({
          companyId, actor: { actorType: "agent", actorId: agentId, agentId },
          request: { ...test.request, connectionId: onHub ? hubConnectionId : connectionId, catalogEntryId: entry!.id },
          consumeRateLimit: false, writeAuditEvent: false,
        });
        expect(response.status, test.name).toBe(200);
        expect(response.body.auditEvent, test.name).toBeNull();
        observed.push({ name: test.name, expected: test.reasonCode, actual: response.body.decision.reasonCode });
        const allowed = test.reasonCode.startsWith("allow_");
        expect(response.body.decision, test.name).toMatchObject({
          allowed, decision: allowed ? "allow" : "deny", reasonCode: test.reasonCode,
        });
        const matched = response.body.decision.matchedPolicyIds as string[];
        if (test.reasonCode === "allow_policy") {
          expect(matched, test.name).toHaveLength(1);
          expect(allowIds.has(matched[0]), test.name).toBe(true);
        } else if (test.reasonCode === "deny_policy_block") {
          expect(matched, test.name).toEqual([onHub ? hubBlockId : blockId]);
        } else expect(matched, test.name).toEqual([]);
      }
    } finally {
      // Expected/actual table for the review record, printed whatever the outcome.
      console.log(`CANDIDATE_RESULTS ${JSON.stringify(observed)}`);
      expect(await mutationCounts()).toEqual(baseline);
    }
  }, 60_000);
});
