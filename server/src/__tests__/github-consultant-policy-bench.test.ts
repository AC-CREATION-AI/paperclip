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
import { getEmbeddedPostgresTestSupport, startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";

type Case = {
  name: string;
  actor?: "unrelated";
  request: { toolName: string; arguments: Record<string, unknown> };
  reasonCode: "allow_policy" | "allow_profile" | "deny_default" | "deny_policy_block";
};
const fixture = JSON.parse(await readFile(new URL("./fixtures/github-consultant-policy-cases.json", import.meta.url), "utf8")) as {
  catalog: { read: string[]; write: string[] };
  cases: Case[];
};
const support = await getEmbeddedPostgresTestSupport();
if (!support.supported) console.warn(`Skipping ACC-4308 policy bench: ${support.reason}`);
const describeDatabase = support.supported ? describe : describe.skip;

// Reference policy simulation only: no installation, broker dispatch, or live GitHub calls.
// Never accept an external test DATABASE_URL; the helper creates a disposable database.
describeDatabase("ACC-4308 GitHub Consultant reference policy bench", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | undefined;
  let db: ReturnType<typeof createDb>;
  let app: express.Express;
  let companyId: string;
  const consultantId = randomUUID();
  const unrelatedId = randomUUID();
  let connectionId: string;
  let catalog: Array<typeof toolCatalogEntries.$inferSelect>;
  let baseline: Awaited<ReturnType<typeof mutationCounts>>;
  const allowIds = new Set<string>();
  let blockId: string;
  const upstream = [
    { owner: "anomalyco", repo: "models.dev", base: "dev" },
    { owner: "cheaper-inference", repo: "OmniRoute", base: "release/v3.8.54" },
    { owner: "paperclipai", repo: "paperclip", base: "master" },
  ];
  const existingForks = [
    { owner: "AC-CREATION-AI", repo: "OmniRoute", base: "release/v3.8.54" },
    { owner: "AC-CREATION-AI", repo: "paperclip", base: "master" },
  ];
  async function mutationCounts() {
    // Aggregates, not unbounded audit/counter row downloads. All fixture-company scoped.
    return Promise.all([
      toolRateLimitCounters, toolAccessAuditEvents, toolCallEvents, toolInvocations,
      toolActionRequests, activityLog,
    ].map(table => db.select({ count: sql<number>`count(*)::int` }).from(table)
      .where(sql`company_id = ${companyId}`)));
  }

  beforeAll(async () => {
    database = await startEmbeddedPostgresTestDatabase("paperclip-github-consultant-policy-");
    db = createDb(database.connectionString);
    const [company] = await db.insert(companies).values({
      name: "ACC-4308 disposable bench", issuePrefix: `GB${randomUUID().slice(0, 6)}`,
    }).returning();
    companyId = company.id;
    await db.insert(agents).values([
      { id: consultantId, companyId, name: "Consultant technique", adapterType: "process", status: "active" },
      { id: unrelatedId, companyId, name: "Unrelated agent", adapterType: "process", status: "active" },
    ]);
    const [application] = await db.insert(toolApplications).values({
      companyId, name: "GitHub offline catalog", applicationKey: "github", type: "mcp_http", status: "active",
    }).returning();
    const [connection] = await db.insert(toolConnections).values({
      companyId, applicationId: application.id, name: "GitHub disposable", uid: randomUUID(),
      transport: "mcp_remote", enabled: true, status: "active",
      config: { url: "https://github-bench.invalid/mcp" },
    }).returning();
    connectionId = connection.id;
    catalog = await db.insert(toolCatalogEntries).values([
      ...fixture.catalog.read.map(toolName => ({ toolName, riskLevel: "read" as const })),
      ...fixture.catalog.write.map(toolName => ({ toolName, riskLevel: "write" as const })),
    ].map(tool => ({ ...tool, companyId, applicationId: application.id, connectionId,
      name: tool.toolName, isReadOnly: tool.riskLevel === "read", isWrite: tool.riskLevel === "write",
      status: "active" as const, versionHash: "acc-4308-offline-v1" }))).returning();
    const [profile] = await db.insert(toolProfiles).values({
      companyId, profileKey: "consultant-get-me-only", name: "Consultant minimal read", defaultAction: "deny",
    }).returning();
    await db.insert(toolProfileBindings).values({
      companyId, profileId: profile.id, targetType: "agent", targetId: consultantId,
    });
    await db.insert(toolProfileEntries).values({
      companyId, profileId: profile.id, selectorType: "catalog_entry", effect: "include",
      catalogEntryId: catalog.find(entry => entry.toolName === "get_me")!.id,
    });
    const svc = toolAccessPolicyService(db);
    const selectors = { actorType: "agent", agentId: consultantId, connectionId };
    const candidateTools = ["get_me", "create_branch", "create_pull_request", "fork_repository", "create_or_update_file"];
    const blocked = await svc.createPolicy(companyId, {
      name: "Consultant forbidden tools and unverified edits", policyType: "block", priority: 1,
      selectors: { ...selectors, toolNames: catalog.map(entry => entry.toolName).filter(name => !candidateTools.includes(name)) },
    });
    blockId = blocked.id;
    // An exercised rate rule makes consumeRateLimit:false meaningful, even for allowed calls.
    await svc.createPolicy(companyId, {
      name: "Non-consuming replay sentinel", policyType: "rate_limit", priority: 0, selectors,
      config: { limit: 1, windowSeconds: 3600, keyBy: ["agent", "tool"] },
    });
    for (const tuple of [...upstream, ...existingForks]) {
      for (const toolName of ["create_branch", "create_pull_request", "fork_repository"]) {
        if (toolName === "fork_repository" && tuple.owner === "AC-CREATION-AI") continue;
        const fieldEquals: Record<string, unknown> = { owner: tuple.owner, repo: tuple.repo };
        const fieldMatches: Record<string, string> = {};
        if (toolName === "fork_repository") fieldEquals.organization = "AC-CREATION-AI";
        else {
          fieldEquals[toolName === "create_branch" ? "base_ref" : "base"] = tuple.base;
          fieldMatches[toolName === "create_branch" ? "branch" : "head"] = "^acc-[0-9]+-";
        }
        const policy = await svc.createPolicy(companyId, {
          name: `${toolName} ${tuple.owner}/${tuple.repo}`, policyType: "allow", priority: 2,
          selectors: { ...selectors, toolName },
          conditions: { arguments: { fieldEquals, ...(Object.keys(fieldMatches).length ? { fieldMatches } : {}) } },
        });
        allowIds.add(policy.id);
      }
    }
    const exactEdit = await svc.createPolicy(companyId, {
      name: "Four exact models.dev files", policyType: "allow", priority: 2,
      selectors: { ...selectors, toolName: "create_or_update_file" },
      conditions: { arguments: {
        fieldEquals: { owner: "anomalyco", repo: "models.dev", branch: "acc-4108-models" },
        fieldIn: { path: [
          "providers/minimax/models/MiniMax-M3.1-Flash.toml",
          "providers/minimax-cn/models/MiniMax-M3.1-Flash.toml",
          "providers/minimax-coding-plan/models/MiniMax-M3.1-Flash.toml",
          "providers/minimax-cn-coding-plan/models/MiniMax-M3.1-Flash.toml",
        ] },
      } },
    });
    allowIds.add(exactEdit.id);
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

  it("replays the JSON cases through the real route without counters, audits, or execution", async () => {
    expect(fixture.cases.length).toBeGreaterThanOrEqual(34);
    expect(new Set(fixture.cases.map(test => test.name)).size).toBe(fixture.cases.length);
    expect(catalog).toHaveLength(50);
    expect(allowIds.size).toBe(14); // Atomic tuples plus one exact scalar-path edit policy.
    try {
      for (const test of fixture.cases) {
        const entry = catalog.find(tool => tool.toolName === test.request.toolName);
        expect(entry, test.name).toBeDefined();
        const agentId = test.actor === "unrelated" ? unrelatedId : consultantId;
        const response = await request(app).post(`/api/companies/${companyId}/tools/policy/test`).send({
          companyId, actor: { actorType: "agent", actorId: agentId, agentId },
          request: { ...test.request, connectionId, catalogEntryId: entry!.id },
          consumeRateLimit: false, writeAuditEvent: false,
        });
        expect(response.status, test.name).toBe(200);
        expect(response.body.auditEvent, test.name).toBeNull();
        const allowed = test.reasonCode.startsWith("allow_");
        expect(response.body.decision, test.name).toMatchObject({
          allowed, decision: allowed ? "allow" : "deny", reasonCode: test.reasonCode,
        });
        const matched = response.body.decision.matchedPolicyIds as string[];
        if (test.reasonCode === "allow_policy") {
          expect(matched, test.name).toHaveLength(1);
          expect(allowIds.has(matched[0]), test.name).toBe(true);
        } else expect(matched, test.name).toEqual(test.reasonCode === "deny_policy_block" ? [blockId] : []);
      }
    } finally {
      expect(await mutationCounts()).toEqual(baseline);
    }
  }, 60_000);

  it("gives an explicit block precedence over an earlier allow", async () => {
    const svc = toolAccessPolicyService(db);
    await svc.createPolicy(companyId, { name: "Earlier broad allow", policyType: "allow", priority: 2,
      selectors: { agentId: unrelatedId, connectionId, toolName: "get_me" } });
    const block = await svc.createPolicy(companyId, { name: "Later explicit block", policyType: "block", priority: 999,
      selectors: { agentId: unrelatedId, connectionId, toolName: "get_me" } });
    const response = await request(app).post(`/api/companies/${companyId}/tools/policy/test`).send({
      companyId, actor: { actorType: "agent", actorId: unrelatedId, agentId: unrelatedId },
      request: { toolName: "get_me", connectionId }, consumeRateLimit: false, writeAuditEvent: false,
    });
    expect(response.status).toBe(200);
    expect(response.body.decision).toMatchObject({ allowed: false, reasonCode: "deny_policy_block", matchedPolicyIds: [block.id] });
  });
});
