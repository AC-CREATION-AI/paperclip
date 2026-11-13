import { randomUUID } from "node:crypto";
import {
  agents, companies, createDb, EMBEDDED_POSTGRES_TEST_TIMEOUT_MS,
  toolApplications, toolCatalogEntries, toolConnections,
  toolProfileBindings, toolProfileEntries, toolProfiles,
} from "@paperclipai/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { connectorToolPolicy } from "../services/connectors/tool-policy.js";
import { descriptorHash, stableHash } from "../services/tool-catalog-hash.js";
import { createCatalogDefaultAccess } from "../services/tool-access/catalog/default-access.js";
import { classifyRisk, shouldQuarantineNewEntries, type McpToolDescriptor } from "../services/tool-access/catalog/descriptors.js";
import { createToolCatalogPublication } from "../services/tool-access/catalog/publication.js";
import { getEmbeddedPostgresTestSupport, startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";

function connectionFor(config: Record<string, unknown>) {
  return { transport: "mcp_remote", config } as typeof toolConnections.$inferSelect;
}

describe("GitHub catalog quarantine defaults", () => {
  it("declares GitHub review without replacing its existing risk classifier", () => {
    expect(connectorToolPolicy("github")).toMatchObject({
      sourceTemplateKey: "github", quarantineNewEntries: true,
    });
    expect(connectorToolPolicy("github").classifyRisk).toBeUndefined();
    expect(classifyRisk({ name: "get_me" }, "github")).toBe("read");
    expect(classifyRisk({ name: "create_pull_request" }, "github")).toBe("write");
  });

  it.each([undefined, false, true])("requires GitHub review with a saved flag of %s", quarantineNewEntries => {
    const connection = connectionFor({ sourceTemplateKey: "github", quarantineNewEntries });
    expect(connectorToolPolicy("github", connection).quarantineNewEntries).toBe(true);
    expect(shouldQuarantineNewEntries(connection)).toBe(true);
  });

  it.each([undefined, null, "custom", "notion", "github-code-review-bot"])("leaves unrelated source %s unchanged", sourceTemplateKey => {
    expect(connectorToolPolicy(sourceTemplateKey).quarantineNewEntries).toBe(false);
    expect(shouldQuarantineNewEntries(connectionFor({ sourceTemplateKey }))).toBe(false);
    expect(shouldQuarantineNewEntries(connectionFor({ sourceTemplateKey, quarantineNewEntries: false }))).toBe(false);
    expect(shouldQuarantineNewEntries(connectionFor({ sourceTemplateKey, quarantineNewEntries: true }))).toBe(true);
  });
});

const support = await getEmbeddedPostgresTestSupport();
(support.supported ? describe : describe.skip)("GitHub catalog publication quarantine", () => {
  let temporary: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | undefined;
  let db: ReturnType<typeof createDb>;

  beforeAll(async () => {
    temporary = await startEmbeddedPostgresTestDatabase("paperclip-github-quarantine-");
    db = createDb(temporary.connectionString);
  }, EMBEDDED_POSTGRES_TEST_TIMEOUT_MS);

  afterAll(async () => {
    try { await db?.$client.end({ timeout: 1 }); }
    finally { await temporary?.cleanup(); }
  });

  async function fixture(status: "draft" | "active", authKind: "api_key" | "oauth", quarantineNewEntries: boolean) {
    const [company] = await db.insert(companies).values({
      name: "GitHub quarantine fixture", issuePrefix: `GQ${randomUUID().slice(0, 6)}`,
    }).returning();
    const [application] = await db.insert(toolApplications).values({
      companyId: company.id, name: "GitHub", type: "mcp_http", status: "active",
    }).returning();
    const config = { sourceTemplateKey: "github", quarantineNewEntries };
    const [connection] = await db.insert(toolConnections).values({
      companyId: company.id, applicationId: application.id, uid: randomUUID(), name: "GitHub fixture",
      transport: "mcp_remote", status, enabled: status === "active", authKind,
      config, transportConfig: config,
    }).returning();
    const discovery: { tools: McpToolDescriptor[] } = { tools: [] };
    const enableCatalogEntriesByDefault = vi.fn(createCatalogDefaultAccess(db).enableCatalogEntriesByDefault);
    const refresh = createToolCatalogPublication(db, {
      now: () => new Date("2026-11-13T12:00:00Z"),
      audit: vi.fn(async () => undefined),
      getConnectionRow: async () => {
        const [row] = await db.select().from(toolConnections).where(eq(toolConnections.id, connection.id));
        return row;
      },
      discoverTools: async () => discovery.tools,
      assertConnectorConnectionSetupEnabled: async () => undefined,
      updateConnectionHealth: async row => row,
      vaultGrantForConnection: async () => null,
      ensureRuntimeSlot: async () => null,
      enableCatalogEntriesByDefault,
    });
    return { company, application, connection, discovery, refresh, enableCatalogEntriesByDefault };
  }

  it.each(["api_key", "oauth"] as const)("quarantines first %s draft discovery without the managed OAuth option", async authKind => {
    const f = await fixture("draft", authKind, true);
    f.discovery.tools = [{ name: "get_me" }, { name: "create_pull_request" }];
    const result = await f.refresh(f.connection.id);
    expect(result.quarantinedCount).toBe(2);
    expect(result.catalog).toHaveLength(2);
    for (const entry of result.catalog) {
      expect(entry).toMatchObject({ status: "quarantined", quarantineReason: "pending_review" });
    }
    expect(result.connection.status).toBe("draft");
    expect(f.enableCatalogEntriesByDefault).toHaveBeenCalledWith(expect.objectContaining({
      newCatalogEntryIds: [], activeCatalogEntryIds: [],
    }), expect.anything());
    expect(await db.select().from(toolProfiles).where(eq(toolProfiles.companyId, f.company.id))).toEqual([]);
  });

  it("does not let enable-all or safe-default bypass first GitHub discovery review", async () => {
    const f = await fixture("draft", "api_key", false);
    await db.update(toolConnections).set({ config: { ...f.connection.config, safeDefault: true } })
      .where(eq(toolConnections.id, f.connection.id));
    f.discovery.tools = [{ name: "get_me" }, { name: "create_pull_request" }];
    const result = await f.refresh(f.connection.id, undefined, { enableAllByDefault: true });
    expect(result.quarantinedCount).toBe(2);
    expect(result.catalog.every(entry => entry.status === "quarantined")).toBe(true);
  });

  it("preserves reviewed active entries and seven consumers while quarantining new and changed definitions", async () => {
    const f = await fixture("active", "api_key", false);
    const reviewedAt = new Date("2026-11-12T12:00:00Z");
    const original: McpToolDescriptor[] = [
      { name: "get_me" },
      { name: "create_branch", inputSchema: { type: "object" } },
      { name: "get_disabled" },
      { name: "get_pending" },
      { name: "get_description", description: "Reviewed description" },
    ];
    const saved = await db.insert(toolCatalogEntries).values(original.map(descriptor => {
      const riskLevel = classifyRisk(descriptor, "github");
      const status = descriptor.name === "get_disabled" ? "disabled" as const
        : descriptor.name === "get_pending" ? "quarantined" as const : "active" as const;
      return {
        companyId: f.company.id, applicationId: f.application.id, connectionId: f.connection.id,
        name: descriptor.name, toolName: descriptor.name, description: descriptor.description ?? null,
        inputSchema: descriptor.inputSchema ?? {}, riskLevel, isReadOnly: riskLevel === "read",
        isWrite: riskLevel === "write", status, versionHash: descriptorHash(descriptor, riskLevel),
        schemaHash: stableHash(descriptor.inputSchema ?? {}), reviewedAt,
        quarantinedAt: status === "quarantined" ? reviewedAt : null,
        quarantineReason: status === "quarantined" ? "pending_review" : null,
      };
    })).returning();
    const [profile] = await db.insert(toolProfiles).values({
      companyId: f.company.id, profileKey: `app:${f.connection.id}`, name: "Reviewed GitHub access",
      status: "active", defaultAction: "deny",
    }).returning();
    const consumers = await db.insert(agents).values(Array.from({ length: 7 }, (_, index) => ({
      companyId: f.company.id, name: `Existing consumer ${index}`, adapterType: "process", status: "active" as const,
    }))).returning();
    await db.insert(toolProfileBindings).values(consumers.map(agent => ({
      companyId: f.company.id, profileId: profile.id, targetType: "agent", targetId: agent.id,
    })));
    await db.insert(toolProfileEntries).values(saved.filter(entry => entry.status === "active").map(entry => ({
      companyId: f.company.id, profileId: profile.id, selectorType: "catalog_entry" as const,
      effect: "include" as const, catalogEntryId: entry.id,
    })));
    const bindingsBefore = await db.select().from(toolProfileBindings).where(eq(toolProfileBindings.profileId, profile.id));
    const entriesBefore = await db.select().from(toolProfileEntries).where(eq(toolProfileEntries.profileId, profile.id));
    f.discovery.tools = [
      original[0],
      { ...original[1], inputSchema: { type: "object", required: ["branch"] } },
      original[2], original[3],
      { ...original[4], description: "Changed description" },
      { name: "get_provider_added" }, { name: "create_provider_added" },
    ];
    const result = await f.refresh(f.connection.id, undefined, { enableAllByDefault: true });
    expect(result.quarantinedCount).toBe(4);
    expect(result.catalog.find(entry => entry.toolName === "get_me")).toMatchObject({
      id: saved[0].id, status: "active", reviewedAt,
    });
    expect(result.catalog.find(entry => entry.toolName === "get_disabled")).toMatchObject({ status: "disabled" });
    expect(result.catalog.find(entry => entry.toolName === "get_pending")).toMatchObject({
      status: "quarantined", quarantinedAt: reviewedAt,
    });
    for (const name of ["create_branch", "get_description", "get_provider_added", "create_provider_added"]) {
      expect(result.catalog.find(entry => entry.toolName === name)).toMatchObject({
        status: "quarantined", quarantineReason: "pending_review",
      });
    }
    expect(result.connection.config.quarantineNewEntries).toBe(true);
    const [persisted] = await db.select().from(toolConnections).where(eq(toolConnections.id, f.connection.id));
    expect(persisted.transportConfig.quarantineNewEntries).toBe(true);
    expect(f.enableCatalogEntriesByDefault).toHaveBeenCalledWith(expect.objectContaining({
      newCatalogEntryIds: [], activeCatalogEntryIds: [saved[0].id],
    }), expect.anything());
    const repeated = await f.refresh(f.connection.id, undefined, { enableAllByDefault: true });
    expect(repeated.quarantinedCount).toBe(0);
    expect(repeated.catalog.map(entry => [entry.id, entry.status]))
      .toEqual(result.catalog.map(entry => [entry.id, entry.status]));
    const bindingsAfter = await db.select().from(toolProfileBindings).where(eq(toolProfileBindings.profileId, profile.id));
    expect(bindingsAfter).toHaveLength(7);
    expect(bindingsAfter).toEqual(expect.arrayContaining(bindingsBefore));
    const entriesAfter = await db.select().from(toolProfileEntries).where(eq(toolProfileEntries.profileId, profile.id));
    expect(entriesAfter).toHaveLength(entriesBefore.length);
    expect(entriesAfter).toEqual(expect.arrayContaining(entriesBefore));
  });
});
