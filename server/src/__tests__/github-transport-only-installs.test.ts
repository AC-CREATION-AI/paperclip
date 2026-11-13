import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  agents,
  companies,
  closeRegisteredClients,
  connectionGrants,
  createDb,
  toolAccessAuditEvents,
  toolApplications,
  toolCatalogEntries,
  toolConnections,
  toolConnectionInstalls,
  toolProfileBindings,
  toolProfileEntries,
  toolProfiles,
  type Db,
} from "@paperclipai/db";
import { putToolConnectionInstallsSchema } from "@paperclipai/shared";
import { and, eq, sql } from "drizzle-orm";
import { errorHandler } from "../middleware/index.js";
import { toolAccessRoutes } from "../routes/tool-access.js";
import * as accessModule from "../services/access.js";
import { createConnectionInstalls } from "../services/tool-access/connections/installs.js";
import { toolAccessService } from "../services/tool-access.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

type Install = { targetType: "agent" | "company"; targetId: string; bindAppProfile?: false };
const externalDatabaseUrl = process.env.PAPERCLIP_TOOL_ACCESS_TEST_DATABASE_URL?.trim();
const support = externalDatabaseUrl ? { supported: true } : await getEmbeddedPostgresTestSupport();
const describeDatabase = support.supported ? describe : describe.skip;

function createRouteApp(db: Db) {
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.actor = { type: "board", userId: "board-user", isInstanceAdmin: true, source: "local_implicit" };
    next();
  });
  app.use("/api", toolAccessRoutes(db));
  app.use(errorHandler);
  return app;
}

describe("transport-only install input", () => {
  it("accepts only an explicit false app-profile binding option", () => {
    const install = { targetType: "agent", targetId: randomUUID() };
    expect(putToolConnectionInstallsSchema.parse({ installs: [install] }).installs).toEqual([install]);
    expect(putToolConnectionInstallsSchema.parse({ installs: [{ ...install, bindAppProfile: false }] }).installs)
      .toEqual([{ ...install, bindAppProfile: false }]);
    expect(putToolConnectionInstallsSchema.safeParse({ installs: [{ ...install, bindAppProfile: true }] }).success).toBe(false);
  });
});

describeDatabase("GitHub transport-only connection installs", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let db: Db;

  beforeAll(async () => {
    if (externalDatabaseUrl) {
      db = createDb(externalDatabaseUrl);
      return;
    }
    database = await startEmbeddedPostgresTestDatabase("paperclip-github-transport-only-");
    db = createDb(database.connectionString);
  }, 90_000);

  afterAll(async () => {
    if (externalDatabaseUrl) await closeRegisteredClients(externalDatabaseUrl);
    await database?.cleanup();
  });

  async function fixture(config: Record<string, unknown> = { onDemandTools: { enabled: true } }) {
    const [company] = await db.insert(companies).values({
      name: "GitHub transport-only fixture", issuePrefix: `GT${randomUUID().slice(0, 6)}`,
    }).returning();
    const companyId = company.id;
    const agentIds = Array.from({ length: 9 }, () => randomUUID());
    await db.insert(agents).values(agentIds.map(id => ({
      id, companyId, name: id, status: "active", adapterType: "process",
    })));
    const [application] = await db.insert(toolApplications).values({
      companyId, name: "GitHub fixture", type: "mcp_http",
    }).returning();
    const [connection] = await db.insert(toolConnections).values({
      companyId, applicationId: application.id, name: "GitHub fixture", uid: randomUUID(),
      transport: "mcp_remote", status: "active", enabled: true,
      config: { ...config, mcpAgentAccessConfigured: true },
    }).returning();
    await db.insert(connectionGrants).values({
      companyId, connectionId: connection.id, kind: "organization", status: "active", isDefault: true,
    });
    const catalog = await db.insert(toolCatalogEntries).values(Array.from({ length: 50 }, (_, index) => ({
      companyId, applicationId: application.id, connectionId: connection.id,
      name: `github_tool_${index}`, toolName: `github_tool_${index}`, versionHash: "fixture-v1",
      riskLevel: "read" as const, isReadOnly: true, isWrite: false,
    }))).returning();
    const [appProfile] = await db.insert(toolProfiles).values({
      companyId, profileKey: `app:${connection.id}`, name: "Full GitHub fixture access", defaultAction: "deny",
    }).returning();
    await db.insert(toolProfileEntries).values(catalog.map(entry => ({
      companyId, profileId: appProfile.id, selectorType: "catalog_entry" as const,
      catalogEntryId: entry.id, connectionId: connection.id,
    })));
    const service = toolAccessService(db);
    const app = createRouteApp(db);
    const put = (installs: Install[]) => request(app)
      .put(`/api/tool-connections/${connection.id}/installs`).send({ installs })
      .expect(response => expect(response.status, JSON.stringify(response.body)).toBe(200));
    const bindings = () => db.select().from(toolProfileBindings).where(and(
      eq(toolProfileBindings.companyId, companyId), eq(toolProfileBindings.profileId, appProfile.id),
    )).orderBy(toolProfileBindings.targetId);
    const effective = (agentId: string) => service.getEffectiveProfilesForAgent(companyId, agentId);
    const targets: Install[] = agentIds.slice(0, 7).map(targetId => ({ targetType: "agent", targetId }));
    const seed = async (installs: Install[] = targets, source = "app_gallery_finish") => {
      await db.insert(toolConnectionInstalls).values(installs.map(install => ({
        companyId, connectionId: connection.id, targetType: install.targetType, targetId: install.targetId,
      })));
      await db.insert(toolProfileBindings).values(installs.map(install => ({
        companyId, profileId: appProfile.id, targetType: install.targetType, targetId: install.targetId,
        metadata: { source, connectionId: connection.id },
      })));
    };
    return { companyId, agentIds, connection, catalog, appProfile, service, put, bindings, effective, targets, seed };
  }

  it.each([
    { onDemandTools: true },
    { onDemandTools: { enabled: true } },
    { loadToolsOnDemand: true },
    { loadToolsOnDemand: { enabled: true } },
    { onDemandTools: { enabled: false }, loadToolsOnDemand: { enabled: true } },
  ])("grants none of the full 50-tool profile to a new on-demand install with %j", async config => {
    const f = await fixture(config);
    const targetId = f.agentIds[7];
    await f.put([{ targetType: "agent", targetId }]);
    await f.put([{ targetType: "agent", targetId }]);
    expect(await f.bindings()).toEqual([]);
    const effective = await f.effective(targetId);
    expect(effective.allowedTools).toEqual([]);
    expect(effective.allowedToolNames).toEqual([]);
    expect(effective.installedConnections.map(connection => connection.id)).toEqual([f.connection.id]);
  });

  it("removes a pre-existing app binding before a new on-demand target gains reach", async () => {
    const f = await fixture();
    const target = f.targets[0];
    await db.insert(toolProfileBindings).values({
      companyId: f.companyId, profileId: f.appProfile.id, targetType: target.targetType, targetId: target.targetId,
      metadata: { source: "manual" },
    });
    await f.put([target]);
    expect(await f.bindings()).toEqual([]);
    expect((await f.effective(target.targetId)).allowedTools).toEqual([]);
  });

  it("preserves all seven existing targets and their grants on ordinary saves and additions", async () => {
    const f = await fixture();
    await f.seed();
    const priorBindings = await f.bindings();
    const priorInstalls = await f.service.listConnectionInstalls(f.connection.id);
    await f.put(f.targets);
    expect(await f.service.listConnectionInstalls(f.connection.id)).toEqual(priorInstalls);
    const added = { targetType: "agent" as const, targetId: f.agentIds[7] };
    await f.put([...f.targets, added]);
    expect(await f.bindings()).toEqual(priorBindings);
    for (const agentId of f.agentIds.slice(0, 7)) {
      expect((await f.effective(agentId)).allowedTools).toHaveLength(50);
    }
    expect((await f.effective(added.targetId)).allowedTools).toEqual([]);
    const catalog = await db.select().from(toolCatalogEntries).where(eq(toolCatalogEntries.connectionId, f.connection.id));
    expect(catalog.sort((a, b) => a.id.localeCompare(b.id)))
      .toEqual([...f.catalog].sort((a, b) => a.id.localeCompare(b.id)));
    const [connection] = await db.select().from(toolConnections).where(eq(toolConnections.id, f.connection.id));
    expect(connection.config).toEqual(f.connection.config);
  });

  it.each(["agent", "company"] as const)("keeps a new on-demand %s target transport-only", async targetType => {
    const f = await fixture();
    const targetId = targetType === "company" ? f.companyId : f.agentIds[7];
    await f.put([{ targetType, targetId }]);
    expect(await f.bindings()).toEqual([]);
    expect((await f.effective(f.agentIds[7])).allowedTools).toEqual([]);
  });

  it.each(["tool_connection_install", "app_gallery_finish", "manual"])(
    "explicit transport_only removes only the selected app binding with source %s and retries keep it absent",
    async source => {
      const f = await fixture({});
      await f.seed(f.targets, source);
      const target = f.targets[0];
      const [otherProfile] = await db.insert(toolProfiles).values({
        companyId: f.companyId, profileKey: "unrelated", name: "Unrelated access", defaultAction: "deny",
      }).returning();
      const [otherBinding] = await db.insert(toolProfileBindings).values({
        companyId: f.companyId, profileId: otherProfile.id, targetType: target.targetType, targetId: target.targetId,
      }).returning();
      const priorBindings = await f.bindings();
      const priorInstalls = await f.service.listConnectionInstalls(f.connection.id);
      const input = f.targets.map(install => install.targetId === target.targetId ? { ...install, bindAppProfile: false as const } : install);
      await f.put(input);
      await f.put(input);
      await f.put(f.targets);
      expect(await f.bindings()).toEqual(priorBindings.filter(binding => binding.targetId !== target.targetId));
      expect(await db.select().from(toolProfileBindings).where(eq(toolProfileBindings.id, otherBinding.id)))
        .toEqual([otherBinding]);
      expect(await f.service.listConnectionInstalls(f.connection.id)).toEqual(priorInstalls);
      expect((await f.effective(target.targetId)).allowedTools).toEqual([]);
      expect((await f.effective(f.agentIds[1])).allowedTools).toHaveLength(50);
    },
  );

  it("explicitly unbinds an existing company target without touching agent bindings", async () => {
    const f = await fixture({});
    const target: Install = { targetType: "company", targetId: f.companyId };
    await f.seed([target, f.targets[0]], "manual");
    const priorBindings = await f.bindings();
    await f.put([{ ...target, bindAppProfile: false }, f.targets[0]]);
    await f.put([target, f.targets[0]]);
    expect(await f.bindings()).toEqual(priorBindings.filter(binding => binding.targetType === "agent"));
    expect((await f.effective(f.agentIds[7])).allowedTools).toEqual([]);
  });

  it("refuses an agent transport-only transition while a broader company app binding survives", async () => {
    const f = await fixture();
    const companyTarget: Install = { targetType: "company", targetId: f.companyId };
    await f.seed([companyTarget]);
    const prior = await f.bindings();
    await expect(f.service.putConnectionInstalls(f.connection.id, {
      installs: [companyTarget, { targetType: "agent", targetId: f.agentIds[7], bindAppProfile: false }],
    })).rejects.toThrow("company-wide app profile");
    expect(await f.bindings()).toEqual(prior);
  });

  it.each([false, true])("refuses a surviving manual company binding without retained company reach (installed=%s)", async installed => {
    const f = await fixture();
    const companyTarget: Install = { targetType: "company", targetId: f.companyId };
    if (installed) await f.seed([companyTarget], "manual");
    else await db.insert(toolProfileBindings).values({
      companyId: f.companyId, profileId: f.appProfile.id, targetType: "company", targetId: f.companyId,
      metadata: { source: "manual" },
    });
    const priorBindings = await f.bindings();
    const priorInstalls = await f.service.listConnectionInstalls(f.connection.id);
    await expect(f.service.putConnectionInstalls(f.connection.id, {
      installs: [{ targetType: "agent", targetId: f.agentIds[7], bindAppProfile: false }],
    })).rejects.toThrow("company-wide app profile");
    expect(await f.bindings()).toEqual(priorBindings);
    expect(await f.service.listConnectionInstalls(f.connection.id)).toEqual(priorInstalls);
  });

  it("allows explicit transport-only new installs even without on-demand configuration", async () => {
    const f = await fixture({});
    const target: Install = { targetType: "agent", targetId: f.agentIds[7], bindAppProfile: false };
    await f.put([target]);
    await f.put([{ targetType: target.targetType, targetId: target.targetId }]);
    expect(await f.bindings()).toEqual([]);
    expect((await f.effective(target.targetId)).allowedTools).toEqual([]);
  });

  it("retains ordinary full-profile binding for non-on-demand additions", async () => {
    const f = await fixture({ onDemandTools: { enabled: false } });
    await f.put([f.targets[0]]);
    expect(await f.bindings()).toHaveLength(1);
    expect((await f.effective(f.targets[0].targetId)).allowedTools).toHaveLength(50);
  });

  it("uses the locked connection configuration rather than a stale pre-transaction read", async () => {
    const f = await fixture({});
    const service = createConnectionInstalls(db, {
      now: () => new Date(),
      getConnectionRow: async () => {
        await db.update(toolConnections).set({ config: { ...f.connection.config, onDemandTools: true } })
          .where(eq(toolConnections.id, f.connection.id));
        return f.connection;
      },
      assertOptionalAgent: async () => {},
    });
    await service.putConnectionInstalls(f.connection.id, { installs: [f.targets[0]] });
    expect(await f.bindings()).toEqual([]);
  });

  it("authorizes explicit unbinding even when the installed agent target is unchanged", async () => {
    const f = await fixture();
    await f.seed();
    const priorBindings = await f.bindings();
    const access = accessModule.accessService(db);
    const decide = vi.fn().mockResolvedValue({ allowed: false });
    const spy = vi.spyOn(accessModule, "accessService").mockReturnValue({ ...access, decide });
    try {
      const app = createRouteApp(db);
      await request(app).put(`/api/tool-connections/${f.connection.id}/installs`)
        .send({ installs: f.targets }).expect(200);
      expect(decide).not.toHaveBeenCalled();
      await request(app).put(`/api/tool-connections/${f.connection.id}/installs`)
        .send({ installs: f.targets.map((install, index) => index === 0 ? { ...install, bindAppProfile: false } : install) })
        .expect(403);
      expect(decide).toHaveBeenCalledWith(expect.objectContaining({
        action: "agent_config:update",
        resource: { type: "agent", companyId: f.companyId, agentId: f.targets[0].targetId },
      }));
      expect(await f.bindings()).toEqual(priorBindings);
    } finally {
      spy.mockRestore();
    }
  });

  it("rolls back a terminated database session before reach insert and reconciles on retry", async () => {
    const f = await fixture({});
    await f.seed();
    const added: Install = { targetType: "agent", targetId: f.agentIds[7], bindAppProfile: false };
    await db.insert(toolProfileBindings).values({
      companyId: f.companyId, profileId: f.appProfile.id, targetType: "agent", targetId: added.targetId,
      metadata: { source: "manual" },
    });
    const priorBindings = await f.bindings();
    const priorInstalls = await f.service.listConnectionInstalls(f.connection.id);
    const functionName = `transport_only_disconnect_${randomUUID().replace(/-/g, "")}`;
    await db.execute(sql.raw(`CREATE FUNCTION ${functionName}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      PERFORM pg_terminate_backend(pg_backend_pid());
      RETURN NEW;
    END $$`));
    await db.execute(sql.raw(`CREATE TRIGGER ${functionName} BEFORE INSERT ON tool_connection_installs
      FOR EACH ROW WHEN (NEW.connection_id = '${f.connection.id}') EXECUTE FUNCTION ${functionName}()`));
    try {
      await expect(f.service.putConnectionInstalls(f.connection.id, { installs: [...f.targets, added] })).rejects.toBeDefined();
      expect(await f.bindings()).toEqual(priorBindings);
      expect(await f.service.listConnectionInstalls(f.connection.id)).toEqual(priorInstalls);
    } finally {
      await db.execute(sql.raw(`DROP TRIGGER ${functionName} ON tool_connection_installs`));
      await db.execute(sql.raw(`DROP FUNCTION ${functionName}()`));
    }
    await f.put([...f.targets, added]);
    await f.put([...f.targets, added]);
    expect(await f.bindings()).toEqual(priorBindings.filter(binding => binding.targetId !== added.targetId));
    expect((await f.effective(added.targetId)).allowedTools).toEqual([]);
  });

  it("rolls back binding deletion, reach and audit when install insertion fails", async () => {
    const f = await fixture({});
    await f.seed();
    const added: Install = { targetType: "agent", targetId: f.agentIds[7], bindAppProfile: false };
    // A stale manual binding must be deleted before the new reach row is inserted.
    await db.insert(toolProfileBindings).values({
      companyId: f.companyId, profileId: f.appProfile.id, targetType: added.targetType, targetId: added.targetId,
      metadata: { source: "manual" },
    });
    const priorBindings = await f.bindings();
    const priorInstalls = await f.service.listConnectionInstalls(f.connection.id);
    const priorAudit = await db.select().from(toolAccessAuditEvents).where(eq(toolAccessAuditEvents.connectionId, f.connection.id));
    const functionName = `transport_only_fail_${randomUUID().replace(/-/g, "")}`;
    await db.execute(sql.raw(`CREATE FUNCTION ${functionName}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
      IF EXISTS (SELECT 1 FROM tool_profile_bindings WHERE profile_id = '${f.appProfile.id}'
        AND target_type = 'agent' AND target_id = '${added.targetId}') THEN
        RAISE EXCEPTION 'app binding still present before reach insert';
      END IF;
      RAISE EXCEPTION 'synthetic transport-only install failure';
    END $$`));
    await db.execute(sql.raw(`CREATE TRIGGER ${functionName} BEFORE INSERT ON tool_connection_installs
      FOR EACH ROW WHEN (NEW.connection_id = '${f.connection.id}') EXECUTE FUNCTION ${functionName}()`));
    try {
      await expect(f.service.putConnectionInstalls(f.connection.id, {
        installs: [...f.targets.map((install, index) => index === 0 ? { ...install, bindAppProfile: false as const } : install), added],
      })).rejects.toMatchObject({ cause: expect.objectContaining({ message: "synthetic transport-only install failure" }) });
      expect(await f.bindings()).toEqual(priorBindings);
      expect(await f.service.listConnectionInstalls(f.connection.id)).toEqual(priorInstalls);
      expect(await db.select().from(toolAccessAuditEvents).where(eq(toolAccessAuditEvents.connectionId, f.connection.id)))
        .toEqual(priorAudit);
    } finally {
      await db.execute(sql.raw(`DROP TRIGGER ${functionName} ON tool_connection_installs`));
      await db.execute(sql.raw(`DROP FUNCTION ${functionName}()`));
    }
  });
});
