import { randomUUID } from "node:crypto";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  agents,
  closeRegisteredClients,
  companies,
  connectionGrants,
  createDb,
  toolAccessAuditEvents,
  toolApplications,
  toolConnectionInstallRevisions,
  toolConnectionInstalls,
  toolConnections,
  type Db,
} from "@paperclipai/db";
import { and, eq } from "drizzle-orm";
import { errorHandler } from "../middleware/index.js";
import { toolAccessRoutes } from "../routes/tool-access.js";
import { toolAccessService } from "../services/tool-access.js";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";

// ACC-4941: per-connection compare-and-write on install replacement, enforced
// for every write path (REST, internal services, raw SQL from another process).

const externalDatabaseUrl = process.env.PAPERCLIP_TOOL_ACCESS_TEST_DATABASE_URL?.trim();
const support = externalDatabaseUrl ? { supported: true } : await getEmbeddedPostgresTestSupport();
const describeDatabase = support.supported ? describe : describe.skip;

type Target = { targetType: "company" | "agent"; targetId: string };

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

describeDatabase("tool connection installs revision (compare-and-write)", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let connectionString: string;
  // Two independent pools stand in for two Paperclip processes on one database.
  let dbA: Db;
  let dbB: Db;

  beforeAll(async () => {
    if (externalDatabaseUrl) {
      connectionString = externalDatabaseUrl;
    } else {
      database = await startEmbeddedPostgresTestDatabase("paperclip-install-revision-");
      connectionString = database.connectionString;
    }
    dbA = createDb(connectionString);
    dbB = createDb(connectionString);
  }, 90_000);

  afterAll(async () => {
    await closeRegisteredClients(connectionString);
    await database?.cleanup();
  });

  async function fixture() {
    const [company] = await dbA.insert(companies).values({
      name: "Install revision fixture",
      issuePrefix: `IR${randomUUID().slice(0, 6)}`,
    }).returning();
    const companyId = company.id;
    const agentIds = [randomUUID(), randomUUID(), randomUUID()];
    await dbA.insert(agents).values(agentIds.map(id => ({
      id, companyId, name: id, status: "active", adapterType: "process",
    })));
    const [application] = await dbA.insert(toolApplications).values({
      companyId, name: "Fixture app", type: "mcp_http",
    }).returning();
    const makeConnection = async (name: string) => {
      const [connection] = await dbA.insert(toolConnections).values({
        companyId, applicationId: application.id, name, uid: randomUUID(),
        transport: "mcp_remote", status: "active", enabled: true,
        config: { mcpAgentAccessConfigured: true },
      }).returning();
      await dbA.insert(connectionGrants).values({
        companyId, connectionId: connection.id, kind: "organization", status: "active", isDefault: true,
      });
      return connection;
    };
    const connection = await makeConnection("Fixture connection");
    // An unrelated company-wide install that must never move.
    const other = await makeConnection("Company-wide connection");
    await dbA.insert(toolConnectionInstalls).values({
      companyId, connectionId: other.id, targetType: "company", targetId: companyId,
    });
    const appA = createRouteApp(dbA);
    const appB = createRouteApp(dbB);
    const get = (app: express.Express, id = connection.id) => request(app).get(`/api/tool-connections/${id}/installs`);
    const put = (app: express.Express, installs: Target[], expectedRevision?: number) =>
      request(app).put(`/api/tool-connections/${connection.id}/installs`)
        .send(expectedRevision === undefined ? { installs } : { installs, expectedRevision });
    const rows = async (id = connection.id) => (await dbA.select({ targetType: toolConnectionInstalls.targetType, targetId: toolConnectionInstalls.targetId })
      .from(toolConnectionInstalls).where(eq(toolConnectionInstalls.connectionId, id)))
      .map(row => `${row.targetType}:${row.targetId}`).sort();
    const revision = async (id = connection.id) => (await dbA.select({ revision: toolConnectionInstallRevisions.revision })
      .from(toolConnectionInstallRevisions).where(eq(toolConnectionInstallRevisions.connectionId, id)))[0]?.revision ?? 0;
    const audits = () => dbA.select().from(toolAccessAuditEvents).where(and(
      eq(toolAccessAuditEvents.connectionId, connection.id), eq(toolAccessAuditEvents.action, "connection_installs.changed"),
    ));
    return { companyId, agentIds, connection, other, appA, appB, get, put, rows, revision, audits };
  }

  it("requires expectedRevision on the REST route", async () => {
    const f = await fixture();
    const response = await f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[0] }]);
    expect(response.status).toBe(400);
    expect(await f.rows()).toEqual([]);
  });

  it("exposes the revision on GET and advances it on every successful write", async () => {
    const f = await fixture();
    const initial = await f.get(f.appA).expect(200);
    expect(initial.body).toMatchObject({ connectionId: f.connection.id, installs: [], revision: 0 });
    const saved = await f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[0] }], 0).expect(200);
    expect(saved.body.revision).toBeGreaterThan(0);
    const reread = await f.get(f.appA).expect(200);
    expect(reread.body.revision).toBe(saved.body.revision);
    expect(reread.body.installs.map((row: Target) => row.targetId)).toEqual([f.agentIds[0]]);
  });

  it("two writers on the same revision: exactly one succeeds, the other gets 409 and loses nothing", async () => {
    const f = await fixture();
    await f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[0] }], 0).expect(200);
    const { body: read } = await f.get(f.appA).expect(200);
    const base: Target[] = read.installs.map(({ targetType, targetId }: Target) => ({ targetType, targetId }));
    const auditsBefore = (await f.audits()).length;
    const otherBefore = await f.rows(f.other.id);
    const otherRevisionBefore = await f.revision(f.other.id);

    // Writer A (process A) adds agent 1; writer B (process B) adds agent 2.
    // Both read the same revision and fire at the same time.
    const [first, second] = await Promise.all([
      f.put(f.appA, [...base, { targetType: "agent", targetId: f.agentIds[1] }], read.revision),
      f.put(f.appB, [...base, { targetType: "agent", targetId: f.agentIds[2] }], read.revision),
    ]);
    const statuses = [first.status, second.status].sort();
    expect(statuses).toEqual([200, 409]);
    const winner = first.status === 200 ? first : second;
    const loser = first.status === 200 ? second : first;
    const winnerAgent = first.status === 200 ? f.agentIds[1] : f.agentIds[2];
    expect(loser.body).toMatchObject({ code: "installs_revision_conflict" });

    // The winner's set is persisted exactly; the loser mutated nothing.
    expect(await f.rows()).toEqual([`agent:${f.agentIds[0]}`, `agent:${winnerAgent}`].sort());
    expect(await f.revision()).toBe(winner.body.revision);
    expect((await f.audits()).length).toBe(auditsBefore + 1);
    // Unrelated company-wide install untouched.
    expect(await f.rows(f.other.id)).toEqual(otherBefore);
    expect(await f.revision(f.other.id)).toBe(otherRevisionBefore);

    // The loser recovers by re-reading: nothing of the winner is lost.
    const { body: fresh } = await f.get(f.appB).expect(200);
    const merged: Target[] = [
      ...fresh.installs.map(({ targetType, targetId }: Target) => ({ targetType, targetId })),
      { targetType: "agent", targetId: first.status === 200 ? f.agentIds[2] : f.agentIds[1] },
    ];
    await f.put(f.appB, merged, fresh.revision).expect(200);
    expect(await f.rows()).toEqual(f.agentIds.map(id => `agent:${id}`).sort());
  });

  it("a removal racing an addition cannot resurrect or drop the other writer's change", async () => {
    const f = await fixture();
    await f.put(f.appA, [
      { targetType: "agent", targetId: f.agentIds[0] },
      { targetType: "agent", targetId: f.agentIds[1] },
    ], 0).expect(200);
    const { body: read } = await f.get(f.appA).expect(200);
    const [remove, add] = await Promise.all([
      f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[1] }], read.revision),
      f.put(f.appB, [
        { targetType: "agent", targetId: f.agentIds[0] },
        { targetType: "agent", targetId: f.agentIds[1] },
        { targetType: "agent", targetId: f.agentIds[2] },
      ], read.revision),
    ]);
    expect([remove.status, add.status].sort()).toEqual([200, 409]);
    const expected = remove.status === 200
      ? [`agent:${f.agentIds[1]}`]
      : f.agentIds.map(id => `agent:${id}`).sort();
    expect(await f.rows()).toEqual(expected);
  });

  it("internal unversioned writers and raw SQL from another process still invalidate a stale revision", async () => {
    const f = await fixture();
    const { body: read } = await f.get(f.appA).expect(200);

    // Internal service path without expectedRevision (process B).
    await toolAccessService(dbB).putConnectionInstalls(f.connection.id, {
      installs: [{ targetType: "agent", targetId: f.agentIds[0] }],
    });
    const stale = await f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[1] }], read.revision);
    expect(stale.status).toBe(409);
    expect(await f.rows()).toEqual([`agent:${f.agentIds[0]}`]);

    // A writer that bypasses the service entirely (raw insert, other process).
    const { body: afterService } = await f.get(f.appA).expect(200);
    await dbB.insert(toolConnectionInstalls).values({
      companyId: f.companyId, connectionId: f.connection.id, targetType: "agent", targetId: f.agentIds[2],
    });
    expect(await f.revision()).toBe(afterService.revision + 1);
    const staleAgain = await f.put(f.appA, [], afterService.revision);
    expect(staleAgain.status).toBe(409);
    expect(await f.rows()).toEqual([`agent:${f.agentIds[0]}`, `agent:${f.agentIds[2]}`].sort());

    // Raw delete bumps too.
    const { body: beforeDelete } = await f.get(f.appA).expect(200);
    await dbB.delete(toolConnectionInstalls).where(and(
      eq(toolConnectionInstalls.connectionId, f.connection.id), eq(toolConnectionInstalls.targetId, f.agentIds[2]),
    ));
    expect(await f.revision()).toBe(beforeDelete.revision + 1);
    expect((await f.put(f.appA, [], beforeDelete.revision)).status).toBe(409);
    expect(await f.rows()).toEqual([`agent:${f.agentIds[0]}`]);
  });

  it("a no-op save keeps the revision and a stale no-op is still rejected", async () => {
    const f = await fixture();
    const saved = await f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[0] }], 0).expect(200);
    const same = await f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[0] }], saved.body.revision).expect(200);
    expect(same.body.revision).toBe(saved.body.revision);
    expect((await f.put(f.appA, [{ targetType: "agent", targetId: f.agentIds[0] }], 0)).status).toBe(409);
  });
});
