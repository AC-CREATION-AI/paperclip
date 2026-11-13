import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { connectionGrants, createDb } from "@paperclipai/db";
import { githubCredentialsFixture } from "./helpers/github-credentials-fixture.js";
import { getEmbeddedPostgresTestSupport, startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";
import { resolveManagedGitHubIdentitySelection } from "../services/git-credentials.js";

const support = await getEmbeddedPostgresTestSupport();
(support.supported ? describe : describe.skip)("organization bearer is not a managed agent identity", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
  let db: ReturnType<typeof createDb>;
  beforeAll(async () => {
    database = await startEmbeddedPostgresTestDatabase("paperclip-org-identity-");
    db = createDb(database.connectionString);
  }, 90_000);
  afterAll(async () => { await db?.$client.end({ timeout: 1 }); await database?.cleanup(); });
  const { seed, grant } = githubCredentialsFixture(() => db);

  it("does not infer an agent identity from an organization bearer", async () => {
    const input = await seed();
    const authorization = await grant(input, "A", true);
    await db.update(connectionGrants).set({
      kind: "organization", subjectAgentId: null, isDefault: true, providerTenant: null,
      credentialSecretRefs: [{ secretId: authorization.secretId, configPath: "credentials.authorization" }],
    }).where(eq(connectionGrants.id, authorization.id));
    const selection = await resolveManagedGitHubIdentitySelection(db, input.companyId, {
      agentId: input.agentId, responsibleUserId: "A",
    });
    expect(selection).toMatchObject({ configured: true, error: "No managed GitHub identity is available for this run" });
    expect(selection.grant).toBeUndefined();
  });

  it.each([1, 2, 3, 4, 5, 6, 7])("preserves dedicated precedence for existing consumer %s", async () => {
    const input = await seed();
    const dedicated = await grant(input, "A", true);
    await db.insert(connectionGrants).values({
      companyId: input.companyId, connectionId: dedicated.connectionId, kind: "organization",
      isDefault: true, status: "active", credentialSecretRefs: [],
    });
    const selection = await resolveManagedGitHubIdentitySelection(db, input.companyId, {
      agentId: input.agentId, responsibleUserId: "A",
    });
    expect(selection.grant?.id).toBe(dedicated.id);
    expect(selection.identitySource).toBe("dedicated");
  });
});
