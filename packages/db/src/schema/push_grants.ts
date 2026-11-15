import type { PushGrantForge, PushGrantMode, PushGrantOutcome } from "@paperclipai/shared";
import { index, pgTable, text, timestamp, uniqueIndex, uuid, varchar } from "drizzle-orm/pg-core";
import { agents } from "./agents.js";
import { companies } from "./companies.js";
import { heartbeatRuns } from "./heartbeat_runs.js";
import { issueThreadInteractions } from "./issue_thread_interactions.js";
import { issues } from "./issues.js";

export const pushGrants = pgTable(
  "push_grants",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id")
      .notNull()
      .references(() => companies.id, { onDelete: "cascade" }),
    issueId: uuid("issue_id")
      .notNull()
      .references(() => issues.id, { onDelete: "cascade" }),
    interactionId: uuid("interaction_id")
      .notNull()
      .references(() => issueThreadInteractions.id, { onDelete: "restrict" }),
    agentId: uuid("agent_id")
      .notNull()
      .references(() => agents.id, { onDelete: "cascade" }),
    runId: uuid("run_id")
      .notNull()
      .references(() => heartbeatRuns.id, { onDelete: "cascade" }),
    repository: text("repository").notNull(),
    forge: text("forge").$type<PushGrantForge>().notNull(),
    ref: text("ref").notNull(),
    expectedOldSha: varchar("expected_old_sha", { length: 40 }).notNull(),
    newSha: varchar("new_sha", { length: 40 }).notNull(),
    mode: text("mode").$type<PushGrantMode>().notNull(),
    issuedAt: timestamp("issued_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    outcome: text("outcome").$type<PushGrantOutcome>().notNull().default("issued"),
    requestId: text("request_id").notNull(),
    argumentsHash: text("arguments_hash").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    companyRequestIdUq: uniqueIndex("push_grants_company_request_id_uq").on(table.companyId, table.requestId),
    companyRepoRefConsumedIdx: index("push_grants_company_repo_ref_consumed_idx").on(
      table.companyId,
      table.repository,
      table.ref,
      table.consumedAt,
    ),
    companyExpiresAtIdx: index("push_grants_company_expires_at_idx").on(table.companyId, table.expiresAt),
    companyIssueIdx: index("push_grants_company_issue_idx").on(table.companyId, table.issueId),
  }),
);
