import type { PushGrantForge } from "@paperclipai/shared";
import { sql } from "drizzle-orm";
import { pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { companies } from "./companies.js";

/**
 * Server-side allowlist of the repositories a company may publish to through
 * push grants (ACC-4966 M2). Read by the push grant service at issue and at
 * consumption; a repository that is not listed here is refused (422), whatever
 * the human agreement says. There is no API to write it in v1: rows are added
 * by the operator at activation time (see the `interface` document of ACC-4931).
 */
export const pushGrantRepositories = pgTable(
  "push_grant_repositories",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id")
      .notNull()
      .references(() => companies.id, { onDelete: "cascade" }),
    forge: text("forge").$type<PushGrantForge>().notNull(),
    /** Canonical `owner/name`, compared case-insensitively. */
    repository: text("repository").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    companyForgeRepositoryUq: uniqueIndex("push_grant_repositories_company_forge_repository_uq").on(
      table.companyId,
      table.forge,
      sql`lower(${table.repository})`,
    ),
  }),
);
