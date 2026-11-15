import type { PushGrantReceiptStatus } from "@paperclipai/shared";
import { index, jsonb, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { companies } from "./companies.js";
import { pushGrants } from "./push_grants.js";

export const pushGrantReceipts = pgTable(
  "push_grant_receipts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    companyId: uuid("company_id")
      .notNull()
      .references(() => companies.id, { onDelete: "cascade" }),
    grantId: uuid("grant_id")
      .notNull()
      .references(() => pushGrants.id, { onDelete: "cascade" }),
    requestId: text("request_id").notNull(),
    argumentsHash: text("arguments_hash").notNull(),
    status: text("status").$type<PushGrantReceiptStatus>().notNull(),
    result: jsonb("result").$type<Record<string, unknown>>(),
    errorCode: text("error_code"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    companyRequestIdUq: uniqueIndex("push_grant_receipts_company_request_id_uq").on(table.companyId, table.requestId),
    companyGrantIdx: index("push_grant_receipts_company_grant_idx").on(table.companyId, table.grantId),
  }),
);
