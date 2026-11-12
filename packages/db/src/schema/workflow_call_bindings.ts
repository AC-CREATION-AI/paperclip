import { jsonb, pgTable, text, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { companies } from "./companies.js";
import { toolInvocations } from "./tool_access.js";

// Private server assertion material; never include this row in invocation API responses.
// The invocation owns its lifecycle and deletion. Writers must lock it first.
export const workflowCallBindings = pgTable("workflow_call_bindings", {
  invocationId: uuid("invocation_id").primaryKey().references(() => toolInvocations.id, { onDelete: "cascade" }),
  companyId: uuid("company_id").notNull().references(() => companies.id, { onDelete: "cascade" }),
  issuer: text("issuer").notNull(),
  jti: text("jti").notNull(),
  binding: jsonb("binding").$type<Record<string, unknown>>().notNull(),
}, table => [uniqueIndex("workflow_call_bindings_issuer_jti_uq").on(table.issuer, table.jti)]);
