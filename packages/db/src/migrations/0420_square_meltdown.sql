CREATE TABLE "push_grant_receipts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"grant_id" uuid NOT NULL,
	"request_id" text NOT NULL,
	"arguments_hash" text NOT NULL,
	"status" text NOT NULL,
	"result" jsonb,
	"error_code" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "push_grants" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"company_id" uuid NOT NULL,
	"issue_id" uuid NOT NULL,
	"interaction_id" uuid NOT NULL,
	"agent_id" uuid NOT NULL,
	"run_id" uuid NOT NULL,
	"repository" text NOT NULL,
	"forge" text NOT NULL,
	"ref" text NOT NULL,
	"expected_old_sha" varchar(40) NOT NULL,
	"new_sha" varchar(40) NOT NULL,
	"mode" text NOT NULL,
	"issued_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"consumed_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"outcome" text DEFAULT 'issued' NOT NULL,
	"request_id" text NOT NULL,
	"arguments_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "push_grant_receipts" ADD CONSTRAINT "push_grant_receipts_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_grant_receipts" ADD CONSTRAINT "push_grant_receipts_grant_id_push_grants_id_fk" FOREIGN KEY ("grant_id") REFERENCES "public"."push_grants"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_grants" ADD CONSTRAINT "push_grants_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_grants" ADD CONSTRAINT "push_grants_issue_id_issues_id_fk" FOREIGN KEY ("issue_id") REFERENCES "public"."issues"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_grants" ADD CONSTRAINT "push_grants_interaction_id_issue_thread_interactions_id_fk" FOREIGN KEY ("interaction_id") REFERENCES "public"."issue_thread_interactions"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_grants" ADD CONSTRAINT "push_grants_agent_id_agents_id_fk" FOREIGN KEY ("agent_id") REFERENCES "public"."agents"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_grants" ADD CONSTRAINT "push_grants_run_id_heartbeat_runs_id_fk" FOREIGN KEY ("run_id") REFERENCES "public"."heartbeat_runs"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "push_grant_receipts_company_request_id_uq" ON "push_grant_receipts" USING btree ("company_id","request_id");--> statement-breakpoint
CREATE INDEX "push_grant_receipts_company_grant_idx" ON "push_grant_receipts" USING btree ("company_id","grant_id");--> statement-breakpoint
CREATE UNIQUE INDEX "push_grants_company_request_id_uq" ON "push_grants" USING btree ("company_id","request_id");--> statement-breakpoint
CREATE INDEX "push_grants_company_repo_ref_consumed_idx" ON "push_grants" USING btree ("company_id","repository","ref","consumed_at");--> statement-breakpoint
CREATE INDEX "push_grants_company_expires_at_idx" ON "push_grants" USING btree ("company_id","expires_at");--> statement-breakpoint
CREATE INDEX "push_grants_company_issue_idx" ON "push_grants" USING btree ("company_id","issue_id");