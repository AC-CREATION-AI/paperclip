CREATE TABLE "workflow_call_bindings" (
	"invocation_id" uuid PRIMARY KEY NOT NULL,
	"company_id" uuid NOT NULL,
	"issuer" text NOT NULL,
	"jti" text NOT NULL,
	"binding" jsonb NOT NULL
);
--> statement-breakpoint
ALTER TABLE "workflow_call_bindings" ADD CONSTRAINT "workflow_call_bindings_invocation_id_tool_invocations_id_fk" FOREIGN KEY ("invocation_id") REFERENCES "public"."tool_invocations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "workflow_call_bindings" ADD CONSTRAINT "workflow_call_bindings_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "workflow_call_bindings_issuer_jti_uq" ON "workflow_call_bindings" USING btree ("issuer","jti");