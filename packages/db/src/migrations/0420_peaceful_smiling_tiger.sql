CREATE TABLE "tool_connection_install_revisions" (
	"connection_id" uuid PRIMARY KEY NOT NULL,
	"company_id" uuid NOT NULL,
	"revision" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "tool_connection_install_revisions" ADD CONSTRAINT "tool_connection_install_revisions_connection_id_tool_connections_id_fk" FOREIGN KEY ("connection_id") REFERENCES "public"."tool_connections"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tool_connection_install_revisions" ADD CONSTRAINT "tool_connection_install_revisions_company_id_companies_id_fk" FOREIGN KEY ("company_id") REFERENCES "public"."companies"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "tool_connection_install_revisions_company_idx" ON "tool_connection_install_revisions" USING btree ("company_id");--> statement-breakpoint
CREATE OR REPLACE FUNCTION paperclip_bump_tool_connection_install_revision() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  -- Every writer of tool_connection_installs (REST, internal services, other
  -- processes on this database) advances the per-connection revision in the
  -- same transaction. Connections deleted in the same statement (cascade) are
  -- skipped by the join. Ordered upsert keeps row-lock order deterministic.
  IF TG_OP = 'INSERT' THEN
    INSERT INTO tool_connection_install_revisions AS r (connection_id, company_id, revision, updated_at)
    SELECT c.id, c.company_id, 1, now()
    FROM (SELECT DISTINCT connection_id FROM new_rows) changed
    JOIN tool_connections c ON c.id = changed.connection_id
    ORDER BY c.id
    ON CONFLICT (connection_id) DO UPDATE SET revision = r.revision + 1, updated_at = now();
  ELSIF TG_OP = 'DELETE' THEN
    INSERT INTO tool_connection_install_revisions AS r (connection_id, company_id, revision, updated_at)
    SELECT c.id, c.company_id, 1, now()
    FROM (SELECT DISTINCT connection_id FROM old_rows) changed
    JOIN tool_connections c ON c.id = changed.connection_id
    ORDER BY c.id
    ON CONFLICT (connection_id) DO UPDATE SET revision = r.revision + 1, updated_at = now();
  ELSE
    INSERT INTO tool_connection_install_revisions AS r (connection_id, company_id, revision, updated_at)
    SELECT c.id, c.company_id, 1, now()
    FROM (SELECT connection_id FROM old_rows UNION SELECT connection_id FROM new_rows) changed
    JOIN tool_connections c ON c.id = changed.connection_id
    ORDER BY c.id
    ON CONFLICT (connection_id) DO UPDATE SET revision = r.revision + 1, updated_at = now();
  END IF;
  RETURN NULL;
END;
$$;
--> statement-breakpoint
DROP TRIGGER IF EXISTS paperclip_tool_connection_install_revision_insert ON tool_connection_installs;--> statement-breakpoint
DROP TRIGGER IF EXISTS paperclip_tool_connection_install_revision_update ON tool_connection_installs;--> statement-breakpoint
DROP TRIGGER IF EXISTS paperclip_tool_connection_install_revision_delete ON tool_connection_installs;--> statement-breakpoint
CREATE TRIGGER paperclip_tool_connection_install_revision_insert AFTER INSERT ON tool_connection_installs
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION paperclip_bump_tool_connection_install_revision();--> statement-breakpoint
CREATE TRIGGER paperclip_tool_connection_install_revision_update AFTER UPDATE ON tool_connection_installs
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION paperclip_bump_tool_connection_install_revision();--> statement-breakpoint
CREATE TRIGGER paperclip_tool_connection_install_revision_delete AFTER DELETE ON tool_connection_installs
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION paperclip_bump_tool_connection_install_revision();
