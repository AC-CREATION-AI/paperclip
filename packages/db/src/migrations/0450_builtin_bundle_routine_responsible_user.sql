-- Built-in bundle installs persisted the synthetic "built-in-bundles" actor as
-- the routine's responsible user. That pseudo-user is not a company member, so
-- every run descending from those routines failed setup with
-- RESPONSIBLE_USER_UNAVAILABLE. Resolve a real responsible user the way the
-- service now does — the company default, else its first active owner — and
-- only rewrite the rows that still name the marker.
UPDATE "routines" AS "routine"
SET "responsible_user_id" = "resolved"."user_id"
FROM (
  SELECT "company"."id" AS "company_id",
    coalesce(
      "company"."default_responsible_user_id",
      (
        SELECT "membership"."principal_id" FROM "company_memberships" AS "membership"
        WHERE "membership"."company_id" = "company"."id"
          AND "membership"."principal_type" = 'user'
          AND "membership"."status" = 'active'
          AND "membership"."membership_role" = 'owner'
        ORDER BY "membership"."created_at", "membership"."id"
        LIMIT 1
      )
    ) AS "user_id"
  FROM "companies" AS "company"
) AS "resolved"
WHERE "routine"."company_id" = "resolved"."company_id"
  AND "routine"."responsible_user_id" = 'built-in-bundles'
  AND "resolved"."user_id" IS NOT NULL
  AND "resolved"."user_id" <> 'built-in-bundles';--> statement-breakpoint
-- A routine's latest revision feeds run seeding from its column and its
-- snapshot, and both were written together. Repair the revisions that still
-- name the marker from the routine row repaired above (or already repaired by
-- an operator); a routine that could not be resolved keeps its revisions
-- unchanged rather than diverging from it.
UPDATE "routine_revisions" AS "revision"
SET "responsible_user_id" = "routine"."responsible_user_id",
  "snapshot" = jsonb_set(
    "revision"."snapshot",
    '{routine,responsibleUserId}',
    to_jsonb("routine"."responsible_user_id")
  )
FROM "routines" AS "routine"
WHERE "routine"."id" = "revision"."routine_id"
  AND "revision"."responsible_user_id" = 'built-in-bundles'
  AND "routine"."responsible_user_id" <> 'built-in-bundles'
  AND "routine"."responsible_user_id" IS NOT NULL;
