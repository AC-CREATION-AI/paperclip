import { z } from "zod";

export const pushGrantForgeSchema = z.enum(["gitea", "github"]);

export const pushGrantModeSchema = z.enum(["fast-forward", "force-with-lease"]);

export const pushGrantOutcomeSchema = z.enum([
  "issued",
  "consumed",
  "revoked",
  "expired",
  "rejected",
  "failed",
  // The push may or may not have reached the forge: blocks the agreement for good.
  "unknown",
]);

/** Grant outcomes without any external effect: the agreement may be used again (ACC-4966 H1.b). */
export const PUSH_GRANT_REUSABLE_OUTCOMES = ["failed", "expired", "revoked", "rejected"] as const;

/** Default branches on which only fast-forward publication is allowed in v1 (ACC-4966 M2). */
export const PUSH_GRANT_PROTECTED_REFS = ["refs/heads/main", "refs/heads/master", "refs/heads/trunk"] as const;

export const pushGrantReceiptStatusSchema = z.enum([
  "reserved",
  "completed",
  "unknown",
]);

const sha40Regex = /^[0-9a-fA-F]{40}$/;
const headsRefRegex = /^refs\/heads\/[a-zA-Z0-9_.\/-]+$/;
const repositoryRegex = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

/**
 * Structured human push agreement (ACC-4966 H1.a). The `detailsMarkdown` of the
 * accepted `request_confirmation` must be exactly this JSON object, nothing else.
 */
export const pushGrantAgreementSchema = z
  .object({
    kind: z.literal("push_grant"),
    repository: z.string().regex(repositoryRegex),
    ref: z.string().regex(headsRefRegex),
    mode: pushGrantModeSchema,
    expectedOldSha: z.string().regex(sha40Regex),
    newSha: z.string().regex(sha40Regex),
  })
  .strict();

export const createPushGrantInputSchema = z
  .object({
    issueId: z.string().uuid(),
    interactionId: z.string().uuid(),
    repository: z.string().trim().min(1).max(200),
    forge: pushGrantForgeSchema,
    ref: z
      .string()
      .trim()
      .min(1)
      .max(300)
      .regex(headsRefRegex, "Must be a full refs/heads/* reference without wildcards"),
    expectedOldSha: z
      .string()
      .trim()
      .regex(sha40Regex, "expectedOldSha must be a 40-character hex SHA"),
    newSha: z
      .string()
      .trim()
      .regex(sha40Regex, "newSha must be a 40-character hex SHA"),
    mode: pushGrantModeSchema,
    ttlSeconds: z.number().int().min(1).max(120).default(120),
    requestId: z.string().trim().min(1).max(128),
  })
  .strict();

export const consumePushGrantInputSchema = z
  .object({
    repository: z.string().trim().min(1).max(200),
    ref: z
      .string()
      .trim()
      .min(1)
      .max(300)
      .regex(headsRefRegex, "Must be a full refs/heads/* reference without wildcards"),
    expectedOldSha: z
      .string()
      .trim()
      .regex(sha40Regex, "expectedOldSha must be a 40-character hex SHA"),
    newSha: z
      .string()
      .trim()
      .regex(sha40Regex, "newSha must be a 40-character hex SHA"),
    requestId: z.string().trim().min(1).max(128),
  })
  .strict();

export type PushGrantForge = z.infer<typeof pushGrantForgeSchema>;
export type PushGrantMode = z.infer<typeof pushGrantModeSchema>;
export type PushGrantOutcome = z.infer<typeof pushGrantOutcomeSchema>;
export type PushGrantReceiptStatus = z.infer<typeof pushGrantReceiptStatusSchema>;
export type CreatePushGrantInput = z.infer<typeof createPushGrantInputSchema>;
export type ConsumePushGrantInput = z.infer<typeof consumePushGrantInputSchema>;
export type PushGrantAgreement = z.infer<typeof pushGrantAgreementSchema>;
