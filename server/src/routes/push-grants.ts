import { Router, type Request } from "express";
import type { Db } from "@paperclipai/db";
import { consumePushGrantInputSchema, createPushGrantInputSchema, isUuidLike } from "@paperclipai/shared";
import { forbidden, notFound, unauthorized } from "../errors.js";
import { verifyRuntimeToolsToken } from "../runtime-tools-token.js";
import { pushGrantService, type PushGrantDeps } from "../services/push-grants.js";

function bearer(req: Request) {
  const value = req.header("authorization") ?? "";
  return /^Bearer\s+/i.test(value) ? value.replace(/^Bearer\s+/i, "").trim() : "";
}

/**
 * Push authority routes (ACC-4931). Mounted before the general actor middleware:
 * they accept only a run-bound `push_grant` runtime capability, never a board
 * session, agent API key or browser request.
 */
export function pushGrantRoutes(db: Db, deps: PushGrantDeps = {}) {
  const router = Router();
  const service = pushGrantService(db, deps);

  function claimsFor(req: Request) {
    // Browsers send Origin, Cookie or Sec-Fetch-Site; runtime fetch does not.
    if (req.headers.origin || req.headers.cookie || req.headers["sec-fetch-site"]) {
      throw forbidden("Push grants require runtime authentication");
    }
    const claims = verifyRuntimeToolsToken(bearer(req), "push_grant");
    if (!claims) throw unauthorized("Invalid push_grant runtime capability");
    if (claims.company_id !== req.params.companyId) throw forbidden("Runtime capability belongs to another company");
    return claims;
  }

  router.post("/companies/:companyId/push-grants", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const claims = claimsFor(req);
    const input = createPushGrantInputSchema.parse(req.body ?? {});
    res.status(201).json(await service.issue(claims, input));
  });

  router.post("/companies/:companyId/push-grants/:grantId/consume", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    const claims = claimsFor(req);
    if (!isUuidLike(req.params.grantId)) throw notFound("Push grant not found");
    const input = consumePushGrantInputSchema.parse(req.body ?? {});
    res.json(await service.consume(claims, req.params.grantId as string, input));
  });

  return router;
}
