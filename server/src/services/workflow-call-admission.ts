import { createHash } from 'node:crypto';
import { canonicalizeWorkflowEnvelope } from './workflow-client-v1.js';
import type { WorkflowIdentity, WorkflowLimits } from './workflow-client-v1.js';

/** Server-owned durable binding, written by the gateway when issuing the assertion.
 * Never construct this record from the introspection caller's claims.
 * runId is execution authority, not a workflow identifier.
 */
export interface WorkflowCallBinding extends WorkflowIdentity {
  invocationId: string;
  runId: string;
  connectionId: string;
  route: string;
  assertion: string;
  canonical: string;
  issuer: string;
  jti: string;
  expiresAt: number;
}

export interface WorkflowCallAdmissionDependencies {
  limits: WorkflowLimits;
  nowSeconds(): number;
  /** Must verify the dedicated service identity and its fixed audience/route scope. */
  authenticateService(credential: unknown): Promise<boolean>;
  /** Reads only server-persisted assertion bindings; absent/terminal work returns null. */
  loadBinding(invocationId: string): Promise<WorkflowCallBinding | null>;
  /** Must lock and compare the entire binding again in the invocation transaction,
   * re-resolve principal/run/connection/grant and composed gateway policy, and use
   * admitWorkflowCall's durable rate receipts. Approval must already be owned by
   * the exact gateway claim: never claim/consume an approval here. Return true only
   * after commit. Must reject changed/terminal bindings. No dispatch, no positive
   * cache. This boundary intentionally cannot be implemented by executeTool.
   */
  admitBoundCall(binding: Readonly<WorkflowCallBinding>): Promise<boolean>;
}

/** Unregistered call-only introspection seam. No endpoint, keys, transport or
 * default adapter. Open/close, delegated approval plumbing, cancellation and
 * durable binding persistence remain gateway integration prerequisites.
 * Hub signature verification and atomic anti-replay are still mandatory.
 */
export function workflowCallAdmission(deps: WorkflowCallAdmissionDependencies) {
  return async (credential: unknown, invocationId: string, assertion: string, rawEnvelope: string) => {
    const unavailable = () => { throw new Error('workflow admission unavailable'); };
    // Fail closed; do not expose handles, credentials, payload or storage errors.
    try {
      if (!await deps.authenticateService(credential)) return unavailable();
      if (!invocationId || typeof assertion !== 'string' || !assertion) return unavailable();
      const canonical = canonicalizeWorkflowEnvelope(rawEnvelope, deps.limits);
      const envelope = JSON.parse(canonical);
      if (envelope.operation !== 'call') return unavailable();
      const loaded = await deps.loadBinding(invocationId);
      if (!loaded) return unavailable();
      // Snapshot before awaiting admission: injected storage cannot mutate the
      // context whose identity will be returned after the transaction commits.
      const binding = Object.freeze({ ...loaded, owner: Object.freeze({ ...loaded.owner }) });
      const now = deps.nowSeconds();
      if (!Number.isSafeInteger(now) || !Number.isSafeInteger(binding.expiresAt) || binding.expiresAt <= now
        || binding.invocationId !== invocationId || binding.assertion !== assertion || binding.canonical !== canonical
        || binding.connectionId !== envelope.connectionId || binding.route !== envelope.route
        || !binding.runId || !binding.owner.type || !binding.owner.id || !binding.companyId || !binding.grantId
        || !binding.issuer || !binding.jti) return unavailable();
      if (!await deps.admitBoundCall(binding)) return unavailable();
      if (binding.expiresAt <= deps.nowSeconds()) return unavailable();
      return {
        version: 1 as const, jti: binding.jti, requestId: envelope.requestId,
        payloadHash: createHash('sha256').update(canonical, 'utf8').digest('base64url'),
        issuer: binding.issuer, owner: { ...binding.owner }, companyId: binding.companyId,
        connectionId: binding.connectionId, grantId: binding.grantId, route: binding.route,
        operation: 'call' as const, allowed: true as const,
      };
    } catch {
      return unavailable();
    }
  };
}
