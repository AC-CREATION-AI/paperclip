import { createHash, randomUUID, sign } from 'node:crypto';
import type { KeyObject } from 'node:crypto';

export interface WorkflowLimits { maxBytes: number; maxDepth: number }
export interface WorkflowIdentity {
  owner: { type: string; id: string };
  companyId: string;
  grantId: string;
}
export interface WorkflowApplicationKey {
  purpose: 'workflow-application';
  privateKey: KeyObject;
  kid: string;
  issuer: string;
  audience: string;
  ttlSeconds: number;
}

const invalid = (): never => { throw new Error('invalid workflow request'); };
const text = (v: unknown): v is string => typeof v === 'string' && v.length > 0;
function unicode(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const low = s.charCodeAt(++i);
      if (!(low >= 0xdc00 && low <= 0xdfff)) invalid();
    } else if (c >= 0xdc00 && c <= 0xdfff) invalid();
  }
}

// Parse raw JSON rather than an object: JSON.parse alone silently loses duplicates.
// No transport, key discovery, environment credentials or gateway activation here.
export function canonicalizeWorkflowEnvelope(raw: string, limits: WorkflowLimits): string {
  if (typeof raw !== 'string' || !Number.isSafeInteger(limits.maxBytes) || limits.maxBytes <= 0 ||
      !Number.isSafeInteger(limits.maxDepth) || limits.maxDepth <= 0 || limits.maxDepth > 128 ||
      Buffer.byteLength(raw, 'utf8') > limits.maxBytes) invalid();
  unicode(raw);
  let i = 0;
  let versionLiteral = '';
  const ws = () => { while (/[\x20\t\r\n]/.test(raw[i] ?? '') && i < raw.length) i++; };
  const string = (): string => {
    const start = i++;
    while (i < raw.length) {
      const c = raw[i++];
      if (c === '\\') { i++; continue; }
      if (c === '"') {
        const s: string = JSON.parse(raw.slice(start, i)); unicode(s); return s;
      }
    }
    return invalid();
  };
  const value = (depth: number): unknown => {
    ws();
    if (raw[i] === '"') return string();
    if (raw[i] === '{' || raw[i] === '[') {
      if (depth > limits.maxDepth) invalid();
      const object = raw[i++] === '{';
      const end = object ? '}' : ']';
      const entries: string[] = [];
      const seen = new Set<string>();
      ws();
      if (raw[i] === end) { i++; return object ? {} : []; }
      for (;;) {
        ws();
        if (object) {
          if (raw[i] !== '"') invalid();
          const key = string(); if (seen.has(key)) invalid(); seen.add(key);
          ws(); if (raw[i++] !== ':') invalid();
          ws(); const start = i;
          const child = value(depth + 1);
          if (depth === 1 && key === 'version') versionLiteral = raw.slice(start, i);
          entries.push(JSON.stringify(key) + ':' + canonical(child));
        } else entries.push(canonical(value(depth + 1)));
        ws();
        const next = raw[i++];
        if (next === end) break;
        if (next !== ',') invalid();
      }
      return JSON.parse((object ? '{' : '[') + entries.join(',') + end);
    }
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(raw.slice(i))?.[0];
    if (!token) return invalid();
    i += token.length;
    const v: unknown = JSON.parse(token);
    if (typeof v === 'number' && (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v)))) invalid();
    return v;
  };
  // JSON.stringify supplies ECMAScript number/string formatting; default sort is UTF-16.
  function canonical(v: unknown): string {
    if (v !== null && typeof v === 'object') {
      if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
      const obj = v as Record<string, unknown>;
      return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
    }
    return JSON.stringify(v) as string;
  }
  const parsed = value(1); ws(); if (i !== raw.length) invalid();
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) invalid();
  const e = parsed as Record<string, unknown>;
  const required = ['version', 'requestId', 'operation', 'connectionId', 'route', 'handle'];
  const allowed = [...required, 'tool', 'arguments'];
  if (Object.keys(e).some(k => !allowed.includes(k)) || required.some(k => !Object.hasOwn(e, k)) ||
      e.version !== 1 || !text(e.requestId) || !text(e.connectionId) || !text(e.route)) invalid();
  // Hub requires the version's literal spelling to be exactly 1.
  if (versionLiteral !== '1') invalid();
  const hasTool = Object.hasOwn(e, 'tool'), hasArgs = Object.hasOwn(e, 'arguments');
  if (e.operation === 'open') {
    if (e.handle !== null || hasTool || hasArgs) invalid();
  } else if (e.operation === 'call') {
    if (!text(e.handle) || !text(e.tool) || !hasArgs || e.arguments === null || typeof e.arguments !== 'object' || Array.isArray(e.arguments)) invalid();
  } else if (e.operation === 'close') {
    if (!text(e.handle) || hasTool || hasArgs) invalid();
  } else invalid();
  return canonical(e);
}

// Identity MUST come from fresh server gateway checks, never model arguments.
// This only prepares an assertion: it does not assert admission or execute tools.
// Dedicated key provenance is the injecting server's responsibility; no agent-key fallback.
export function createWorkflowAssertion(raw: string, identity: WorkflowIdentity, key: WorkflowApplicationKey,
  limits: WorkflowLimits, nowSeconds: number): { assertion: string; canonical: string } {
  const canonical = canonicalizeWorkflowEnvelope(raw, limits);
  if (key.purpose !== 'workflow-application' || key.privateKey.type !== 'private' || key.privateKey.asymmetricKeyType !== 'ed25519' ||
      !text(key.kid) || !text(key.issuer) || !text(key.audience) || !Number.isSafeInteger(key.ttlSeconds) || key.ttlSeconds < 1 || key.ttlSeconds > 30 ||
      !Number.isSafeInteger(nowSeconds) || nowSeconds <= 0 || !Number.isSafeInteger(nowSeconds + key.ttlSeconds) ||
      !text(identity.owner.type) || !text(identity.owner.id) || !text(identity.companyId) || !text(identity.grantId)) invalid();
  const e = JSON.parse(canonical);
  const claims = {
    version: 1, jti: randomUUID(), requestId: e.requestId,
    payloadHash: createHash('sha256').update(canonical, 'utf8').digest('base64url'),
    issuer: key.issuer, owner: { type: identity.owner.type, id: identity.owner.id }, companyId: identity.companyId,
    connectionId: e.connectionId, grantId: identity.grantId, route: e.route, operation: e.operation,
    aud: key.audience, iat: nowSeconds, nbf: nowSeconds, exp: nowSeconds + key.ttlSeconds,
    handle: e.handle, ...(e.operation === 'call' ? { tool: e.tool } : {}),
  };
  for (const s of [key.kid, key.issuer, key.audience, identity.owner.type, identity.owner.id, identity.companyId, identity.grantId]) unicode(s);
  const encode = (v: unknown) => Buffer.from(JSON.stringify(v), 'utf8').toString('base64url');
  const input = encode({ alg: 'EdDSA', kid: key.kid, typ: 'workflow-v1+jws' }) + '.' + encode(claims);
  return { canonical, assertion: input + '.' + sign(null, Buffer.from(input), key.privateKey).toString('base64url') };
}
