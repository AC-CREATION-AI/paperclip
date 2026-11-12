import { test } from 'vitest';
import assert from 'node:assert/strict';
import { workflowCallAdmission } from '../services/workflow-call-admission.js';
import { canonicalizeWorkflowEnvelope } from '../services/workflow-client-v1.js';
import type { WorkflowCallBinding } from '../services/workflow-call-admission.js';

const limits = { maxBytes: 4096, maxDepth: 8 };
const raw = JSON.stringify({ version: 1, requestId: 'request', operation: 'call', connectionId: 'connection', route: '/rea', handle: 'opaque', tool: 'read', arguments: { address: 1 } });
const binding: WorkflowCallBinding = {
  invocationId: 'invocation', runId: 'run', connectionId: 'connection', route: '/rea',
  assertion: 'server-persisted-jws', canonical: canonicalizeWorkflowEnvelope(raw, limits),
  issuer: 'paperclip-test', jti: 'unique', expiresAt: 120,
  owner: { type: 'agent', id: 'agent' }, companyId: 'company', grantId: 'grant',
};
function fixture(options: { authenticated?: boolean; record?: WorkflowCallBinding | null; allowed?: boolean; fail?: boolean } = {}) {
  let admissions = 0;
  let reads = 0;
  const admit = workflowCallAdmission({ limits, nowSeconds: () => 100,
    authenticateService: async () => options.authenticated ?? true,
    loadBinding: async () => { reads++; return options.record === undefined ? binding : options.record; },
    admitBoundCall: async snapshot => {
      admissions++;
      assert.equal(snapshot.runId, 'run');
      assert.ok(Object.isFrozen(snapshot));
      assert.ok(Object.isFrozen(snapshot.owner));
      if (options.fail) throw new Error('sensitive upstream error');
      return options.allowed ?? true;
    },
  });
  return { admit, counts: () => ({ admissions, reads }) };
}
test('returns exact admission context and rechecks every request without dispatch', async () => {
  const f = fixture();
  const result = await f.admit('service', 'invocation', binding.assertion, raw);
  assert.equal(result.allowed, true);
  assert.equal(result.jti, binding.jti);
  assert.deepEqual(result.owner, binding.owner);
  assert.equal(result.connectionId, binding.connectionId);
  assert.equal(result.grantId, binding.grantId);
  await f.admit('service', 'invocation', binding.assertion, raw);
  assert.deepEqual(f.counts(), { admissions: 2, reads: 2 });
});
test('unauthenticated service cannot read durable context', async () => {
  const f = fixture({ authenticated: false });
  await assert.rejects(f.admit(null, 'invocation', binding.assertion, raw), /workflow admission unavailable/);
  assert.deepEqual(f.counts(), { admissions: 0, reads: 0 });
});
test('rejects mismatched invocation, assertion, connection, route, handle, action and payload before admission', async () => {
  const variants = [
    ['other', binding.assertion, raw], ['invocation', 'other', raw],
    ...Object.entries({ connectionId: 'other', route: '/other', handle: 'other', tool: 'write', arguments: {} })
      .map(([key, value]) => ['invocation', binding.assertion, JSON.stringify({ ...JSON.parse(raw), [key]: value })]),
  ];
  for (const [id, assertion, envelope] of variants) {
    const f = fixture();
    await assert.rejects(f.admit('service', id, assertion, envelope));
    assert.equal(f.counts().admissions, 0);
  }
});
test('missing, expired and run-less durable context fails closed', async () => {
  for (const record of [null, { ...binding, expiresAt: 100 }, { ...binding, runId: '' }]) {
    const f = fixture({ record });
    await assert.rejects(f.admit('service', 'invocation', binding.assertion, raw));
    assert.equal(f.counts().admissions, 0);
  }
});
test('revocation, pending approval and dependency failure never return allowed', async () => {
  for (const options of [{ allowed: false }, { fail: true }]) {
    const f = fixture(options);
    await assert.rejects(f.admit('service', 'invocation', binding.assertion, raw), /^Error: workflow admission unavailable$/);
    assert.equal(f.counts().admissions, 1);
  }
});
test('open, close and duplicate JSON fields are not admitted by this call-only seam', async () => {
  for (const envelope of [
    JSON.stringify({ ...JSON.parse(raw), operation: 'open', handle: null, tool: undefined, arguments: undefined }),
    JSON.stringify({ ...JSON.parse(raw), operation: 'close', tool: undefined, arguments: undefined }),
    raw.replace('"version":1', '"version":1,"version":1'),
  ]) {
    const f = fixture();
    await assert.rejects(f.admit('service', 'invocation', binding.assertion, envelope));
    assert.equal(f.counts().admissions, 0);
  }
});
