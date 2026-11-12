import { test } from 'vitest';
import assert from 'node:assert/strict';
import { generateKeyPairSync, verify, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalizeWorkflowEnvelope, createWorkflowAssertion } from '../services/workflow-client-v1.js';

const open = '{"version":1,"requestId":"fixture-open","operation":"open","connectionId":"connection-test","route":"/rea","handle":null}';
const limits = { maxBytes: 8192, maxDepth: 16 };
test('all shared hub open/call/close fixtures', () => {
  const fixtures = JSON.parse(readFileSync(new URL('../services/workflow-client-v1.fixtures.json', import.meta.url), 'utf8'));
  for (const f of fixtures) {
    const canonical = canonicalizeWorkflowEnvelope(JSON.stringify(f.envelope), limits);
    assert.equal(canonical, f.canonical, f.name);
    assert.equal(createHash('sha256').update(canonical).digest('base64url'), f.payloadHash, f.name);
  }
});
test('hub open canonical bytes and digest', () => {
  const canonical = canonicalizeWorkflowEnvelope(open, limits);
  assert.equal(canonical, '{"connectionId":"connection-test","handle":null,"operation":"open","requestId":"fixture-open","route":"/rea","version":1}');
  assert.equal(createHash('sha256').update(canonical).digest('base64url'), '-p5JYjb_g3u4keCDQ9mD-wvK8yNy-dhbKsPAI3iymEs');
});
test('reject invalid or ambiguous envelopes before signing', () => {
  for (const raw of [open + '{}', open.replace('"version":1', '"version":1,"version":1'), open.replace('"version":1', '"version":1,"owner":{}'), open.replace('null', '"handle"'), open.replace('fixture-open', '\\ud800'), open.replace('1,', '1.0,')]) {
    assert.throws(() => canonicalizeWorkflowEnvelope(raw, limits));
  }
  const call = (args: string) => open.replace('"open"', '"call"').replace('null', '"handle"') .replace(/}$/, ',"tool":"read","arguments":' + args + '}');
  for (const args of ['null', '[]', '{"a":1,"a":2}', '{"x":9007199254740992}', '{"x":1e400}', '{"x":"\\udfff"}']) assert.throws(() => canonicalizeWorkflowEnvelope(call(args), limits));
  assert.throws(() => canonicalizeWorkflowEnvelope(open, { ...limits, maxBytes: 1 }));
  assert.throws(() => canonicalizeWorkflowEnvelope(call('{"a":[[]]}'), { ...limits, maxDepth: 2 }));
  assert.match(canonicalizeWorkflowEnvelope(call('{"z":-0,"é":"ok","a":0.000001}'), limits), /"arguments":\{"a":0.000001,"z":0,"é":"ok"\}/);
});
test('dedicated Ed25519 signer binds trusted identity and envelope with fresh jti', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const config = { purpose: 'workflow-application' as const, privateKey, kid: 'app-test', issuer: 'paperclip-test', audience: 'hub:connection-test:/rea', ttlSeconds: 30 };
  const identity = { owner: { type: 'agent', id: 'owner-test' }, companyId: 'company-test', grantId: 'grant-test' };
  const signed = createWorkflowAssertion(open, identity, config, limits, 1700000000);
  const [header, payload, signature] = signed.assertion.split('.');
  assert.deepEqual(JSON.parse(Buffer.from(header, 'base64url').toString()), { alg: 'EdDSA', kid: 'app-test', typ: 'workflow-v1+jws' });
  assert.ok(verify(null, Buffer.from(header + '.' + payload), publicKey, Buffer.from(signature, 'base64url')));
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  assert.equal(claims.issuer, config.issuer); assert.equal(claims.exp - claims.iat, 30);
  assert.equal(claims.payloadHash, '-p5JYjb_g3u4keCDQ9mD-wvK8yNy-dhbKsPAI3iymEs');
  assert.deepEqual(claims.owner, identity.owner); assert.equal(claims.handle, null);
  assert.notEqual(claims.jti, JSON.parse(Buffer.from(createWorkflowAssertion(open, identity, config, limits, 1700000000).assertion.split('.')[1], 'base64url').toString()).jti);
  assert.throws(() => createWorkflowAssertion(open, identity, { ...config, ttlSeconds: 31 }, limits, 1700000000));
  assert.throws(() => createWorkflowAssertion(open, identity, { ...config, privateKey: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey }, limits, 1700000000));
});
