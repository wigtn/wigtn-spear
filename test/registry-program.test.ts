import assert from 'node:assert/strict';
import test from 'node:test';
import {
  computePackDescriptorDigest,
  packDescriptor,
  verifyPackRegistry,
} from '../src/registry.js';
import { validateAttackProgram } from '../src/validation.js';
import {
  httpPack,
  signedRegistry,
  testKeys,
} from './helpers.js';

test('verifies registry signature and each canonical pack descriptor digest', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const registry = signedRegistry(privateKeyPem);
  const verified = verifyPackRegistry(registry, trustStore);
  assert.match(verified.registryDigest, /^sha256:/u);
});

test('rejects descriptor plus digest tampering because the registry signature no longer matches', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const registry = structuredClone(signedRegistry(privateKeyPem));
  const changed = httpPack({ mutationGrammar: 'tampered grammar' });
  changed.integrity.descriptorDigest = computePackDescriptorDigest(packDescriptor(changed));
  registry.packs[0] = changed;
  assert.throws(() => verifyPackRegistry(registry, trustStore), /signature is invalid/u);
});

test('rejects pack descriptor digest mismatch', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const broken = httpPack();
  broken.integrity.descriptorDigest = `sha256:${'f'.repeat(64)}`;
  const registry = signedRegistry(privateKeyPem, [broken]);
  assert.throws(() => verifyPackRegistry(registry, trustStore), /digest mismatch/u);
});

test('rejects a registry signed by a revoked key', () => {
  const { privateKeyPem, trustStore } = testKeys();
  trustStore.keys[0]!.status = 'revoked';
  assert.throws(
    () => verifyPackRegistry(signedRegistry(privateKeyPem), trustStore),
    /revoked/u,
  );
});

test('attack program requires semantic attack and oracle fields', () => {
  const valid = {
    schemaVersion: '3.0',
    kind: 'attack-program',
    id: 'bola-swap',
    title: 'Cross-principal object swap',
    principal: { id: 'user-b', kind: 'fixture-session' },
    preconditions: ['user-a owns canary object'],
    carrier: { protocol: 'http', entryPoint: '/api/items/{id}' },
    source: { kind: 'fixture', reference: 'user-a-object-id' },
    capability: 'read:item',
    mutation: { kind: 'identifier-swap', description: 'use A object with B session' },
    forbiddenPredicate: { kind: 'data-flow', expression: 'A canary reaches B response' },
    oracle: { kind: 'http-body', witness: 'http-response' },
  };
  assert.equal(validateAttackProgram(valid).id, 'bola-swap');
  const missingOracle = structuredClone(valid) as Record<string, unknown>;
  delete missingOracle.oracle;
  assert.throws(() => validateAttackProgram(missingOracle), /program.oracle/u);
});
