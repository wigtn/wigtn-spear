import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateCoverage } from '../src/coverage.js';
import { diffCoverage } from '../src/diff.js';
import { discoverSurfaces } from '../src/discovery.js';
import {
  mappedPolicy,
  signedRegistry,
  targetProfile,
  testKeys,
} from './helpers.js';

const OPENAPI = {
  openapi: '3.1.0',
  paths: {
    '/users/{id}': {
      get: { security: [{ bearerAuth: [] }] },
    },
    '/health': {
      get: { security: [] },
    },
  },
};

test('merges operator and OpenAPI sources into stable passive inventory', () => {
  const inventory = discoverSurfaces(targetProfile(), OPENAPI, new Date('2026-07-23T00:00:00Z'));
  assert.equal(inventory.surfaces.length, 3);
  assert.deepEqual(inventory.sources, ['openapi', 'operator']);
  assert.equal(
    inventory.surfaces.find((surface) => surface.entryPoint === '/health')?.principals[0],
    'anonymous',
  );
  assert.deepEqual(
    inventory.surfaces.map((surface) => surface.id),
    [...inventory.surfaces.map((surface) => surface.id)].sort(),
  );
});

test('coverage is complete only when compatible packs and witnesses satisfy explicit policy', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  const inventory = discoverSurfaces(profile, OPENAPI);
  const report = evaluateCoverage(
    inventory,
    profile,
    signedRegistry(privateKeyPem),
    trustStore,
    mappedPolicy(),
  );
  assert.equal(report.verdict, 'coverage-complete');
  assert.ok(report.ledger.every((item) => item.state === 'attackable'));
  assert.ok(!JSON.stringify(report).includes('"secure"'));
});

test('missing witness and missing pack remain explicit coverage gaps even with zero findings', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const missingWitnessProfile = targetProfile([]);
  const blocked = evaluateCoverage(
    discoverSurfaces(missingWitnessProfile, OPENAPI),
    missingWitnessProfile,
    signedRegistry(privateKeyPem),
    trustStore,
    mappedPolicy(),
  );
  assert.equal(blocked.verdict, 'coverage-incomplete');
  assert.ok(blocked.ledger.every((item) => item.state === 'blocked'));

  const unsupportedProfile = {
    ...targetProfile(),
    surfaces: [{ protocol: 'graphql' as const, entryPoint: '/graphql' }],
  };
  const unsupported = evaluateCoverage(
    discoverSurfaces(unsupportedProfile),
    unsupportedProfile,
    signedRegistry(privateKeyPem),
    trustStore,
    { ...mappedPolicy(), requiredProtocols: ['graphql'] },
  );
  assert.equal(unsupported.verdict, 'coverage-incomplete');
  assert.equal(unsupported.ledger[0]?.state, 'unsupported');
});

test('coverage diff separates surface and state regressions', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  const from = evaluateCoverage(
    discoverSurfaces(profile, OPENAPI),
    profile,
    signedRegistry(privateKeyPem),
    trustStore,
    mappedPolicy(),
  );
  const blockedProfile = targetProfile([]);
  const to = evaluateCoverage(
    discoverSurfaces(blockedProfile, {
      openapi: '3.1.0',
      paths: { '/users/{id}': OPENAPI.paths['/users/{id}'] },
    }),
    blockedProfile,
    signedRegistry(privateKeyPem),
    trustStore,
    mappedPolicy(),
  );
  const result = diffCoverage(from, to);
  assert.equal(result.removedSurfaceIds.length, 1);
  assert.ok(result.changedCoverage.length >= 1);
});
