import assert from 'node:assert/strict';
import test from 'node:test';
import { discoverSurfacesFrom, surfacesFromHar } from '../src/discovery.js';
import { validateSurfaceInventory } from '../src/validation.js';
import { targetProfile } from './helpers.js';

const HAR = {
  log: {
    version: '1.2',
    entries: [
      { request: { method: 'GET', url: 'https://app.example.com/api/users/123', headers: [{ name: 'Authorization', value: 'Bearer x' }] } },
      { request: { method: 'GET', url: 'https://app.example.com/api/users/456?expand=1', headers: [{ name: 'Cookie', value: 's=1' }] } },
      { request: { method: 'GET', url: 'https://app.example.com/api/public/status', headers: [] } },
      { request: { method: 'POST', url: 'https://app.example.com/api/users/550e8400-e29b-41d4-a716-446655440000/reset', headers: [{ name: 'authorization', value: 'Bearer y' }] } },
    ],
  },
};

test('surfacesFromHar templatizes ids, keys principals off auth headers, and drops query strings', () => {
  const surfaces = surfacesFromHar(HAR);
  assert.equal(surfaces.length, 4);
  // Numeric ids collapse to the same templated entry point.
  const userReads = surfaces.filter((s) => s.entryPoint === '/api/users/{id}' && s.operation === 'GET');
  assert.equal(userReads.length, 2);
  assert.ok(userReads.every((s) => s.principals?.[0] === 'authenticated-or-unknown'));
  // A UUID segment is templatized too.
  assert.ok(surfaces.some((s) => s.entryPoint === '/api/users/{id}/reset' && s.operation === 'POST'));
  // No auth/cookie header -> anonymous.
  const status = surfaces.find((s) => s.entryPoint === '/api/public/status');
  assert.deepEqual(status?.principals, ['anonymous']);
  assert.ok(surfaces.every((s) => s.mappingSource === 'har-capture' && s.protocol === 'http'));
});

test('discoverSurfacesFrom merges repeated HAR captures into one validated surface', () => {
  const inventory = discoverSurfacesFrom(targetProfile(), { har: HAR });
  // The two GET /api/users/{id} captures merge into a single surface.
  const userReads = inventory.surfaces.filter(
    (s) => s.entryPoint === '/api/users/{id}' && s.operation === 'GET',
  );
  assert.equal(userReads.length, 1);
  assert.ok(inventory.sources.includes('har-capture'));
  // The stored inventory round-trips through untrusted validation (ids recomputed).
  assert.doesNotThrow(() => validateSurfaceInventory(inventory));
});

test('surfacesFromHar rejects malformed captures', () => {
  assert.throws(() => surfacesFromHar({ log: { entries: 'nope' } }), /entries must be an array/u);
  assert.throws(
    () => surfacesFromHar({ log: { entries: [{ request: { method: 'GET', url: '/relative/only' } }] } }),
    /not an absolute URL/u,
  );
  assert.throws(
    () => surfacesFromHar({ log: { entries: [{ request: { method: 'FROB', url: 'https://h/x' } }] } }),
    /method is unsupported/u,
  );
});
