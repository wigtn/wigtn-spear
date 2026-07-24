import assert from 'node:assert/strict';
import test from 'node:test';
import {
  discoverSurfacesFrom,
  surfacesFromNextRoutes,
  surfacesFromSupabase,
} from '../src/discovery.js';
import { validateSurfaceInventory } from '../src/validation.js';
import { targetProfile } from './helpers.js';

const NEXT_ROUTES = {
  framework: 'next',
  routes: [
    { kind: 'route-handler', path: '/api/users/[id]', methods: ['GET', 'PATCH'], public: false },
    { kind: 'route-handler', path: '/api/public/status', methods: ['GET'], public: true },
    { kind: 'server-action', id: 'updateProfile' },
    { kind: 'middleware', matcher: ['/dashboard/:path*'] },
  ],
};

const SUPABASE = {
  framework: 'supabase',
  tables: [
    { schema: 'public', name: 'profiles', rlsEnabled: true, operations: ['select', 'update'] },
    { name: 'audit_logs', rlsEnabled: false, operations: ['select'] },
  ],
  storageBuckets: [{ name: 'avatars', public: false }],
};

test('surfacesFromNextRoutes maps handlers, server actions, and middleware', () => {
  const surfaces = surfacesFromNextRoutes(NEXT_ROUTES);
  // Two methods on /api/users/[id] + one public GET + one action + one middleware = 5.
  assert.equal(surfaces.length, 5);
  const handler = surfaces.find((s) => s.entryPoint === '/api/users/[id]' && s.operation === 'PATCH');
  assert.deepEqual(handler?.principals, ['authenticated-or-unknown']);
  const publicHandler = surfaces.find((s) => s.entryPoint === '/api/public/status');
  assert.deepEqual(publicHandler?.principals, ['anonymous']);
  assert.ok(surfaces.some((s) => s.entryPoint === 'action:updateProfile' && s.operation === 'POST'));
  assert.ok(surfaces.some((s) => s.entryPoint.startsWith('middleware:')));
  assert.ok(surfaces.every((s) => s.mappingSource === 'next-app'));
});

test('surfacesFromNextRoutes rejects malformed descriptors', () => {
  assert.throws(() => surfacesFromNextRoutes({ framework: 'remix', routes: [] }), /framework must be "next"/u);
  assert.throws(
    () => surfacesFromNextRoutes({ routes: [{ kind: 'route-handler', path: 'api/x', methods: ['GET'] }] }),
    /must start with/u,
  );
  assert.throws(
    () => surfacesFromNextRoutes({ routes: [{ kind: 'route-handler', path: '/x', methods: ['FETCH'] }] }),
    /unsupported method/u,
  );
});

test('surfacesFromSupabase flags RLS-disabled tables as anonymous with a state dependency', () => {
  const surfaces = surfacesFromSupabase(SUPABASE);
  const audit = surfaces.find((s) => s.entryPoint === 'table:public.audit_logs');
  assert.deepEqual(audit?.principals, ['anonymous']);
  assert.deepEqual(audit?.stateDependencies, ['rls-disabled']);
  const profiles = surfaces.find((s) => s.entryPoint === 'table:public.profiles');
  assert.deepEqual(profiles?.principals, ['authenticated-or-unknown']);
  const bucket = surfaces.find((s) => s.protocol === 'storage');
  assert.equal(bucket?.entryPoint, 'bucket:avatars');
  assert.ok(surfaces.every((s) => s.mappingSource === 'supabase'));
});

test('discoverSurfacesFrom merges operator, Next.js, and Supabase sources into a valid inventory', () => {
  const inventory = discoverSurfacesFrom(targetProfile(), {
    nextRoutes: NEXT_ROUTES,
    supabase: SUPABASE,
  }, new Date('2026-07-24T00:00:00.000Z'));
  assert.doesNotThrow(() => validateSurfaceInventory(inventory));
  assert.ok(inventory.sources.includes('next-app'));
  assert.ok(inventory.sources.includes('supabase'));
  assert.ok(inventory.sources.includes('operator'));
  // Database and storage protocols now appear alongside the operator HTTP surface.
  assert.ok(inventory.surfaces.some((s) => s.protocol === 'database'));
  assert.ok(inventory.surfaces.some((s) => s.protocol === 'storage'));
});
