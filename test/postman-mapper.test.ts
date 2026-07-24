import assert from 'node:assert/strict';
import test from 'node:test';
import { discoverSurfacesFrom, surfacesFromPostman } from '../src/discovery.js';
import { validateSurfaceInventory } from '../src/validation.js';
import { targetProfile } from './helpers.js';

const COLLECTION = {
  info: { schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
  item: [
    {
      name: 'Users',
      item: [
        {
          name: 'Get user',
          request: {
            method: 'GET',
            url: { raw: 'https://api.example.com/v1/users/:id', path: ['v1', 'users', ':id'] },
            auth: { type: 'bearer' },
          },
        },
        {
          name: 'Update user',
          request: {
            method: 'PATCH',
            url: { raw: 'https://api.example.com/v1/users/{{userId}}', path: ['v1', 'users', '{{userId}}'] },
            header: [{ key: 'Authorization', value: 'Bearer x' }],
          },
        },
      ],
    },
    {
      name: 'Public status',
      request: {
        method: 'GET',
        url: 'https://api.example.com/v1/status?verbose=1',
        auth: { type: 'noauth' },
      },
    },
    { name: 'A folder with no requests', item: [] },
  ],
};

test('surfacesFromPostman walks folders, templatizes path variables, and infers auth', () => {
  const surfaces = surfacesFromPostman(COLLECTION);
  assert.equal(surfaces.length, 3);

  // Both :id and {{userId}} collapse to {id}.
  const read = surfaces.find((s) => s.entryPoint === '/v1/users/{id}' && s.operation === 'GET');
  assert.deepEqual(read?.principals, ['authenticated-or-unknown']);
  const patch = surfaces.find((s) => s.entryPoint === '/v1/users/{id}' && s.operation === 'PATCH');
  assert.deepEqual(patch?.principals, ['authenticated-or-unknown']); // Authorization header

  // noauth + query string dropped -> anonymous /v1/status.
  const status = surfaces.find((s) => s.entryPoint === '/v1/status');
  assert.deepEqual(status?.principals, ['anonymous']);
  assert.ok(surfaces.every((s) => s.mappingSource === 'postman' && s.protocol === 'http'));
});

test('discoverSurfacesFrom merges the Postman GET/PATCH into stable validated surfaces', () => {
  const inventory = discoverSurfacesFrom(targetProfile(), { postman: COLLECTION });
  // GET and PATCH on /v1/users/{id} are distinct surfaces (different operation).
  const userSurfaces = inventory.surfaces.filter((s) => s.entryPoint === '/v1/users/{id}');
  assert.deepEqual(userSurfaces.map((s) => s.operation).sort(), ['GET', 'PATCH']);
  assert.ok(inventory.sources.includes('postman'));
  assert.doesNotThrow(() => validateSurfaceInventory(inventory));
});

test('surfacesFromPostman rejects malformed collections', () => {
  assert.throws(() => surfacesFromPostman({ info: {} }), /postman.item must be an array/u);
  assert.throws(
    () => surfacesFromPostman({ item: [{ request: { method: 'FROB', url: 'https://h/x' } }] }),
    /method is unsupported/u,
  );
});
