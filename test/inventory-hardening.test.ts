import assert from 'node:assert/strict';
import test from 'node:test';
import { discoverSurfaces } from '../src/discovery.js';
import { validateSurfaceInventory } from '../src/validation.js';
import { targetProfile } from './helpers.js';

test('a freshly discovered inventory passes validation', () => {
  const inventory = discoverSurfaces(targetProfile());
  assert.doesNotThrow(() => validateSurfaceInventory(inventory));
});

test('altering a surface protocol without recomputing its ID is rejected', () => {
  const inventory = discoverSurfaces(targetProfile());
  const tampered = structuredClone(inventory);
  // Keep the stored ID but change the semantics it labels.
  tampered.surfaces[0]!.protocol = 'graphql';
  assert.throws(() => validateSurfaceInventory(tampered), /does not match its protocol/u);
});

test('altering a surface entryPoint without recomputing its ID is rejected', () => {
  const inventory = discoverSurfaces(targetProfile());
  const tampered = structuredClone(inventory);
  tampered.surfaces[0]!.entryPoint = '/smuggled';
  assert.throws(() => validateSurfaceInventory(tampered), /does not match its protocol/u);
});

test('duplicate surface IDs are rejected', () => {
  const inventory = discoverSurfaces(targetProfile());
  const tampered = structuredClone(inventory);
  tampered.surfaces.push(structuredClone(tampered.surfaces[0]!));
  assert.throws(() => validateSurfaceInventory(tampered), /Duplicate surface ID/u);
});
