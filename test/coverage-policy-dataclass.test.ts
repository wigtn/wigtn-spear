import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluateCoverage } from '../src/coverage.js';
import { discoverSurfaces } from '../src/discovery.js';
import type { CoveragePolicy } from '../src/types.js';
import { mappedPolicy, signedRegistry, targetProfile, testKeys } from './helpers.js';

// A policy that requires nothing by protocol/id, so the data-class rule is the
// only thing that can select a surface (isolating its effect).
function dataClassPolicy(overrides: Partial<CoveragePolicy>): CoveragePolicy {
  return {
    ...mappedPolicy(),
    requiredProtocols: [],
    requiredWitnesses: [],
    ...overrides,
  };
}

test('requiredDataClasses selects surfaces by attribute and enforces the evidence-grade floor', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile(); // the operator surface carries dataClass "internal"
  const inventory = discoverSurfaces(profile);
  const registry = signedRegistry(privateKeyPem); // makes the surface attackable

  // No data-class match -> the raised grade floor applies to nothing -> complete.
  const noMatch = evaluateCoverage(inventory, profile, registry, trustStore,
    dataClassPolicy({ minimumEvidenceGrade: 'exercised', requiredDataClasses: ['pci'] }));
  assert.equal(noMatch.verdict, 'coverage-complete');

  // The "internal" surface is attackable (grade mapped) but the policy demands
  // "exercised" for that data class -> incomplete on the grade floor.
  const graded = evaluateCoverage(inventory, profile, registry, trustStore,
    dataClassPolicy({ minimumEvidenceGrade: 'exercised', requiredDataClasses: ['internal'] }));
  assert.equal(graded.verdict, 'coverage-incomplete');
  assert.ok(graded.unmetRequirements.some((r) => /evidence mapped is below exercised/u.test(r)));
});

test('a data-class-required surface with no compatible pack is an explicit gap', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  const inventory = discoverSurfaces(profile);
  const emptyRegistry = signedRegistry(privateKeyPem, []); // no packs -> unsupported

  const report = evaluateCoverage(inventory, profile, emptyRegistry, trustStore,
    dataClassPolicy({ requiredDataClasses: ['internal'] }));
  assert.equal(report.verdict, 'coverage-incomplete');
  assert.ok(
    report.unmetRequirements.some((r) => /carries required data class.*internal.*is unsupported/u.test(r)),
    'the data-class gap is reported explicitly',
  );
});

test('absent requiredDataClasses stays backward-compatible', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const profile = targetProfile();
  const inventory = discoverSurfaces(profile);
  const report = evaluateCoverage(inventory, profile, signedRegistry(privateKeyPem), trustStore, mappedPolicy());
  assert.equal(report.verdict, 'coverage-complete');
});
