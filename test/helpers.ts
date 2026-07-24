import {
  generateEd25519KeyPair,
  signDocument,
} from '../src/crypto.js';
import {
  computePackDescriptorDigest,
} from '../src/registry.js';
import type {
  AuthorizationManifest,
  CoveragePolicy,
  PackManifest,
  PackRegistry,
  TargetProfile,
  TrustStore,
  UnsignedAuthorizationManifest,
  UnsignedPackRegistry,
} from '../src/types.js';

export const BUILD_DIGEST = `sha256:${'a'.repeat(64)}`;
export const KEY_ID = 'owner-2026';

export function testKeys(): {
  privateKeyPem: string;
  trustStore: TrustStore;
} {
  const keys = generateEd25519KeyPair();
  return {
    privateKeyPem: keys.privateKeyPem,
    trustStore: {
      schemaVersion: '3.0',
      keys: [{
        keyId: KEY_ID,
        algorithm: 'Ed25519',
        publicKeyPem: keys.publicKeyPem,
        status: 'active',
      }],
    },
  };
}

export function signedManifest(
  privateKeyPem: string,
  overrides: Partial<UnsignedAuthorizationManifest> = {},
): AuthorizationManifest {
  const unsigned: UnsignedAuthorizationManifest = {
    schemaVersion: '3.0',
    kind: 'authorization-manifest',
    engagement: {
      id: 'eng-test-001',
      owner: 'security@example.test',
      issuedAt: '2026-07-01T00:00:00.000Z',
      expiresAt: '2026-08-01T00:00:00.000Z',
    },
    target: {
      name: 'fixture-app',
      repositoryPath: '/workspace/fixture-app',
      buildDigest: BUILD_DIGEST,
      origins: ['http://127.0.0.1:4310'],
      environment: 'test',
    },
    capabilities: ['discover', 'run:project'],
    safety: {
      allowedHosts: ['127.0.0.1'],
      allowedCanaryOrigins: ['http://127.0.0.1:4399'],
      maxRequests: 100,
      maxWallTimeMs: 30_000,
      maxConcurrency: 2,
      maxResponseBytes: 262_144,
      allowMutations: false,
      twinAttested: false,
    },
    ...overrides,
  };
  return {
    ...unsigned,
    signature: signDocument(
      unsigned as unknown as Record<string, unknown>,
      privateKeyPem,
      KEY_ID,
    ),
  };
}

export function httpPack(
  overrides: Partial<Omit<PackManifest, 'integrity'>> = {},
): PackManifest {
  const descriptor: Omit<PackManifest, 'integrity'> = {
    schemaVersion: '3.0',
    id: 'http-authz',
    version: '1.0.0',
    apiVersion: '1.0',
    supportedTargetVersions: ['*'],
    applicableProtocols: ['http'],
    capabilities: ['mutate:http'],
    safetyClass: 'active-safe',
    requiredWitnesses: ['http-response'],
    fixtures: ['principal-a', 'principal-b'],
    mutationGrammar: 'swap fixture-owned object identifiers',
    forbiddenPredicates: ['cross-principal canary disclosure'],
    cleanup: 'reset fixture',
    standards: ['OWASP API1:2023'],
    ...overrides,
  };
  return {
    ...descriptor,
    integrity: {
      algorithm: 'sha256',
      descriptorDigest: computePackDescriptorDigest(descriptor),
    },
  };
}

export function signedRegistry(
  privateKeyPem: string,
  packs: PackManifest[] = [httpPack()],
): PackRegistry {
  const unsigned: UnsignedPackRegistry = {
    schemaVersion: '3.0',
    kind: 'pack-registry',
    registryId: 'official-test',
    generatedAt: '2026-07-20T00:00:00.000Z',
    packs,
  };
  return {
    ...unsigned,
    signature: signDocument(
      unsigned as unknown as Record<string, unknown>,
      privateKeyPem,
      KEY_ID,
    ),
  };
}

export function targetProfile(witnesses = ['http-response']): TargetProfile {
  return {
    schemaVersion: '3.0',
    kind: 'target-profile',
    target: {
      name: 'fixture-app',
      version: '1.0.0',
      buildDigest: BUILD_DIGEST,
    },
    availableWitnesses: witnesses,
    surfaces: [{
      protocol: 'http',
      entryPoint: '/operator-only',
      operation: 'POST',
      principals: ['authenticated'],
      dataClasses: ['internal'],
    }],
  };
}

export function mappedPolicy(): CoveragePolicy {
  return {
    schemaVersion: '3.0',
    kind: 'coverage-policy',
    requiredProtocols: ['http'],
    requiredSurfaceIds: [],
    requiredWitnesses: ['http-response'],
    minimumEvidenceGrade: 'mapped',
    allowedSafetyClasses: ['passive', 'active-safe'],
  };
}
