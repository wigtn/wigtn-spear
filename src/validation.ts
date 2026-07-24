import { isAbsolute } from 'node:path';
import { isSha256Digest, sha256Digest } from './crypto.js';
import { SpearConfigError, SpearSafetyError } from './errors.js';
import type {
  AttackProgram,
  AuthorizationManifest,
  CausalHttpAttackProgram,
  CoveragePolicy,
  EnvironmentClass,
  EvidenceGrade,
  MappingSource,
  PackManifest,
  PackRegistry,
  SafetyClass,
  SignatureEnvelope,
  SurfaceInput,
  SurfaceInventory,
  SurfaceProtocol,
  TargetProfile,
  TrustStore,
} from './types.js';
import {
  assertUnique,
  isRecord,
  requireArray,
  requireInteger,
  requireRecord,
  requireString,
  stringArray,
} from './utils.js';

const ENVIRONMENTS = new Set<EnvironmentClass>(['disposable', 'test', 'production']);
const SAFETY_CLASSES = new Set<SafetyClass>([
  'passive',
  'active-safe',
  'active-mutating',
  'high-risk',
]);
const PROTOCOLS = new Set<SurfaceProtocol>([
  'browser',
  'http',
  'openapi',
  'graphql',
  'websocket',
  'grpc',
  'soap',
  'event',
  'storage',
  'database',
  'filesystem',
  'ci',
  'agent',
  'unknown',
]);
const EVIDENCE_GRADES = new Set<EvidenceGrade>([
  'inventory',
  'mapped',
  'exercised',
  'witnessed',
  'causal',
]);

function requireV3(record: Record<string, unknown>, context: string): void {
  if (record.schemaVersion !== '3.0') {
    throw new SpearConfigError(`${context}.schemaVersion must be "3.0"`);
  }
}

function requireBoolean(
  record: Record<string, unknown>,
  key: string,
  context: string,
): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') {
    throw new SpearConfigError(`${context}.${key} must be a boolean`);
  }
  return value;
}

function requireEnum<T extends string>(
  record: Record<string, unknown>,
  key: string,
  context: string,
  allowed: Set<T>,
): T {
  const value = requireString(record, key, context);
  if (!allowed.has(value as T)) {
    throw new SpearConfigError(`${context}.${key} is unsupported: ${value}`);
  }
  return value as T;
}

function validateSignature(value: unknown, context: string): SignatureEnvelope {
  const signature = requireRecord(value, context);
  if (signature.algorithm !== 'Ed25519') {
    throw new SpearConfigError(`${context}.algorithm must be "Ed25519"`);
  }
  requireString(signature, 'keyId', context);
  const encoded = requireString(signature, 'value', context);
  if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(encoded)) {
    throw new SpearConfigError(`${context}.value must be base64`);
  }
  return signature as unknown as SignatureEnvelope;
}

function validateDate(value: string, context: string): number {
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) {
    throw new SpearConfigError(`${context} must be an ISO date`);
  }
  return timestamp;
}

export function validateTrustStore(value: unknown): TrustStore {
  const store = requireRecord(value, 'trustStore');
  requireV3(store, 'trustStore');
  const keys = requireArray(store, 'keys', 'trustStore');
  if (keys.length === 0) throw new SpearConfigError('trustStore.keys must not be empty');
  const ids: string[] = [];
  keys.forEach((item, index) => {
    const key = requireRecord(item, `trustStore.keys[${index}]`);
    ids.push(requireString(key, 'keyId', `trustStore.keys[${index}]`));
    if (key.algorithm !== 'Ed25519') {
      throw new SpearConfigError(`trustStore.keys[${index}].algorithm must be "Ed25519"`);
    }
    requireString(key, 'publicKeyPem', `trustStore.keys[${index}]`);
    if (key.status !== 'active' && key.status !== 'revoked') {
      throw new SpearConfigError(`trustStore.keys[${index}].status is invalid`);
    }
  });
  assertUnique(ids, 'trustStore key IDs');
  return store as unknown as TrustStore;
}

function canonicalOriginHost(origin: string, context: string): string {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new SpearConfigError(`Invalid ${context}: ${origin}`);
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new SpearSafetyError(`${context} must be credential-free HTTP(S): ${origin}`);
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new SpearConfigError(`${context} must not include path, query, or fragment: ${origin}`);
  }
  if (origin !== url.origin) {
    throw new SpearConfigError(`${context} must be a canonical exact origin: ${origin}`);
  }
  return url.hostname;
}

export function validateAuthorizationManifest(value: unknown): AuthorizationManifest {
  const manifest = requireRecord(value, 'manifest');
  requireV3(manifest, 'manifest');
  if (manifest.kind !== 'authorization-manifest') {
    throw new SpearConfigError('manifest.kind must be "authorization-manifest"');
  }
  const engagement = requireRecord(manifest.engagement, 'manifest.engagement');
  requireString(engagement, 'id', 'manifest.engagement');
  requireString(engagement, 'owner', 'manifest.engagement');
  const issuedAt = validateDate(
    requireString(engagement, 'issuedAt', 'manifest.engagement'),
    'manifest.engagement.issuedAt',
  );
  const expiresAt = validateDate(
    requireString(engagement, 'expiresAt', 'manifest.engagement'),
    'manifest.engagement.expiresAt',
  );
  if (expiresAt <= issuedAt) {
    throw new SpearConfigError('manifest expiry must be after issue time');
  }

  const target = requireRecord(manifest.target, 'manifest.target');
  requireString(target, 'name', 'manifest.target');
  const repositoryPath = requireString(target, 'repositoryPath', 'manifest.target');
  if (!isAbsolute(repositoryPath)) {
    throw new SpearConfigError('manifest.target.repositoryPath must be an absolute path');
  }
  const buildDigest = requireString(target, 'buildDigest', 'manifest.target');
  if (!isSha256Digest(buildDigest)) {
    throw new SpearConfigError('manifest.target.buildDigest must be sha256:<64 lowercase hex>');
  }
  const environment = requireEnum(target, 'environment', 'manifest.target', ENVIRONMENTS);
  const origins = stringArray(target, 'origins', 'manifest.target');
  if (origins.length === 0) {
    throw new SpearConfigError('manifest.target.origins must not be empty');
  }
  const originHosts = origins.map((origin) => canonicalOriginHost(origin, 'target origin'));

  const capabilities = stringArray(manifest, 'capabilities', 'manifest');
  if (capabilities.length === 0) {
    throw new SpearConfigError('manifest.capabilities must not be empty');
  }
  const safety = requireRecord(manifest.safety, 'manifest.safety');
  const allowedHosts = stringArray(safety, 'allowedHosts', 'manifest.safety');
  for (const host of originHosts) {
    if (!allowedHosts.includes(host)) {
      throw new SpearSafetyError(`Target origin host is absent from allowedHosts: ${host}`);
    }
  }
  for (const canary of stringArray(safety, 'allowedCanaryOrigins', 'manifest.safety')) {
    canonicalOriginHost(canary, 'manifest.safety.allowedCanaryOrigins entry');
  }
  if (safety.allowedControlOrigins !== undefined) {
    for (const control of stringArray(safety, 'allowedControlOrigins', 'manifest.safety')) {
      canonicalOriginHost(control, 'manifest.safety.allowedControlOrigins entry');
    }
  }
  requireInteger(safety, 'maxRequests', 'manifest.safety', 1, 10_000);
  requireInteger(safety, 'maxWallTimeMs', 'manifest.safety', 100, 3_600_000);
  requireInteger(safety, 'maxConcurrency', 'manifest.safety', 1, 100);
  requireInteger(safety, 'maxResponseBytes', 'manifest.safety', 1_024, 16_777_216);
  requireBoolean(safety, 'allowMutations', 'manifest.safety');
  requireBoolean(safety, 'twinAttested', 'manifest.safety');
  validateSignature(manifest.signature, 'manifest.signature');

  if (environment === 'production' && safety.allowMutations === true) {
    throw new SpearSafetyError('Production manifest cannot enable mutations');
  }
  return manifest as unknown as AuthorizationManifest;
}

export function validateSurfaceInput(value: unknown, context: string): SurfaceInput {
  const surface = requireRecord(value, context);
  requireEnum(surface, 'protocol', context, PROTOCOLS);
  requireString(surface, 'entryPoint', context);
  if (surface.operation !== undefined && typeof surface.operation !== 'string') {
    throw new SpearConfigError(`${context}.operation must be a string`);
  }
  for (const key of ['principals', 'dataClasses', 'stateDependencies', 'applicablePacks']) {
    if (surface[key] !== undefined) stringArray(surface, key, context);
  }
  if (
    surface.mappingSource !== undefined
    && !MAPPING_SOURCES.has(surface.mappingSource as MappingSource)
  ) {
    throw new SpearConfigError(`${context}.mappingSource is unsupported`);
  }
  return surface as unknown as SurfaceInput;
}

export function validateTargetProfile(value: unknown): TargetProfile {
  const profile = requireRecord(value, 'profile');
  requireV3(profile, 'profile');
  if (profile.kind !== 'target-profile') {
    throw new SpearConfigError('profile.kind must be "target-profile"');
  }
  const target = requireRecord(profile.target, 'profile.target');
  requireString(target, 'name', 'profile.target');
  requireString(target, 'version', 'profile.target');
  const digest = requireString(target, 'buildDigest', 'profile.target');
  if (!isSha256Digest(digest)) {
    throw new SpearConfigError('profile.target.buildDigest must be sha256:<64 lowercase hex>');
  }
  stringArray(profile, 'availableWitnesses', 'profile');
  requireArray(profile, 'surfaces', 'profile').forEach((surface, index) => {
    validateSurfaceInput(surface, `profile.surfaces[${index}]`);
  });
  return profile as unknown as TargetProfile;
}

export function surfaceId(
  protocol: SurfaceProtocol,
  entryPoint: string,
  operation: string,
): string {
  return `surface-${sha256Digest({ protocol, entryPoint, operation }).slice(7, 23)}`;
}

const MAPPING_SOURCES = new Set<MappingSource>([
  'operator', 'openapi', 'next-app', 'supabase', 'graphql-schema',
]);

/**
 * Validate a stored surface inventory as an untrusted artifact: every surface ID
 * is recomputed from its protocol/entryPoint/operation and must match, so an ID
 * cannot be decoupled from the semantics it labels; duplicate IDs and mismatched
 * target bindings are rejected. This makes a hand-edited inventory detectable.
 */
export function validateSurfaceInventory(value: unknown): SurfaceInventory {
  const record = requireRecord(value, 'inventory');
  requireV3(record, 'inventory');
  if (record.kind !== 'surface-inventory') {
    throw new SpearConfigError('inventory.kind must be "surface-inventory"');
  }
  const target = requireRecord(record.target, 'inventory.target');
  requireString(target, 'name', 'inventory.target');
  requireString(target, 'version', 'inventory.target');
  const digest = requireString(target, 'buildDigest', 'inventory.target');
  if (!isSha256Digest(digest)) {
    throw new SpearConfigError('inventory.target.buildDigest must be sha256:<64 lowercase hex>');
  }
  const seen = new Set<string>();
  requireArray(record, 'surfaces', 'inventory').forEach((raw, index) => {
    const context = `inventory.surfaces[${index}]`;
    const surface = requireRecord(raw, context);
    const protocol = requireEnum(surface, 'protocol', context, PROTOCOLS);
    const entryPoint = requireString(surface, 'entryPoint', context);
    const operation = requireString(surface, 'operation', context);
    const id = requireString(surface, 'id', context);
    if (id !== surfaceId(protocol, entryPoint, operation)) {
      throw new SpearConfigError(
        `${context}.id does not match its protocol/entryPoint/operation; inventory was altered`,
      );
    }
    if (seen.has(id)) {
      throw new SpearConfigError(`Duplicate surface ID in inventory: ${id}`);
    }
    seen.add(id);
    for (const key of ['principals', 'dataClasses', 'stateDependencies', 'applicablePacks']) {
      stringArray(surface, key, context);
    }
    const sources = requireArray(surface, 'mappingSources', context);
    if (sources.length === 0 || sources.some((source) => !MAPPING_SOURCES.has(source as MappingSource))) {
      throw new SpearConfigError(`${context}.mappingSources must be non-empty operator/openapi values`);
    }
  });
  requireArray(record, 'blindSpots', 'inventory');
  return value as SurfaceInventory;
}

export function validatePackManifest(value: unknown, context: string): PackManifest {
  const pack = requireRecord(value, context);
  requireV3(pack, context);
  requireString(pack, 'id', context);
  requireString(pack, 'version', context);
  if (pack.apiVersion !== '1.0') {
    throw new SpearConfigError(`${context}.apiVersion must be "1.0"`);
  }
  const versions = stringArray(pack, 'supportedTargetVersions', context);
  if (versions.length === 0) {
    throw new SpearConfigError(`${context}.supportedTargetVersions must not be empty`);
  }
  const protocols = stringArray(pack, 'applicableProtocols', context);
  protocols.forEach((protocol) => {
    if (!PROTOCOLS.has(protocol as SurfaceProtocol)) {
      throw new SpearConfigError(`${context}.applicableProtocols contains ${protocol}`);
    }
  });
  stringArray(pack, 'capabilities', context);
  requireEnum(pack, 'safetyClass', context, SAFETY_CLASSES);
  stringArray(pack, 'requiredWitnesses', context);
  stringArray(pack, 'fixtures', context);
  requireString(pack, 'mutationGrammar', context);
  stringArray(pack, 'forbiddenPredicates', context);
  requireString(pack, 'cleanup', context);
  stringArray(pack, 'standards', context);
  const integrity = requireRecord(pack.integrity, `${context}.integrity`);
  if (integrity.algorithm !== 'sha256') {
    throw new SpearConfigError(`${context}.integrity.algorithm must be "sha256"`);
  }
  if (!isSha256Digest(requireString(integrity, 'descriptorDigest', `${context}.integrity`))) {
    throw new SpearConfigError(`${context}.integrity.descriptorDigest is invalid`);
  }
  return pack as unknown as PackManifest;
}

export function validatePackRegistry(value: unknown): PackRegistry {
  const registry = requireRecord(value, 'registry');
  requireV3(registry, 'registry');
  if (registry.kind !== 'pack-registry') {
    throw new SpearConfigError('registry.kind must be "pack-registry"');
  }
  requireString(registry, 'registryId', 'registry');
  validateDate(requireString(registry, 'generatedAt', 'registry'), 'registry.generatedAt');
  const ids: string[] = [];
  requireArray(registry, 'packs', 'registry').forEach((pack, index) => {
    ids.push(validatePackManifest(pack, `registry.packs[${index}]`).id);
  });
  assertUnique(ids, 'registry pack IDs');
  validateSignature(registry.signature, 'registry.signature');
  return registry as unknown as PackRegistry;
}

export function validateCoveragePolicy(value: unknown): CoveragePolicy {
  const policy = requireRecord(value, 'policy');
  requireV3(policy, 'policy');
  if (policy.kind !== 'coverage-policy') {
    throw new SpearConfigError('policy.kind must be "coverage-policy"');
  }
  const protocols = stringArray(policy, 'requiredProtocols', 'policy');
  protocols.forEach((protocol) => {
    if (!PROTOCOLS.has(protocol as SurfaceProtocol)) {
      throw new SpearConfigError(`policy.requiredProtocols contains ${protocol}`);
    }
  });
  stringArray(policy, 'requiredSurfaceIds', 'policy');
  stringArray(policy, 'requiredWitnesses', 'policy');
  requireEnum(policy, 'minimumEvidenceGrade', 'policy', EVIDENCE_GRADES);
  const classes = stringArray(policy, 'allowedSafetyClasses', 'policy');
  if (classes.length === 0) {
    throw new SpearConfigError('policy.allowedSafetyClasses must not be empty');
  }
  classes.forEach((safetyClass) => {
    if (!SAFETY_CLASSES.has(safetyClass as SafetyClass)) {
      throw new SpearConfigError(`policy.allowedSafetyClasses contains ${safetyClass}`);
    }
  });
  return policy as unknown as CoveragePolicy;
}

export function validateAttackProgram(value: unknown): AttackProgram {
  const program = requireRecord(value, 'program');
  requireV3(program, 'program');
  if (program.kind !== 'attack-program') {
    throw new SpearConfigError('program.kind must be "attack-program"');
  }
  requireString(program, 'id', 'program');
  requireString(program, 'title', 'program');
  const principal = requireRecord(program.principal, 'program.principal');
  requireString(principal, 'id', 'program.principal');
  requireString(principal, 'kind', 'program.principal');
  const preconditions = stringArray(program, 'preconditions', 'program');
  if (preconditions.length === 0) {
    throw new SpearConfigError('program.preconditions must not be empty');
  }
  const carrier = requireRecord(program.carrier, 'program.carrier');
  requireEnum(carrier, 'protocol', 'program.carrier', PROTOCOLS);
  requireString(carrier, 'entryPoint', 'program.carrier');
  const source = requireRecord(program.source, 'program.source');
  requireString(source, 'kind', 'program.source');
  requireString(source, 'reference', 'program.source');
  requireString(program, 'capability', 'program');
  const mutation = requireRecord(program.mutation, 'program.mutation');
  requireString(mutation, 'kind', 'program.mutation');
  requireString(mutation, 'description', 'program.mutation');
  const predicate = requireRecord(program.forbiddenPredicate, 'program.forbiddenPredicate');
  requireString(predicate, 'kind', 'program.forbiddenPredicate');
  requireString(predicate, 'expression', 'program.forbiddenPredicate');
  const oracle = requireRecord(program.oracle, 'program.oracle');
  requireString(oracle, 'kind', 'program.oracle');
  requireString(oracle, 'witness', 'program.oracle');
  return program as unknown as AttackProgram;
}

function validateHttpSequence(value: unknown, context: string): void {
  const sequence = requireRecord(value, context);
  requireString(sequence, 'id', context);
  requireString(sequence, 'principalId', context);
  const requests = requireArray(sequence, 'requests', context);
  if (requests.length === 0) {
    throw new SpearConfigError(`${context}.requests must not be empty`);
  }
  requests.forEach((item, index) => {
    const request = requireRecord(item, `${context}.requests[${index}]`);
    requireString(request, 'id', `${context}.requests[${index}]`);
    const method = requireString(request, 'method', `${context}.requests[${index}]`);
    if (!['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      throw new SpearConfigError(`${context}.requests[${index}].method is unsupported`);
    }
    const path = requireString(request, 'path', `${context}.requests[${index}]`);
    if (!path.startsWith('/') || path.startsWith('//')) {
      throw new SpearSafetyError(`${context}.requests[${index}].path must be origin-relative`);
    }
    if (request.headers !== undefined) {
      const headers = requireRecord(request.headers, `${context}.requests[${index}].headers`);
      for (const [name, headerValue] of Object.entries(headers)) {
        if (
          !/^[A-Za-z0-9-]+$/u.test(name)
          || typeof headerValue !== 'string'
          || /[\r\n]/u.test(headerValue)
        ) {
          throw new SpearSafetyError(`${context}.requests[${index}] contains an unsafe header`);
        }
      }
    }
    if (request.body !== undefined && typeof request.body !== 'string') {
      throw new SpearConfigError(`${context}.requests[${index}].body must be a string`);
    }
    if (request.idempotencyKey !== undefined) {
      const key = request.idempotencyKey;
      if (typeof key !== 'string' || key.trim() === '' || /[\r\n]/u.test(key)) {
        throw new SpearConfigError(`${context}.requests[${index}].idempotencyKey must be a safe non-empty string`);
      }
    }
    if (request.asPrincipalId !== undefined
      && (typeof request.asPrincipalId !== 'string' || request.asPrincipalId.trim() === '')) {
      throw new SpearConfigError(`${context}.requests[${index}].asPrincipalId must be a non-empty string`);
    }
  });
}

export function validateCausalHttpAttackProgram(value: unknown): CausalHttpAttackProgram {
  validateAttackProgram(value);
  const program = requireRecord(value, 'program');
  const execution = requireRecord(program.execution, 'program.execution');
  validateHttpSequence(execution.baseline, 'program.execution.baseline');
  validateHttpSequence(execution.attack, 'program.execution.attack');
  validateHttpSequence(execution.counterfactual, 'program.execution.counterfactual');
  if (execution.nondeterministic !== undefined && typeof execution.nondeterministic !== 'boolean') {
    throw new SpearConfigError('program.execution.nondeterministic must be a boolean');
  }
  // FR-603: a causal HTTP program is project-only and deterministic by construction,
  // so it must require every attempt to succeed (>= 2 of 2). The relaxed N-of-M (>= 2
  // of >= 3) threshold is reserved for compound/agent programs whose nondeterminism is
  // structural — it cannot be opted into with a self-declared flag on an HTTP program.
  if (execution.nondeterministic === true) {
    throw new SpearConfigError(
      'nondeterministic thresholds are not allowed on a project-only HTTP program; '
      + 'the deterministic all-success threshold applies',
    );
  }
  const repetitions = requireInteger(execution, 'repetitions', 'program.execution', 2, 10);
  const minimum = requireInteger(
    execution,
    'minimumAttackSuccesses',
    'program.execution',
    2,
    repetitions,
  );
  if (minimum !== repetitions) {
    throw new SpearConfigError(
      'deterministic project-only program must require every attempt to succeed '
      + '(minimumAttackSuccesses === repetitions)',
    );
  }
  const oracle = requireRecord(program.oracle, 'program.oracle');
  if (oracle.kind === 'response-contains') {
    requireString(oracle, 'requestId', 'program.oracle');
    requireString(oracle, 'value', 'program.oracle');
    if (oracle.witness !== 'http-gateway') {
      throw new SpearConfigError('response-contains oracle requires http-gateway witness');
    }
  } else if (
    oracle.kind === 'state-path-increased'
    || oracle.kind === 'state-path-decreased'
    || oracle.kind === 'state-path-changed'
  ) {
    requireString(oracle, 'path', 'program.oracle');
    requireString(oracle, 'witness', 'program.oracle');
  } else if (oracle.kind === 'state-path-delta-exceeds') {
    requireString(oracle, 'path', 'program.oracle');
    requireString(oracle, 'witness', 'program.oracle');
    requireInteger(oracle, 'expected', 'program.oracle', 0, 1_000_000);
  } else if (oracle.kind === 'partial-effect') {
    requireString(oracle, 'committedPath', 'program.oracle');
    requireString(oracle, 'rolledBackPath', 'program.oracle');
    requireString(oracle, 'witness', 'program.oracle');
  } else if (oracle.kind === 'differential-access') {
    requireString(oracle, 'privilegedRequestId', 'program.oracle');
    requireString(oracle, 'unprivilegedRequestId', 'program.oracle');
    if (oracle.privilegedRequestId === oracle.unprivilegedRequestId) {
      throw new SpearConfigError(
        'differential-access oracle requires distinct privileged/unprivileged request IDs',
      );
    }
    if (oracle.witness !== 'http-gateway') {
      throw new SpearConfigError('differential-access oracle requires http-gateway witness');
    }
  } else if (oracle.kind === 'canary-egress') {
    requireString(oracle, 'sinkPath', 'program.oracle');
    requireString(oracle, 'canary', 'program.oracle');
    requireString(oracle, 'witness', 'program.oracle');
  } else {
    throw new SpearConfigError(`Unsupported causal HTTP oracle: ${String(oracle.kind)}`);
  }
  return program as unknown as CausalHttpAttackProgram;
}

export function asRecord(value: unknown, context: string): Record<string, unknown> {
  if (!isRecord(value)) throw new SpearConfigError(`${context} must be an object`);
  return value;
}
