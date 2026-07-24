import { sha256Digest, verifyDocumentSignature } from './crypto.js';
import { SpearConfigError } from './errors.js';
import type {
  PackManifest,
  PackRegistry,
  TrustStore,
} from './types.js';
import {
  validatePackRegistry,
  validateTrustStore,
} from './validation.js';

export function packDescriptor(pack: PackManifest): Omit<PackManifest, 'integrity'> {
  const { integrity: _integrity, ...descriptor } = pack;
  return descriptor;
}

export function computePackDescriptorDigest(
  pack: Omit<PackManifest, 'integrity'>,
): string {
  return sha256Digest(pack);
}

export interface VerifiedPackRegistry {
  registry: PackRegistry;
  registryDigest: string;
}

export function verifyPackRegistry(
  registryInput: unknown,
  trustStoreInput: unknown,
): VerifiedPackRegistry {
  const registry = validatePackRegistry(registryInput);
  const trustStore: TrustStore = validateTrustStore(trustStoreInput);
  verifyDocumentSignature(
    registry as unknown as Record<string, unknown>,
    registry.signature,
    trustStore,
  );

  for (const pack of registry.packs) {
    const actual = computePackDescriptorDigest(packDescriptor(pack));
    if (actual !== pack.integrity.descriptorDigest) {
      throw new SpearConfigError(
        `Pack descriptor digest mismatch for ${pack.id}: expected ${pack.integrity.descriptorDigest}, got ${actual}`,
      );
    }
  }
  return {
    registry,
    registryDigest: sha256Digest(registry),
  };
}

export function packSupportsTarget(pack: PackManifest, targetVersion: string): boolean {
  return pack.supportedTargetVersions.some((version) => {
    if (version === '*') return true;
    if (version.endsWith('.*')) return targetVersion.startsWith(version.slice(0, -1));
    return version === targetVersion;
  });
}
