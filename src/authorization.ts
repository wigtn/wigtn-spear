import { sha256Digest, verifyDocumentSignature } from './crypto.js';
import { SpearSafetyError } from './errors.js';
import type {
  AuthorizationManifest,
  TrustStore,
  VerifiedAuthorization,
} from './types.js';
import {
  validateAuthorizationManifest,
  validateTrustStore,
} from './validation.js';

export interface AuthorizationRequirements {
  acknowledgeAuthorization: boolean;
  requiredCapabilities: string[];
  actualBuildDigest: string;
  now?: Date;
}

export function verifyAuthorization(
  manifestInput: unknown,
  trustStoreInput: unknown,
  requirements: AuthorizationRequirements,
): VerifiedAuthorization {
  const manifest = validateAuthorizationManifest(manifestInput);
  const trustStore: TrustStore = validateTrustStore(trustStoreInput);

  // This function is deliberately the first boundary of every active run.
  // No target-aware dependency is called until every check below succeeds.
  if (!requirements.acknowledgeAuthorization) {
    throw new SpearSafetyError('Active run requires --acknowledge-authorization');
  }
  if (manifest.target.environment === 'production') {
    throw new SpearSafetyError('Active runs against production-class targets are prohibited');
  }

  const now = (requirements.now ?? new Date()).getTime();
  if (Date.parse(manifest.engagement.issuedAt) > now + 300_000) {
    throw new SpearSafetyError('Authorization manifest issue time is in the future');
  }
  if (Date.parse(manifest.engagement.expiresAt) <= now) {
    throw new SpearSafetyError('Authorization manifest has expired');
  }
  if (manifest.target.buildDigest !== requirements.actualBuildDigest) {
    throw new SpearSafetyError(
      `Target build digest mismatch: authorized ${manifest.target.buildDigest}, actual ${requirements.actualBuildDigest}`,
    );
  }
  const missingCapabilities = requirements.requiredCapabilities.filter(
    (capability) => !manifest.capabilities.includes(capability),
  );
  if (missingCapabilities.length > 0) {
    throw new SpearSafetyError(
      `Authorization is missing capabilities: ${missingCapabilities.join(', ')}`,
    );
  }

  verifyDocumentSignature(
    manifest as unknown as Record<string, unknown>,
    manifest.signature,
    trustStore,
  );
  return {
    manifest,
    manifestDigest: sha256Digest(manifest),
  };
}

export function manifestWithSignature(
  unsigned: Omit<AuthorizationManifest, 'signature'>,
  signature: AuthorizationManifest['signature'],
): AuthorizationManifest {
  return validateAuthorizationManifest({ ...unsigned, signature });
}
