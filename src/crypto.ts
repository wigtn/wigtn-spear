import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from 'node:crypto';
import { SpearConfigError, SpearSafetyError } from './errors.js';
import type { SignatureEnvelope, TrustStore } from './types.js';
import { isRecord } from './utils.js';

function canonicalize(value: unknown, seen: Set<object>): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new SpearConfigError('Canonical JSON does not allow non-finite numbers');
    }
    return value;
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new SpearConfigError('Canonical JSON does not allow cycles');
    seen.add(value);
    const result = value.map((item) => canonicalize(item, seen));
    seen.delete(value);
    return result;
  }
  if (isRecord(value)) {
    if (seen.has(value)) throw new SpearConfigError('Canonical JSON does not allow cycles');
    seen.add(value);
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const item = value[key];
      if (
        item === undefined
        || typeof item === 'function'
        || typeof item === 'symbol'
        || typeof item === 'bigint'
      ) {
        throw new SpearConfigError(`Canonical JSON cannot encode property ${key}`);
      }
      result[key] = canonicalize(item, seen);
    }
    seen.delete(value);
    return result;
  }
  throw new SpearConfigError(`Canonical JSON cannot encode ${typeof value}`);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value, new Set()));
}

export function sha256Digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value), 'utf8').digest('hex')}`;
}

export function withoutSignature<T extends Record<string, unknown>>(value: T): Omit<T, 'signature'> {
  const { signature: _signature, ...unsigned } = value;
  return unsigned;
}

export function signDocument(
  unsigned: Record<string, unknown>,
  privateKeyPem: string,
  keyId: string,
): SignatureEnvelope {
  let signature: Buffer;
  try {
    signature = sign(null, Buffer.from(canonicalJson(unsigned)), createPrivateKey(privateKeyPem));
  } catch (error) {
    throw new SpearConfigError(
      `Unable to sign document: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return {
    algorithm: 'Ed25519',
    keyId,
    value: signature.toString('base64'),
  };
}

export function verifyDocumentSignature(
  signed: Record<string, unknown>,
  signature: SignatureEnvelope,
  trustStore: TrustStore,
): void {
  const matchingKeys = trustStore.keys.filter((key) => key.keyId === signature.keyId);
  if (matchingKeys.length !== 1) {
    throw new SpearSafetyError(`Unknown or duplicate signing key: ${signature.keyId}`);
  }
  const key = matchingKeys[0];
  if (!key || key.status !== 'active') {
    throw new SpearSafetyError(`Signing key is revoked: ${signature.keyId}`);
  }
  let valid = false;
  try {
    valid = verify(
      null,
      Buffer.from(canonicalJson(withoutSignature(signed))),
      createPublicKey(key.publicKeyPem),
      Buffer.from(signature.value, 'base64'),
    );
  } catch {
    valid = false;
  }
  if (!valid) {
    throw new SpearSafetyError('Document signature is invalid');
  }
}

export function generateEd25519KeyPair(): {
  privateKeyPem: string;
  publicKeyPem: string;
} {
  const pair = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function isSha256Digest(value: string): boolean {
  return /^sha256:[a-f0-9]{64}$/u.test(value);
}
