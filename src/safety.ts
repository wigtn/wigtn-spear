import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { SpearConfigError, SpearSafetyError } from './errors.js';
import type {
  AttackCorpus,
  AuthorizationManifest,
} from './types.js';
import {
  isRecord,
  requireArray,
  requireRecord,
  requireString,
  stringArray,
} from './utils.js';

export type DestinationPurpose = 'target' | 'canary' | 'control';

export interface AddressResolver {
  resolve(hostname: string): Promise<string[]>;
}

const systemResolver: AddressResolver = {
  async resolve(hostname: string): Promise<string[]> {
    if (isIP(hostname)) return [hostname];
    const addresses = await lookup(hostname, { all: true, verbatim: true });
    return [...new Set(addresses.map((item) => item.address))].sort();
  },
};

function exactOrigin(raw: string, context: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new SpearConfigError(`${context} must be an absolute URL`);
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new SpearSafetyError(`${context} must be credential-free HTTP(S)`);
  }
  if (raw !== url.origin) {
    throw new SpearConfigError(`${context} must be a canonical exact origin`);
  }
  return url.origin;
}

function isMetadataAddress(address: string): boolean {
  const normalized = address.toLowerCase();
  return normalized === '169.254.169.254'
    || normalized === '100.100.100.200'
    || normalized === 'fd00:ec2::254'
    || normalized.startsWith('fe80:');
}

export class DestinationGuard {
  readonly #manifest: AuthorizationManifest;
  readonly #resolver: AddressResolver;
  readonly #pins = new Map<string, string[]>();

  constructor(manifest: AuthorizationManifest, resolver: AddressResolver = systemResolver) {
    this.#manifest = manifest;
    this.#resolver = resolver;
  }

  /** The live hostname→addresses pin map, for building a pinned socket dispatcher. */
  get pins(): ReadonlyMap<string, readonly string[]> {
    return this.#pins;
  }

  assertUrl(raw: string, purpose: DestinationPurpose): URL {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new SpearSafetyError(`Destination is not an absolute URL: ${raw}`);
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
      throw new SpearSafetyError(`Destination must be credential-free HTTP(S): ${raw}`);
    }
    if (isMetadataAddress(url.hostname)) {
      throw new SpearSafetyError(`Metadata destination is always prohibited: ${url.hostname}`);
    }
    const allowed = purpose === 'target'
      ? this.#manifest.target.origins
      : purpose === 'canary'
        ? this.#manifest.safety.allowedCanaryOrigins
        : this.#manifest.safety.allowedControlOrigins ?? [];
    if (!allowed.includes(url.origin)) {
      throw new SpearSafetyError(`Out-of-scope ${purpose} origin: ${url.origin}`);
    }
    if (!this.#manifest.safety.allowedHosts.includes(url.hostname)) {
      throw new SpearSafetyError(`Destination host is absent from allowedHosts: ${url.hostname}`);
    }
    return url;
  }

  async pin(raw: string, purpose: DestinationPurpose): Promise<URL> {
    const url = this.assertUrl(raw, purpose);
    const addresses = (await this.#resolver.resolve(url.hostname)).sort();
    if (addresses.length === 0) {
      throw new SpearSafetyError(`Destination did not resolve: ${url.hostname}`);
    }
    if (addresses.some(isMetadataAddress)) {
      throw new SpearSafetyError(`Destination resolves to prohibited metadata address`);
    }
    this.#pins.set(url.hostname, addresses);
    return url;
  }

  async revalidate(raw: string, purpose: DestinationPurpose): Promise<URL> {
    const url = this.assertUrl(raw, purpose);
    const pinned = this.#pins.get(url.hostname);
    if (!pinned) return this.pin(raw, purpose);
    const current = (await this.#resolver.resolve(url.hostname)).sort();
    if (
      pinned.length !== current.length
      || pinned.some((address, index) => address !== current[index])
    ) {
      throw new SpearSafetyError(`DNS rebinding detected for ${url.hostname}`);
    }
    return url;
  }
}

function decodeBase64(value: string, context: string): Buffer {
  if (!/^[A-Za-z0-9+/]*={0,2}$/u.test(value)) {
    throw new SpearConfigError(`${context} must be base64`);
  }
  return Buffer.from(value, 'base64');
}

function looksExecutable(content: Buffer): boolean {
  if (content.length >= 4) {
    if (content[0] === 0x7f && content.subarray(1, 4).toString('ascii') === 'ELF') return true;
    if (content.subarray(0, 2).toString('ascii') === 'MZ') return true;
    if (content.subarray(0, 2).toString('ascii') === '#!') return true;
    const magic = content.subarray(0, 4).toString('hex');
    if (magic === 'feedface' || magic === 'feedfacf' || magic === 'cafebabe') return true;
  }
  return false;
}

export function validateAttackCorpus(
  value: unknown,
  manifest: AuthorizationManifest,
): AttackCorpus {
  const corpus = requireRecord(value, 'corpus');
  if (corpus.schemaVersion !== '3.0' || corpus.kind !== 'attack-corpus') {
    throw new SpearConfigError('corpus must be a SPEAR v3 attack-corpus');
  }
  requireArray(corpus, 'files', 'corpus').forEach((item, index) => {
    const file = requireRecord(item, `corpus.files[${index}]`);
    requireString(file, 'id', `corpus.files[${index}]`);
    requireString(file, 'filename', `corpus.files[${index}]`);
    requireString(file, 'mediaType', `corpus.files[${index}]`);
    if (file.inertCanary !== true) {
      throw new SpearSafetyError(`corpus.files[${index}] must be an inert canary`);
    }
    const decoded = decodeBase64(
      requireString(file, 'contentBase64', `corpus.files[${index}]`),
      `corpus.files[${index}].contentBase64`,
    );
    if (looksExecutable(decoded)) {
      throw new SpearSafetyError(`corpus.files[${index}] contains executable content`);
    }
  });
  requireArray(corpus, 'identities', 'corpus').forEach((item, index) => {
    const identity = requireRecord(item, `corpus.identities[${index}]`);
    requireString(identity, 'id', `corpus.identities[${index}]`);
    if (identity.fixture !== true) {
      throw new SpearSafetyError(`corpus.identities[${index}] must be fixture-only`);
    }
    const token = requireString(identity, 'token', `corpus.identities[${index}]`);
    if (!token.startsWith('fixture_')) {
      throw new SpearSafetyError(`corpus.identities[${index}] may not contain a live credential`);
    }
  });
  const recipients = stringArray(corpus, 'recipients', 'corpus');
  if (recipients.some((recipient) => !recipient.endsWith('.test'))) {
    throw new SpearSafetyError('Corpus recipients must use reserved .test addresses');
  }
  const analyzers = stringArray(corpus, 'analyzerOrigins', 'corpus');
  for (const analyzer of analyzers) {
    const origin = exactOrigin(analyzer, 'corpus analyzer origin');
    if (!manifest.safety.allowedCanaryOrigins.includes(origin)) {
      throw new SpearSafetyError(`External analyzer is outside owned canary scope: ${origin}`);
    }
  }
  return corpus as unknown as AttackCorpus;
}

/**
 * Active runs open real sockets through the global `fetch`, which re-resolves
 * DNS independently of `DestinationGuard`, leaving a resolve→connect TOCTOU for
 * hostname targets. Until the connection is pinned to a resolved IP with a
 * custom dispatcher, we bound the guarantee to what we can actually enforce:
 * every active target origin must already be an IP literal, which fetch cannot
 * re-resolve to a different address. Hostname origins are rejected rather than
 * attacked under a pin we cannot honor.
 *
 * Scope: canary/callback origins are not yet connected to by the active runner;
 * extend this check to them when SSRF-style callbacks are added.
 */
export function assertPinnableOrigin(origin: string, context: string): void {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new SpearConfigError(`${context} must be an absolute URL: ${origin}`);
  }
  const host = url.hostname.replace(/^\[|\]$/gu, '');
  if (isIP(host) === 0) {
    throw new SpearSafetyError(
      `${context} must use an IP-literal host so the connection can be pinned; `
      + `hostname '${url.hostname}' would be re-resolved by fetch and leave a DNS `
      + `TOCTOU: ${origin}`,
    );
  }
}

export function assertPinnableActiveOrigins(manifest: AuthorizationManifest): void {
  for (const origin of manifest.target.origins) {
    assertPinnableOrigin(origin, 'Active run target origin');
  }
}

export function assertNoRawSecrets(value: unknown): void {
  const serialized = JSON.stringify(value);
  if (
    /\bBearer\s+[A-Za-z0-9._~+/-]{8,}/iu.test(serialized)
    || /\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{12,}\b/u.test(serialized)
  ) {
    throw new SpearSafetyError('Artifact contains a raw credential');
  }
}
