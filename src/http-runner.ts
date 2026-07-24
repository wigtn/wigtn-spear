import { randomUUID } from 'node:crypto';
import { fetch as undiciFetch, type Dispatcher } from 'undici';
import { sha256Digest } from './crypto.js';
import { deriveCausalDisposition } from './disposition.js';
import { SpearConfigError, SpearExecutionError, SpearSafetyError } from './errors.js';
import { createPinnedDispatcher } from './pinning.js';
import { verifyPackRegistry } from './registry.js';
import { prepareRunPreview } from './run.js';
import {
  assertPinnableActiveOrigins,
  DestinationGuard,
  type AddressResolver,
} from './safety.js';
import type {
  AuthorizationManifest,
  CausalHttpAttackProgram,
  CausalRunResult,
  HttpObservation,
  HttpRequestSpec,
  HttpSequenceSpec,
  SequenceReceipt,
  StateDiffEntry,
} from './types.js';
import { AttackTwin } from './twin.js';
import { evaluateOracle, oracleStatePaths } from './oracle.js';
import { getPath } from './utils.js';
import {
  validateAuthorizationManifest,
  validateCausalHttpAttackProgram,
} from './validation.js';
import {
  ReceiptChain,
  verifyReceiptChain,
} from './witness.js';

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const FORBIDDEN_HEADERS = new Set([
  'authorization',
  'cookie',
  'host',
  'connection',
  'content-length',
  'transfer-encoding',
]);

interface InternalReceipt {
  receipt: SequenceReceipt;
  rawObservations: HttpObservation[];
}

export interface StoredCookie {
  value: string;
  path: string;
  secure: boolean;
}

export interface ParsedSetCookie extends StoredCookie {
  name: string;
  expired: boolean;
}

export function parseSetCookie(raw: string): ParsedSetCookie | null {
  const segments = raw.split(';');
  const first = segments[0] ?? '';
  const equals = first.indexOf('=');
  if (equals <= 0) return null;
  const name = first.slice(0, equals).trim();
  const value = first.slice(equals + 1).trim();
  if (!name) return null;
  let path = '/';
  let secure = false;
  let expired = false;
  for (const attribute of segments.slice(1)) {
    const attrEquals = attribute.indexOf('=');
    const key = (attrEquals === -1 ? attribute : attribute.slice(0, attrEquals)).trim().toLowerCase();
    const attrValue = attrEquals === -1 ? '' : attribute.slice(attrEquals + 1).trim();
    if (key === 'path' && attrValue.startsWith('/')) {
      path = attrValue;
    } else if (key === 'secure') {
      secure = true;
    } else if (key === 'max-age') {
      const seconds = Number(attrValue);
      if (Number.isFinite(seconds) && seconds <= 0) expired = true;
    } else if (key === 'expires') {
      const at = Date.parse(attrValue);
      if (Number.isFinite(at) && at <= Date.now()) expired = true;
    }
  }
  return { name, value, path, secure, expired };
}

// RFC 6265 §5.1.4 path-match: equal, or a prefix ending in '/', or a prefix
// immediately followed by '/'. A bare startsWith would leak an /admin cookie to
// /administrator.
function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || requestPath[cookiePath.length] === '/';
}

export function cookieHeader(jar: Map<string, StoredCookie>, url: URL): string | undefined {
  const isHttps = url.protocol === 'https:';
  const pairs: string[] = [];
  for (const [name, cookie] of jar.entries()) {
    if (cookie.secure && !isHttps) continue;
    if (!pathMatches(url.pathname, cookie.path)) continue;
    pairs.push(`${name}=${cookie.value}`);
  }
  return pairs.length > 0 ? pairs.join('; ') : undefined;
}

export interface CausalHttpRunOptions {
  acknowledgeAuthorization: boolean;
  now?: Date;
  fetchImpl?: typeof fetch;
  resolver?: AddressResolver;
  signal?: AbortSignal;
}

export interface CausalHttpRunInputs {
  manifest: unknown;
  trustStore: unknown;
  profile: unknown;
  inventory: unknown;
  registry: unknown;
  policy: unknown;
  program: unknown;
  twin: AttackTwin;
}

class StatefulHttpClient {
  readonly #manifest: AuthorizationManifest;
  readonly #guard: DestinationGuard;
  readonly #fetch: typeof fetch;
  readonly #dispatcher: Dispatcher | undefined;
  readonly #signal: AbortSignal | undefined;
  readonly #cookies = new Map<string, Map<string, StoredCookie>>();
  readonly #startedAt = Date.now();
  #requests = 0;

  constructor(
    manifest: AuthorizationManifest,
    fetchImpl: typeof fetch | undefined,
    resolver?: AddressResolver,
    signal?: AbortSignal,
  ) {
    this.#manifest = manifest;
    this.#guard = new DestinationGuard(manifest, resolver);
    this.#signal = signal;
    if (fetchImpl) {
      // An embedder-supplied fetch controls its own connections; SPEAR enforces
      // IP-literal origins for that path instead (see runCausalHttpAttack).
      this.#fetch = fetchImpl;
      this.#dispatcher = undefined;
    } else {
      // Real runs pin the socket to the pre-resolved IPs, so hostname targets are
      // safe against DNS rebinding. Use undici's fetch so the dispatcher applies.
      this.#fetch = undiciFetch as unknown as typeof fetch;
      this.#dispatcher = createPinnedDispatcher(this.#guard.pins);
    }
  }

  get requestCount(): number {
    return this.#requests;
  }

  async prepare(): Promise<void> {
    await Promise.all(
      this.#manifest.target.origins.map((origin) => this.#guard.pin(origin, 'target')),
    );
  }

  assertNotCancelled(): void {
    if (this.#signal?.aborted) {
      throw new SpearExecutionError('Run cancelled before completion; no further steps executed');
    }
  }

  #assertBudget(): void {
    this.assertNotCancelled();
    if (this.#requests >= this.#manifest.safety.maxRequests) {
      throw new SpearExecutionError('HTTP request budget exhausted');
    }
    if (Date.now() - this.#startedAt >= this.#manifest.safety.maxWallTimeMs) {
      throw new SpearExecutionError('HTTP wall-time budget exhausted');
    }
  }

  #headers(
    principalId: string,
    principalHeaders: Record<string, string>,
    request: HttpRequestSpec,
    url: URL,
  ): Headers {
    const headers = new Headers(principalHeaders);
    for (const [name, value] of Object.entries(request.headers ?? {})) {
      if (FORBIDDEN_HEADERS.has(name.toLowerCase())) {
        throw new SpearSafetyError(`Request ${request.id} may not override ${name}`);
      }
      if (/[\r\n]/u.test(value)) {
        throw new SpearSafetyError(`Request ${request.id} contains header injection`);
      }
      headers.set(name, value);
    }
    if (request.idempotencyKey) {
      headers.set('idempotency-key', request.idempotencyKey);
    }
    const jar = this.#cookies.get(principalId);
    if (jar && jar.size > 0) {
      const cookie = cookieHeader(jar, url);
      if (cookie) headers.set('cookie', cookie);
    }
    return headers;
  }

  #setCookieValues(response: Response): string[] {
    const getSetCookie = (response.headers as { getSetCookie?: () => string[] }).getSetCookie;
    if (typeof getSetCookie === 'function') {
      const values = getSetCookie.call(response.headers);
      if (values.length > 0) return values;
    }
    const single = response.headers.get('set-cookie');
    return single ? [single] : [];
  }

  #captureCookie(principalId: string, response: Response): void {
    const values = this.#setCookieValues(response);
    if (values.length === 0) return;
    const jar = this.#cookies.get(principalId) ?? new Map<string, StoredCookie>();
    for (const raw of values) {
      const parsed = parseSetCookie(raw);
      if (!parsed) continue;
      if (parsed.expired) {
        jar.delete(parsed.name);
      } else {
        jar.set(parsed.name, { value: parsed.value, path: parsed.path, secure: parsed.secure });
      }
    }
    if (jar.size > 0) this.#cookies.set(principalId, jar);
    else this.#cookies.delete(principalId);
  }

  async request(
    principalId: string,
    principalHeaders: Record<string, string>,
    request: HttpRequestSpec,
  ): Promise<HttpObservation> {
    if (MUTATING_METHODS.has(request.method) && !this.#manifest.safety.allowMutations) {
      throw new SpearSafetyError(
        `Mutating request ${request.id} requires manifest safety.allowMutations`,
      );
    }
    const base = this.#manifest.target.origins[0];
    if (!base) throw new SpearConfigError('Authorization manifest has no target origin');
    let url = new URL(request.path, base);
    let method = request.method;
    let body = request.body;
    let redirects = 0;

    while (true) {
      this.#assertBudget();
      await this.#guard.revalidate(url.toString(), 'target');
      this.#requests += 1;
      const headers = this.#headers(principalId, principalHeaders, request, url);
      const response = await this.#fetch(url, {
        method,
        headers,
        redirect: 'manual',
        ...(this.#dispatcher ? { dispatcher: this.#dispatcher } : {}),
        ...(this.#signal ? { signal: this.#signal } : {}),
        ...(body !== undefined && method !== 'GET' && method !== 'HEAD' ? { body } : {}),
      } as RequestInit);
      this.#captureCookie(principalId, response);

      if (REDIRECT_STATUSES.has(response.status)) {
        const location = response.headers.get('location');
        if (!location) throw new SpearExecutionError('Redirect response is missing Location');
        if (redirects >= 3) throw new SpearExecutionError('Redirect limit exceeded');
        const next = new URL(location, url);
        await this.#guard.revalidate(next.toString(), 'target');
        redirects += 1;
        if (response.status === 303) {
          method = 'GET';
          body = undefined;
        }
        url = next;
        continue;
      }

      const declaredLength = Number(response.headers.get('content-length') ?? '0');
      if (
        Number.isFinite(declaredLength)
        && declaredLength > this.#manifest.safety.maxResponseBytes
      ) {
        throw new SpearExecutionError('HTTP response exceeds declared byte budget');
      }
      const bytes = Buffer.from(await response.arrayBuffer());
      if (bytes.byteLength > this.#manifest.safety.maxResponseBytes) {
        throw new SpearExecutionError('HTTP response exceeds byte budget');
      }
      const responseHeaders: Record<string, string> = {};
      response.headers.forEach((value, name) => {
        if (name.toLowerCase() !== 'set-cookie') responseHeaders[name] = value;
      });
      return {
        requestId: request.id,
        method,
        url: url.toString(),
        status: response.status,
        headers: responseHeaders,
        body: bytes.toString('utf8'),
      };
    }
  }
}

function redactText(value: string, canaries: string[]): string {
  let result = value
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]{8,}/giu, '[REDACTED]')
    .replace(/\b(?:sk|ghp|github_pat)_[A-Za-z0-9_-]{12,}\b/gu, '[REDACTED]');
  for (const canary of canaries) result = result.split(canary).join('[CANARY]');
  return result.length > 2_000 ? `${result.slice(0, 2_000)}…` : result;
}

const EMPTY_STATE_DIGEST = sha256Digest({});

function emptyReceipt(sequence: HttpSequenceSpec): SequenceReceipt {
  return {
    sequenceId: sequence.id,
    principalId: sequence.principalId,
    observations: [],
    beforeStateDigest: EMPTY_STATE_DIGEST,
    afterStateDigest: EMPTY_STATE_DIGEST,
    stateDiff: [],
    predicateObserved: false,
    events: [],
  };
}

function stateAllowlist(program: CausalHttpAttackProgram): string[] {
  return oracleStatePaths(program.oracle);
}

// Numbers (counters) are disclosed raw; any other value is digested so sensitive
// state (cross-tenant rows, secrets) never lands in a receipt (Critical #3 / m-6).
function redactStateValue(value: unknown): unknown {
  if (typeof value === 'number' || value === undefined) return value;
  return sha256Digest(value);
}

function allowlistedStateDiff(
  before: Record<string, unknown>,
  after: Record<string, unknown>,
  allowlist: string[],
): StateDiffEntry[] {
  return allowlist.map((path) => ({
    path,
    before: redactStateValue(getPath(before, path)),
    after: redactStateValue(getPath(after, path)),
  }));
}

async function executeSequence(
  runId: string,
  program: CausalHttpAttackProgram,
  sequence: HttpSequenceSpec,
  twin: AttackTwin,
  client: StatefulHttpClient,
  chain: ReceiptChain,
): Promise<InternalReceipt> {
  client.assertNotCancelled();
  const principal = twin.principal(sequence.principalId);
  const beforeState = await twin.state();
  const eventStart = chain.events().length;
  chain.append('state-witness', `${sequence.id} state before`, beforeState, {
    sequenceId: sequence.id,
    phase: 'before',
  });
  const observations: HttpObservation[] = [];
  for (const request of sequence.requests) {
    // A request may act as a different principal than the sequence default
    // (e.g. seed data as A, then attack as B within one sequence).
    const actor = request.asPrincipalId ? twin.principal(request.asPrincipalId) : principal;
    const observation = await client.request(actor.id, actor.headers, request);
    observations.push(observation);
    chain.append('http-gateway', `${request.id} response`, {
      status: observation.status,
      body: observation.body,
    }, {
      sequenceId: sequence.id,
      requestId: request.id,
      method: observation.method,
      url: observation.url,
      status: observation.status,
    });
  }
  const afterState = await twin.state();
  chain.append('state-witness', `${sequence.id} state after`, afterState, {
    sequenceId: sequence.id,
    phase: 'after',
  });
  const observed = evaluateOracle(program.oracle, { observations, beforeState, afterState });
  const canaries = twin.definition.assets.map((asset) => asset.canary);
  return {
    rawObservations: observations,
    receipt: {
      sequenceId: sequence.id,
      principalId: sequence.principalId,
      observations: observations.map((item) => ({
        ...item,
        body: redactText(item.body, canaries),
      })),
      beforeStateDigest: sha256Digest(beforeState),
      afterStateDigest: sha256Digest(afterState),
      stateDiff: allowlistedStateDiff(beforeState, afterState, stateAllowlist(program)),
      predicateObserved: observed,
      events: chain.events().slice(eventStart),
    },
  };
}

export async function runCausalHttpAttack(
  inputs: CausalHttpRunInputs,
  options: CausalHttpRunOptions,
): Promise<CausalRunResult> {
  const program = validateCausalHttpAttackProgram(inputs.program);
  const manifest = validateAuthorizationManifest(inputs.manifest);
  // The real runner pins the socket to resolved IPs (undici dispatcher), so
  // hostname targets are safe. An embedder-supplied fetch has no such pin, so
  // that path is still restricted to IP-literal origins.
  if (options.fetchImpl) assertPinnableActiveOrigins(manifest);
  const requiredCapabilities = ['run:project', program.capability];
  const preview = prepareRunPreview(
    inputs.manifest,
    inputs.trustStore,
    inputs.profile,
    inputs.inventory,
    inputs.registry,
    inputs.policy,
    {
      acknowledgeAuthorization: options.acknowledgeAuthorization,
      requiredCapabilities,
      ...(options.now ? { now: options.now } : {}),
    },
  );
  const verifiedRegistry = verifyPackRegistry(inputs.registry, inputs.trustStore);
  if (
    !verifiedRegistry.registry.packs.some(
      (pack) => preview.selectedPackIds.includes(pack.id)
        && pack.capabilities.includes(program.capability),
    )
  ) {
    throw new SpearSafetyError(
      `No selected signed pack grants attack capability ${program.capability}`,
    );
  }

  const runId = `run-${randomUUID()}`;
  const client = new StatefulHttpClient(
    manifest,
    options.fetchImpl,
    options.resolver,
    options.signal,
  );
  client.assertNotCancelled();
  const chain = new ReceiptChain(runId, preview.target.buildDigest);
  const identity = {
    schemaVersion: '3.0' as const,
    kind: 'causal-run' as const,
    runId,
    programId: program.id,
    targetBuildDigest: preview.target.buildDigest,
    manifestDigest: preview.authorization.manifestDigest,
    registryDigest: preview.registryDigest,
  };

  try {
    await client.prepare();
    await inputs.twin.prepare(options.now ?? new Date());

    await inputs.twin.resetAndVerify();
    const baseline = await executeSequence(
      runId,
      program,
      program.execution.baseline,
      inputs.twin,
      client,
      chain,
    );
    const attacks: InternalReceipt[] = [];
    for (let attempt = 0; attempt < program.execution.repetitions; attempt += 1) {
      await inputs.twin.resetAndVerify();
      attacks.push(await executeSequence(
        runId,
        program,
        program.execution.attack,
        inputs.twin,
        client,
        chain,
      ));
    }
    await inputs.twin.resetAndVerify();
    const counterfactual = await executeSequence(
      runId,
      program,
      program.execution.counterfactual,
      inputs.twin,
      client,
      chain,
    );

    // A receipt-chain integrity failure is reported as a structured `error`
    // disposition, not thrown, so the caller always receives a run result.
    let witnessFailure: string | undefined;
    try {
      verifyReceiptChain(chain.events());
    } catch (error) {
      witnessFailure = error instanceof Error ? error.message : String(error);
    }
    const outcome = deriveCausalDisposition({
      baselineObserved: baseline.receipt.predicateObserved,
      counterfactualObserved: counterfactual.receipt.predicateObserved,
      attackObservations: attacks.map((item) => item.receipt.predicateObserved),
      minimumAttackSuccesses: program.execution.minimumAttackSuccesses,
    });

    return {
      ...identity,
      disposition: witnessFailure ? 'error' : outcome.disposition,
      attempts: outcome.attempts,
      attackSuccesses: outcome.attackSuccesses,
      baseline: baseline.receipt,
      attacks: attacks.map((item) => item.receipt),
      counterfactual: counterfactual.receipt,
      reason: witnessFailure
        ? `Witness chain verification failed: ${witnessFailure}`
        : outcome.reason,
    };
  } catch (error) {
    // Cancellation and budget stops are intentional and propagate; every other
    // execution/witness failure becomes a structured `error` run, never a proven
    // finding, so downstream consumers see an explicit gap rather than a crash.
    if (error instanceof SpearExecutionError && !/cancelled|budget/u.test(error.message)) {
      return {
        ...identity,
        disposition: 'error',
        attempts: 0,
        attackSuccesses: 0,
        baseline: emptyReceipt(program.execution.baseline),
        attacks: [],
        counterfactual: emptyReceipt(program.execution.counterfactual),
        reason: `Execution error before a verdict could be reached: ${error.message}`,
      };
    }
    throw error;
  }
}
