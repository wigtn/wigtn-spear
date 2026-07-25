import { fetch as undiciFetch, type Dispatcher } from 'undici';
import { SpearConfigError, SpearExecutionError } from '../errors.js';
import { DestinationGuard, type DestinationPurpose } from '../safety.js';
import { isRecord } from '../utils.js';
import type { AgentSink, AgentTarget } from './types.js';

export type FetchImpl = typeof fetch;

export interface AgentFetchDeps {
  guard: DestinationGuard;
  /** An embedder-supplied fetch (test/injection path); IP-literal origins are enforced upstream. */
  fetchImpl?: FetchImpl;
  /** undici dispatcher pinning hostnames to pre-resolved IPs (real-run path). */
  dispatcher?: Dispatcher;
}

const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;

/** Resolve a dotted path that may include array indices (`choices.0.message.content`). */
function resolvePath(value: unknown, path: string): unknown {
  if (path.trim() === '') return value;
  return path.split('.').reduce<unknown>((current, segment) => {
    if (Array.isArray(current)) {
      const index = Number(segment);
      return Number.isInteger(index) ? current[index] : undefined;
    }
    if (isRecord(current)) return current[segment];
    return undefined;
  }, value);
}

async function readBounded(response: Response, maxBytes: number): Promise<string> {
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.byteLength > maxBytes) {
    throw new SpearExecutionError(`Agent response exceeded ${maxBytes} bytes`);
  }
  return buffer.toString('utf8');
}

async function guardedFetch(
  raw: string,
  purpose: DestinationPurpose,
  init: RequestInit,
  deps: AgentFetchDeps,
): Promise<Response> {
  // On the real-run path, revalidate the pin right before connecting so a DNS
  // rebinding between pin and connect is caught; the undici dispatcher then binds
  // the socket to the pinned IP. On the injected-fetch path we only assert scope.
  const url = deps.fetchImpl
    ? deps.guard.assertUrl(raw, purpose)
    : await deps.guard.revalidate(raw, purpose);
  const doFetch = deps.fetchImpl ?? (undiciFetch as unknown as typeof fetch);
  return doFetch(url.href, {
    ...init,
    redirect: 'error',
    ...(deps.dispatcher ? { dispatcher: deps.dispatcher } : {}),
  } as RequestInit);
}

/**
 * Send one message to the black-box agent and extract its reply text. The endpoint
 * is validated against the authorization scope before any socket opens; the reply
 * is stored only as evidence, never trusted as a verdict.
 */
export async function callAgent(
  target: AgentTarget,
  message: string,
  deps: AgentFetchDeps,
): Promise<{ reply: string; status: number; raw: string }> {
  const body = target.bodyTemplate.replace('{{message}}', () => JSON.stringify(message).slice(1, -1));
  let response: Response;
  try {
    response = await guardedFetch(
      target.endpoint,
      'target',
      {
        method: target.method ?? 'POST',
        headers: { 'content-type': 'application/json', ...(target.headers ?? {}) },
        body,
      },
      deps,
    );
  } catch (error) {
    throw new SpearExecutionError(
      `Agent request failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const raw = await readBounded(response, target.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES);
  let reply: unknown;
  try {
    reply = resolvePath(JSON.parse(raw), target.replyJsonPath);
  } catch {
    throw new SpearConfigError('Agent response was not JSON');
  }
  if (typeof reply !== 'string') {
    throw new SpearConfigError(`Agent reply path '${target.replyJsonPath}' did not resolve to a string`);
  }
  return { reply, status: response.status, raw };
}

/** Reset the owned witness sink to a clean state between attempts. */
export async function resetSink(sink: AgentSink, deps: AgentFetchDeps): Promise<void> {
  try {
    await guardedFetch(sink.resetUrl, 'control', { method: 'POST' }, deps);
  } catch (error) {
    throw new SpearExecutionError(
      `Sink reset failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** Ask the owned sink whether it observed the run canary — the independent witness. */
export async function sinkObserved(
  sink: AgentSink,
  canary: string,
  deps: AgentFetchDeps,
): Promise<boolean> {
  const observeUrl = new URL(sink.observeUrl);
  observeUrl.searchParams.set('token', canary);
  let response: Response;
  try {
    response = await guardedFetch(observeUrl.href, 'canary', { method: 'GET' }, deps);
  } catch (error) {
    throw new SpearExecutionError(
      `Sink observation failed: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  const raw = await readBounded(response, 4096);
  try {
    const parsed: unknown = JSON.parse(raw);
    return isRecord(parsed) && parsed.observed === true;
  } catch {
    throw new SpearConfigError('Sink observation was not JSON');
  }
}
