import { SpearConfigError, SpearExecutionError } from './errors.js';
import {
  assertPinnableOrigin,
  DestinationGuard,
  type AddressResolver,
} from './safety.js';
import type { AuthorizationManifest, TwinControlChannel } from './types.js';
import type { StateController } from './twin.js';
import { isRecord } from './utils.js';

export interface HttpControlOptions {
  fetchImpl?: typeof fetch;
  resolver?: AddressResolver;
}

/**
 * A Twin StateController that snapshots and resets disposable state over an
 * owned control-plane origin, independent of the HTTP surface under attack.
 *
 * The control origin must be authorized in `manifest.safety.allowedControlOrigins`
 * and, like every active destination, must be an IP literal so the socket can be
 * pinned (Critical #2). Snapshots are bounded by the manifest response budget.
 */
export class HttpControlStateController implements StateController {
  readonly #control: TwinControlChannel;
  readonly #manifest: AuthorizationManifest;
  readonly #guard: DestinationGuard;
  readonly #fetch: typeof fetch;

  constructor(
    control: TwinControlChannel,
    manifest: AuthorizationManifest,
    options: HttpControlOptions = {},
  ) {
    this.#control = control;
    this.#manifest = manifest;
    this.#guard = new DestinationGuard(manifest, options.resolver);
    this.#fetch = options.fetchImpl ?? fetch;
    // Fail fast on unpinnable or malformed control endpoints before any run.
    this.#endpoint(control.resetUrl, 'twin control reset URL');
    this.#endpoint(control.snapshotUrl, 'twin control snapshot URL');
  }

  #endpoint(raw: string, context: string): URL {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      throw new SpearConfigError(`${context} must be an absolute URL: ${raw}`);
    }
    assertPinnableOrigin(url.origin, context);
    return url;
  }

  async #readBody(response: Response, context: string): Promise<Buffer> {
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.byteLength > this.#manifest.safety.maxResponseBytes) {
      throw new SpearExecutionError(`${context} exceeds the response byte budget`);
    }
    return bytes;
  }

  async #send(url: URL, method: 'GET' | 'POST', context: string): Promise<Response> {
    try {
      return await this.#fetch(url, { method, redirect: 'manual' });
    } catch (error) {
      throw new SpearExecutionError(
        `${context} request failed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async snapshot(): Promise<Record<string, unknown>> {
    const url = this.#endpoint(this.#control.snapshotUrl, 'twin control snapshot URL');
    await this.#guard.revalidate(url.toString(), 'control');
    const response = await this.#send(url, 'GET', 'Twin control snapshot');
    if (response.status !== 200) {
      throw new SpearExecutionError(`Twin control snapshot returned status ${response.status}`);
    }
    const bytes = await this.#readBody(response, 'Twin control snapshot');
    let parsed: unknown;
    try {
      parsed = JSON.parse(bytes.toString('utf8'));
    } catch {
      throw new SpearExecutionError('Twin control snapshot did not return JSON');
    }
    if (!isRecord(parsed)) {
      throw new SpearExecutionError('Twin control snapshot must be a JSON object');
    }
    return parsed;
  }

  async reset(): Promise<void> {
    const url = this.#endpoint(this.#control.resetUrl, 'twin control reset URL');
    await this.#guard.revalidate(url.toString(), 'control');
    const response = await this.#send(url, 'POST', 'Twin control reset');
    if (response.status < 200 || response.status >= 300) {
      throw new SpearExecutionError(`Twin control reset returned status ${response.status}`);
    }
    await this.#readBody(response, 'Twin control reset');
  }
}
