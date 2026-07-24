import { sha256Digest } from './crypto.js';
import { SpearExecutionError } from './errors.js';
import type { WitnessEvent } from './types.js';

const GENESIS_HASH = `sha256:${'0'.repeat(64)}`;

function eventPayload(event: Omit<WitnessEvent, 'eventHash'>): unknown {
  return event;
}

export class ReceiptChain {
  readonly #runId: string;
  readonly #buildDigest: string;
  readonly #events: WitnessEvent[] = [];

  constructor(runId: string, buildDigest: string) {
    this.#runId = runId;
    this.#buildDigest = buildDigest;
  }

  append(
    source: string,
    summary: string,
    payload: unknown,
    details: Record<string, unknown> = {},
    now = new Date(),
  ): WitnessEvent {
    const withoutHash: Omit<WitnessEvent, 'eventHash'> = {
      schemaVersion: '3.0',
      runId: this.#runId,
      source,
      sequence: this.#events.length + 1,
      timestamp: now.toISOString(),
      buildDigest: this.#buildDigest,
      payloadDigest: sha256Digest(payload),
      previousEventHash: this.#events.at(-1)?.eventHash ?? GENESIS_HASH,
      summary,
      details,
    };
    const event: WitnessEvent = {
      ...withoutHash,
      eventHash: sha256Digest(eventPayload(withoutHash)),
    };
    this.#events.push(event);
    return event;
  }

  events(): WitnessEvent[] {
    return structuredClone(this.#events);
  }
}

export function verifyReceiptChain(events: WitnessEvent[]): void {
  let previous = GENESIS_HASH;
  for (const [index, event] of events.entries()) {
    if (event.sequence !== index + 1) {
      throw new SpearExecutionError(`Witness sequence mismatch at event ${index + 1}`);
    }
    if (event.previousEventHash !== previous) {
      throw new SpearExecutionError(`Witness previous hash mismatch at event ${event.sequence}`);
    }
    const { eventHash, ...withoutHash } = event;
    if (sha256Digest(eventPayload(withoutHash)) !== eventHash) {
      throw new SpearExecutionError(`Witness event hash mismatch at event ${event.sequence}`);
    }
    previous = eventHash;
  }
}
