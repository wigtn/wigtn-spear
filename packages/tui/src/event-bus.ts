/**
 * @wigtn/tui - Typed EventEmitter for attack events
 *
 * Bridges the gap between the attack pipeline (which emits findings)
 * and the React/ink UI (which renders them). Pure event forwarding,
 * no business logic.
 */

import { EventEmitter } from 'node:events';
import type { AttackEvents, TUIFinding, SeverityCounts } from './types.js';

type EventMap = {
  [K in keyof AttackEvents]: [AttackEvents[K]];
};

export class AttackEventBus {
  private emitter = new EventEmitter();

  constructor() {
    // Allow many listeners (components + hooks)
    this.emitter.setMaxListeners(50);
  }

  emit<K extends keyof EventMap>(event: K, data: EventMap[K][0]): void {
    this.emitter.emit(event as string, data);
  }

  on<K extends keyof EventMap>(event: K, listener: (data: EventMap[K][0]) => void): void {
    this.emitter.on(event as string, listener as (...args: unknown[]) => void);
  }

  off<K extends keyof EventMap>(event: K, listener: (data: EventMap[K][0]) => void): void {
    this.emitter.off(event as string, listener as (...args: unknown[]) => void);
  }

  /** Convenience: emit a finding event */
  emitFinding(finding: TUIFinding): void {
    this.emit('finding', finding);
  }

  /** Convenience: emit scan completion */
  emitComplete(durationMs: number, grade: string, counts: SeverityCounts): void {
    this.emit('scan-complete', { durationMs, grade, counts });
  }

  /** Remove all listeners */
  removeAllListeners(): void {
    this.emitter.removeAllListeners();
  }
}
