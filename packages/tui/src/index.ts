/**
 * @wigtn/tui - Terminal UI for WIGTN-SPEAR attack visualization
 *
 * Usage:
 *   const { renderAttackTUI, AttackEventBus } = await import('@wigtn/tui');
 *   const bus = new AttackEventBus();
 *   const { waitUntilExit } = renderAttackTUI({ bus, targetUrl, scanId });
 */

import React from 'react';
import { render } from 'ink';
import { App } from './app.js';
import { AttackEventBus } from './event-bus.js';

export { AttackEventBus } from './event-bus.js';
export type { TUIFinding, SeverityCounts, AttackState, AttackAction, AttackEvents } from './types.js';

interface RenderOptions {
  bus: AttackEventBus;
  targetUrl: string;
  scanId: string;
  onQuit?: () => void;
}

interface RenderResult {
  waitUntilExit: () => Promise<void>;
  unmount: () => void;
}

export function renderAttackTUI(options: RenderOptions): RenderResult {
  const { bus, targetUrl, scanId, onQuit = () => process.exit(0) } = options;

  const instance = render(
    React.createElement(App, { bus, targetUrl, scanId, onQuit }),
  );

  return {
    waitUntilExit: () => instance.waitUntilExit(),
    unmount: () => instance.unmount(),
  };
}
