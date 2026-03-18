/**
 * Root <App> component for the attack TUI.
 */

import React, { useCallback } from 'react';
import { Box } from 'ink';
import type { AttackEventBus } from './event-bus.js';
import { useAttackState } from './hooks/use-attack-state.js';
import { useElapsedTimer } from './hooks/use-elapsed-timer.js';
import { useKeyboard } from './hooks/use-keyboard.js';
import { Header } from './components/header.js';
import { ProgressBar } from './components/progress-bar.js';
import { SeveritySummary } from './components/severity-summary.js';
import { FindingsList } from './components/findings-list.js';
import { StatusBar } from './components/status-bar.js';
import { FinalSummary } from './components/final-summary.js';
import { HelpOverlay } from './components/help-overlay.js';

interface AppProps {
  bus: AttackEventBus;
  targetUrl: string;
  scanId: string;
  onQuit: () => void;
}

export function App({ bus, targetUrl, scanId, onQuit }: AppProps): React.ReactElement {
  const [state, dispatch] = useAttackState(bus, targetUrl, scanId);

  useElapsedTimer(dispatch, state.phase === 'running');

  const handleQuit = useCallback(() => {
    onQuit();
  }, [onQuit]);

  useKeyboard(dispatch, handleQuit, state.helpVisible);

  if (state.helpVisible) {
    return (
      <Box flexDirection="column">
        <Header
          targetUrl={state.targetUrl}
          currentModule={state.currentModule}
          currentPhase={state.currentPhase}
          phase={state.phase}
        />
        <HelpOverlay />
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      <Header
        targetUrl={state.targetUrl}
        currentModule={state.currentModule}
        currentPhase={state.currentPhase}
        phase={state.phase}
      />

      <ProgressBar progress={state.progress} />

      <SeveritySummary counts={state.counts} />

      <FindingsList
        findings={state.findings}
        scrollOffset={state.scrollOffset}
      />

      {state.phase === 'complete' && state.grade && state.durationMs !== null ? (
        <FinalSummary
          grade={state.grade}
          durationMs={state.durationMs}
          counts={state.counts}
        />
      ) : (
        <StatusBar
          requestCount={state.requestCount}
          elapsedMs={state.elapsedMs}
        />
      )}
    </Box>
  );
}
