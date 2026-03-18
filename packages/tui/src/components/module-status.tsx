/**
 * Shows the currently active module and phase.
 */

import React from 'react';
import { Box, Text } from 'ink';

interface ModuleStatusProps {
  currentModule: string;
  currentPhase: string;
  phase: 'initializing' | 'running' | 'complete';
}

export function ModuleStatus({ currentModule, currentPhase, phase }: ModuleStatusProps): React.ReactElement | null {
  if (phase === 'initializing') {
    return (
      <Box paddingX={1}>
        <Text color="yellow">Initializing scan...</Text>
      </Box>
    );
  }

  if (!currentModule) return null;

  return (
    <Box paddingX={1}>
      <Text>
        <Text color="cyan" bold>{currentModule}</Text>
        {currentPhase ? (
          <Text color="gray">{' > '}{currentPhase}</Text>
        ) : null}
      </Text>
    </Box>
  );
}
