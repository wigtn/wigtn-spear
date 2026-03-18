/**
 * Status bar: request count + elapsed time + keybinding hints.
 */

import React from 'react';
import { Box, Text } from 'ink';

interface StatusBarProps {
  requestCount: number;
  elapsedMs: number;
}

function formatElapsed(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

export function StatusBar({ requestCount, elapsedMs }: StatusBarProps): React.ReactElement {
  return (
    <Box paddingX={1} gap={2}>
      <Text>
        <Text bold>{requestCount}</Text>{' requests'}
        {'  |  '}
        <Text bold>{formatElapsed(elapsedMs)}</Text>
        {'  |  '}
        <Text color="gray">q:quit  arrows:scroll  ?:help</Text>
      </Text>
    </Box>
  );
}
