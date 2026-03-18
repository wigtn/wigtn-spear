/**
 * ASCII progress bar component.
 */

import React from 'react';
import { Box, Text } from 'ink';

interface ProgressBarProps {
  progress: { current: number; total: number } | null;
}

const BAR_WIDTH = 30;

export function ProgressBar({ progress }: ProgressBarProps): React.ReactElement | null {
  if (!progress || progress.total === 0) return null;

  const ratio = Math.min(1, progress.current / progress.total);
  const filled = Math.round(ratio * BAR_WIDTH);
  const empty = BAR_WIDTH - filled;
  const pct = Math.round(ratio * 100);

  return (
    <Box paddingX={1}>
      <Text>
        {'Progress: ['}
        <Text color="green">{'█'.repeat(filled)}</Text>
        <Text color="gray">{'░'.repeat(empty)}</Text>
        {']  '}
        {progress.current}/{progress.total}{'  '}({pct}%)
      </Text>
    </Box>
  );
}
