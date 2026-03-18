/**
 * Severity counts summary: CRIT:2 HIGH:5 MED:3 LOW:1 INFO:4 Total:15
 */

import React from 'react';
import { Box, Text } from 'ink';
import type { SeverityCounts } from '../types.js';

interface SeveritySummaryProps {
  counts: SeverityCounts;
}

export function SeveritySummary({ counts }: SeveritySummaryProps): React.ReactElement {
  const total = counts.critical + counts.high + counts.medium + counts.low + counts.info;

  return (
    <Box paddingX={1} gap={2}>
      <Text>
        <Text color="red" bold>CRIT: {counts.critical}</Text>
        {'   '}
        <Text color="magenta" bold>HIGH: {counts.high}</Text>
        {'   '}
        <Text color="yellow">MED: {counts.medium}</Text>
        {'   '}
        <Text color="blue">LOW: {counts.low}</Text>
        {'   '}
        <Text color="gray">INFO: {counts.info}</Text>
        {'   '}
        <Text bold>Total: {total}</Text>
      </Text>
    </Box>
  );
}
