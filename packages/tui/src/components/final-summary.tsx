/**
 * Final summary shown when the scan is complete.
 */

import React from 'react';
import { Box, Text } from 'ink';
import type { SeverityCounts } from '../types.js';

interface FinalSummaryProps {
  grade: string;
  durationMs: number;
  counts: SeverityCounts;
}

function formatDuration(ms: number): string {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes > 0) {
    return `${minutes}m ${seconds}s`;
  }
  return `${seconds}s`;
}

const GRADE_COLORS: Record<string, string> = {
  'A+': 'green',
  A: 'green',
  'A-': 'green',
  'B+': 'yellow',
  B: 'yellow',
  'B-': 'yellow',
  'C+': 'red',
  C: 'red',
  'C-': 'red',
  D: 'red',
  F: 'red',
};

export function FinalSummary({ grade, durationMs, counts }: FinalSummaryProps): React.ReactElement {
  const total = counts.critical + counts.high + counts.medium + counts.low + counts.info;
  const gradeColor = GRADE_COLORS[grade] ?? 'white';

  return (
    <Box flexDirection="column" borderStyle="double" borderColor="green" paddingX={1} marginTop={1}>
      <Text bold color="green">
        Scan Complete
      </Text>
      <Text>
        Grade: <Text color={gradeColor} bold>{grade}</Text>
        {'  |  Duration: '}
        <Text bold>{formatDuration(durationMs)}</Text>
        {'  |  Total Findings: '}
        <Text bold>{total}</Text>
      </Text>
      <Text>
        <Text color="red">Critical: {counts.critical}</Text>
        {'  '}
        <Text color="magenta">High: {counts.high}</Text>
        {'  '}
        <Text color="yellow">Medium: {counts.medium}</Text>
        {'  '}
        <Text color="blue">Low: {counts.low}</Text>
        {'  '}
        <Text color="gray">Info: {counts.info}</Text>
      </Text>
    </Box>
  );
}
