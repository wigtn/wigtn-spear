/**
 * Scrollable findings list component.
 */

import React from 'react';
import { Box, Text } from 'ink';
import type { TUIFinding } from '../types.js';

interface FindingsListProps {
  findings: TUIFinding[];
  scrollOffset: number;
  pageSize?: number;
}

const DEFAULT_PAGE_SIZE = 10;

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'red',
  high: 'magenta',
  medium: 'yellow',
  low: 'blue',
  info: 'gray',
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH    ',
  medium: 'MEDIUM  ',
  low: 'LOW     ',
  info: 'INFO    ',
};

export function FindingsList({ findings, scrollOffset, pageSize = DEFAULT_PAGE_SIZE }: FindingsListProps): React.ReactElement {
  if (findings.length === 0) {
    return (
      <Box paddingX={1} flexDirection="column">
        <Text color="gray">No findings yet...</Text>
      </Box>
    );
  }

  const visible = findings.slice(scrollOffset, scrollOffset + pageSize);
  const showing = `${scrollOffset + 1}-${Math.min(scrollOffset + pageSize, findings.length)}/${findings.length}`;

  return (
    <Box flexDirection="column" paddingX={1}>
      <Text bold>
        Findings: <Text color="gray">[{showing}]</Text>
      </Text>
      {visible.map((f, i) => {
        const color = SEVERITY_COLORS[f.severity] ?? 'white';
        const label = SEVERITY_LABELS[f.severity] ?? f.severity.toUpperCase();
        return (
          <Text key={scrollOffset + i}>
            {'  ['}
            <Text color={color} bold>{label}</Text>
            {']  '}
            <Text color="cyan">{f.ruleId.padEnd(22)}</Text>
            {'  '}
            <Text>{f.message.slice(0, 60)}</Text>
          </Text>
        );
      })}
      {findings.length > pageSize && (
        <Text color="gray">                                           (scroll with arrow keys)</Text>
      )}
    </Box>
  );
}
