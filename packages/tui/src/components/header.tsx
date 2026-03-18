/**
 * Header component: banner + target URL + mode/module/phase info.
 */

import React from 'react';
import { Box, Text } from 'ink';

interface HeaderProps {
  targetUrl: string;
  currentModule: string;
  currentPhase: string;
  phase: 'initializing' | 'running' | 'complete';
}

export function Header({ targetUrl, currentModule, currentPhase, phase }: HeaderProps): React.ReactElement {
  const modeLabel = phase === 'complete' ? 'COMPLETE' : 'AGGRESSIVE';

  return (
    <Box flexDirection="column" borderStyle="single" borderColor="red" paddingX={1}>
      <Text bold color="red">
        WIGTN-SPEAR  --  Offensive Security Testing Tool
      </Text>
      <Text>
        Target: <Text color="cyan" bold>{targetUrl}</Text>
      </Text>
      <Text>
        Mode: <Text color="yellow">{modeLabel}</Text>
        {currentModule ? (
          <>
            {'  |  Module: '}
            <Text color="green">{currentModule}</Text>
          </>
        ) : null}
        {currentPhase ? (
          <>
            {'  |  Phase: '}
            <Text color="green">{currentPhase}</Text>
          </>
        ) : null}
      </Text>
    </Box>
  );
}
