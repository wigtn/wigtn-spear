/**
 * Help overlay shown when ? is pressed.
 */

import React from 'react';
import { Box, Text } from 'ink';

export function HelpOverlay(): React.ReactElement {
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor="cyan"
      paddingX={2}
      paddingY={1}
    >
      <Text bold color="cyan">Keyboard Shortcuts</Text>
      <Text />
      <Text>  <Text bold>q</Text>         Quit (abort scan)</Text>
      <Text>  <Text bold>Up/Down</Text>   Scroll findings</Text>
      <Text>  <Text bold>PgUp/PgDn</Text> Page scroll</Text>
      <Text>  <Text bold>g</Text>         Jump to top</Text>
      <Text>  <Text bold>G</Text>         Jump to bottom</Text>
      <Text>  <Text bold>?</Text>         Toggle this help</Text>
      <Text>  <Text bold>Esc</Text>       Close this help</Text>
      <Text />
      <Text color="gray">Press Esc or ? to close</Text>
    </Box>
  );
}
