/**
 * Hook for handling keyboard input in the TUI.
 */

import { useInput } from 'ink';
import type { AttackAction } from '../types.js';

export function useKeyboard(
  dispatch: React.Dispatch<AttackAction>,
  onQuit: () => void,
  helpVisible: boolean,
): void {
  useInput((input, key) => {
    // Help overlay: Esc closes it
    if (helpVisible) {
      if (key.escape) {
        dispatch({ type: 'close-help' });
      }
      return;
    }

    // q: quit
    if (input === 'q') {
      onQuit();
      return;
    }

    // ?: toggle help
    if (input === '?') {
      dispatch({ type: 'toggle-help' });
      return;
    }

    // Arrow keys: scroll findings
    if (key.upArrow) {
      dispatch({ type: 'scroll', direction: 'up' });
    } else if (key.downArrow) {
      dispatch({ type: 'scroll', direction: 'down' });
    } else if (key.pageUp) {
      dispatch({ type: 'scroll', direction: 'page-up' });
    } else if (key.pageDown) {
      dispatch({ type: 'scroll', direction: 'page-down' });
    }

    // g/G: top/bottom
    if (input === 'g') {
      dispatch({ type: 'scroll', direction: 'top' });
    } else if (input === 'G') {
      dispatch({ type: 'scroll', direction: 'bottom' });
    }
  });
}
