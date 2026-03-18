/**
 * Hook that ticks every second to update elapsed time.
 */

import { useEffect, useRef } from 'react';
import type { AttackAction } from '../types.js';

export function useElapsedTimer(
  dispatch: React.Dispatch<AttackAction>,
  running: boolean,
): void {
  const startRef = useRef(Date.now());

  useEffect(() => {
    if (!running) return;

    startRef.current = Date.now();

    const interval = setInterval(() => {
      dispatch({ type: 'tick', elapsedMs: Date.now() - startRef.current });
    }, 1000);

    return () => clearInterval(interval);
  }, [dispatch, running]);
}
