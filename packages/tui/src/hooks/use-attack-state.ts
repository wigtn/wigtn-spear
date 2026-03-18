/**
 * Central state management hook for the attack TUI.
 * Uses useReducer for predictable state updates.
 */

import { useReducer, useEffect, useCallback } from 'react';
import type { AttackState, AttackAction, TUIFinding } from '../types.js';
import type { AttackEventBus } from '../event-bus.js';

const FINDINGS_PAGE_SIZE = 10;

function createInitialState(targetUrl: string, scanId: string): AttackState {
  return {
    phase: 'initializing',
    targetUrl,
    scanId,
    currentModule: '',
    currentPhase: '',
    findings: [],
    counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    requestCount: 0,
    elapsedMs: 0,
    progress: null,
    grade: null,
    durationMs: null,
    helpVisible: false,
    scrollOffset: 0,
  };
}

function attackReducer(state: AttackState, action: AttackAction): AttackState {
  switch (action.type) {
    case 'finding': {
      const f = action.finding;
      const counts = { ...state.counts };
      counts[f.severity]++;
      return {
        ...state,
        phase: 'running',
        findings: [...state.findings, f],
        counts,
      };
    }
    case 'module-change':
      return {
        ...state,
        phase: 'running',
        currentModule: action.module,
        currentPhase: action.phase,
      };
    case 'progress':
      return {
        ...state,
        progress: { current: action.current, total: action.total },
      };
    case 'request-count':
      return { ...state, requestCount: action.count };
    case 'tick':
      return { ...state, elapsedMs: action.elapsedMs };
    case 'scan-complete':
      return {
        ...state,
        phase: 'complete',
        durationMs: action.durationMs,
        grade: action.grade,
        counts: action.counts,
      };
    case 'scroll': {
      const maxOffset = Math.max(0, state.findings.length - FINDINGS_PAGE_SIZE);
      let next = state.scrollOffset;
      switch (action.direction) {
        case 'up':
          next = Math.max(0, next - 1);
          break;
        case 'down':
          next = Math.min(maxOffset, next + 1);
          break;
        case 'page-up':
          next = Math.max(0, next - FINDINGS_PAGE_SIZE);
          break;
        case 'page-down':
          next = Math.min(maxOffset, next + FINDINGS_PAGE_SIZE);
          break;
        case 'top':
          next = 0;
          break;
        case 'bottom':
          next = maxOffset;
          break;
      }
      return { ...state, scrollOffset: next };
    }
    case 'toggle-help':
      return { ...state, helpVisible: !state.helpVisible };
    case 'close-help':
      return { ...state, helpVisible: false };
    default:
      return state;
  }
}

export function useAttackState(
  bus: AttackEventBus,
  targetUrl: string,
  scanId: string,
): [AttackState, React.Dispatch<AttackAction>] {
  const [state, dispatch] = useReducer(
    attackReducer,
    createInitialState(targetUrl, scanId),
  );

  const onFinding = useCallback((finding: TUIFinding) => {
    dispatch({ type: 'finding', finding });
  }, []);

  const onModuleChange = useCallback((data: { module: string; phase: string }) => {
    dispatch({ type: 'module-change', module: data.module, phase: data.phase });
  }, []);

  const onProgress = useCallback((data: { current: number; total: number }) => {
    dispatch({ type: 'progress', current: data.current, total: data.total });
  }, []);

  const onRequestCount = useCallback((count: number) => {
    dispatch({ type: 'request-count', count });
  }, []);

  const onComplete = useCallback((data: { durationMs: number; grade: string; counts: import('../types.js').SeverityCounts }) => {
    dispatch({ type: 'scan-complete', durationMs: data.durationMs, grade: data.grade, counts: data.counts });
  }, []);

  useEffect(() => {
    bus.on('finding', onFinding);
    bus.on('module-change', onModuleChange);
    bus.on('progress', onProgress);
    bus.on('request-count', onRequestCount);
    bus.on('scan-complete', onComplete);

    return () => {
      bus.off('finding', onFinding);
      bus.off('module-change', onModuleChange);
      bus.off('progress', onProgress);
      bus.off('request-count', onRequestCount);
      bus.off('scan-complete', onComplete);
    };
  }, [bus, onFinding, onModuleChange, onProgress, onRequestCount, onComplete]);

  return [state, dispatch];
}
