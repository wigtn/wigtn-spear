/**
 * @wigtn/tui - Type definitions for the TUI attack visualization
 */

// ─── Finding Types ────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface TUIFinding {
  ruleId: string;
  severity: Severity;
  message: string;
  metadata?: Record<string, unknown>;
}

// ─── Attack State ─────────────────────────────────────────────

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AttackState {
  /** Current phase: initializing, running, complete */
  phase: 'initializing' | 'running' | 'complete';
  /** Target URL being attacked */
  targetUrl: string;
  /** Scan identifier */
  scanId: string;
  /** Current module name */
  currentModule: string;
  /** Current sub-phase description */
  currentPhase: string;
  /** All findings collected so far */
  findings: TUIFinding[];
  /** Severity counts */
  counts: SeverityCounts;
  /** Total requests made */
  requestCount: number;
  /** Elapsed time in ms */
  elapsedMs: number;
  /** Progress: current / total (if known) */
  progress: { current: number; total: number } | null;
  /** Final grade (set on completion) */
  grade: string | null;
  /** Total duration in ms (set on completion) */
  durationMs: number | null;
  /** Whether help overlay is visible */
  helpVisible: boolean;
  /** Scroll offset in findings list */
  scrollOffset: number;
}

// ─── Actions ──────────────────────────────────────────────────

export type AttackAction =
  | { type: 'finding'; finding: TUIFinding }
  | { type: 'module-change'; module: string; phase: string }
  | { type: 'progress'; current: number; total: number }
  | { type: 'request-count'; count: number }
  | { type: 'tick'; elapsedMs: number }
  | { type: 'scan-complete'; durationMs: number; grade: string; counts: SeverityCounts }
  | { type: 'scroll'; direction: 'up' | 'down' | 'page-up' | 'page-down' | 'top' | 'bottom' }
  | { type: 'toggle-help' }
  | { type: 'close-help' };

// ─── Event Bus Types ──────────────────────────────────────────

export interface AttackEvents {
  finding: TUIFinding;
  'module-change': { module: string; phase: string };
  progress: { current: number; total: number };
  'request-count': number;
  'scan-complete': { durationMs: number; grade: string; counts: SeverityCounts };
}
