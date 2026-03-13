/**
 * Promptware Kill Chain Tracker
 *
 * Tracks which stages of the Promptware Kill Chain are covered by
 * detected findings. The 7-stage model describes the lifecycle of
 * an LLM-targeting attack:
 *
 *   1. Delivery           - Payload reaches the LLM input
 *   2. Execution          - LLM processes the injected instruction
 *   3. Persistence        - Payload survives across sessions/turns
 *   4. Propagation        - Infection spreads to other agents/sessions
 *   5. Data Exfiltration  - Sensitive data is extracted
 *   6. Evasion            - Payload avoids detection
 *   7. Destruction        - System integrity or availability is lost
 *
 * The tracker accumulates findings and provides coverage analysis
 * to help security teams understand their exposure across the full
 * attack lifecycle.
 */

import type { Finding } from '@wigtn/shared';
import type { KillChainStage, PayloadCategory } from './payloads/types.js';

// ─── Kill Chain Stage Definitions ────────────────────────────

/** Ordered list of all kill chain stages (attack lifecycle order). */
export const KILL_CHAIN_STAGES: readonly KillChainStage[] = [
  'delivery',
  'execution',
  'persistence',
  'propagation',
  'data_exfiltration',
  'evasion',
  'destruction',
] as const;

/** Human-readable names for each stage. */
export const KILL_CHAIN_STAGE_NAMES: Record<KillChainStage, string> = {
  delivery: 'Delivery',
  execution: 'Execution',
  persistence: 'Persistence',
  propagation: 'Propagation',
  data_exfiltration: 'Data Exfiltration',
  evasion: 'Evasion',
  destruction: 'Destruction',
};

/** Descriptions for each stage explaining the attack behavior. */
export const KILL_CHAIN_STAGE_DESCRIPTIONS: Record<KillChainStage, string> = {
  delivery:
    'Prompt injection payload is delivered to the LLM via user input, ' +
    'file content, web scraping, or tool output.',
  execution:
    'The LLM processes the injected instruction as if it were a legitimate ' +
    'part of the conversation or system prompt.',
  persistence:
    'The injected behavior persists across multiple conversation turns, ' +
    'sessions, or is stored in memory/context windows.',
  propagation:
    'The compromised LLM spreads the injection to other agents, tools, ' +
    'or downstream systems in a multi-agent pipeline.',
  data_exfiltration:
    'Sensitive data from the system prompt, user data, or connected tools ' +
    'is extracted and sent to an attacker-controlled endpoint.',
  evasion:
    'The payload uses encoding, obfuscation, or social engineering to ' +
    'bypass content filters and safety guardrails.',
  destruction:
    'The attack causes data loss, system corruption, denial of service, ' +
    'or other destructive outcomes.',
};

// ─── Category -> Kill Chain Stage Mapping ────────────────────

/**
 * Default mapping from payload category to primary kill chain stage.
 *
 * Each category has a primary stage it most closely relates to.
 * Individual payloads can override this via their killChainStage field.
 */
export function defaultStageForCategory(category: PayloadCategory): KillChainStage {
  switch (category) {
    case 'direct_injection':
      return 'delivery';
    case 'indirect_injection':
      return 'delivery';
    case 'jailbreak':
      return 'execution';
    case 'data_exfil':
      return 'data_exfiltration';
    case 'code_exec':
      return 'execution';
    case 'prompt_leak':
      return 'data_exfiltration';
    case 'context_manipulation':
      return 'persistence';
    case 'privilege_escalation':
      return 'execution';
    default: {
      const _exhaustive: never = category;
      return 'delivery';
    }
  }
}

// ─── Kill Chain Finding Record ───────────────────────────────

/** A finding annotated with its kill chain stage. */
export interface KillChainFinding {
  finding: Finding;
  stage: KillChainStage;
  category: PayloadCategory;
}

// ─── Kill Chain Coverage Report ──────────────────────────────

/** Per-stage coverage details. */
export interface StageCoverage {
  stage: KillChainStage;
  name: string;
  description: string;
  findingsCount: number;
  covered: boolean;
}

/** Overall kill chain coverage summary. */
export interface KillChainCoverage {
  /** Total stages in the kill chain (always 7). */
  totalStages: number;

  /** Number of stages that have at least one finding. */
  coveredStages: number;

  /** Coverage percentage (0-100). */
  coveragePercent: number;

  /** Per-stage breakdown. */
  stages: StageCoverage[];

  /** Total findings tracked across all stages. */
  totalFindings: number;

  /** Uncovered stages that represent gaps in detection. */
  gaps: KillChainStage[];
}

// ─── Kill Chain Tracker ──────────────────────────────────────

/**
 * Tracks prompt injection findings across the Promptware Kill Chain.
 *
 * Usage:
 *   const tracker = new KillChainTracker();
 *   tracker.addFinding(finding, 'delivery', 'direct_injection');
 *   const coverage = tracker.getCoverage();
 */
export class KillChainTracker {
  /** Findings stored per kill chain stage. */
  private stageFindings: Map<KillChainStage, KillChainFinding[]> = new Map();

  constructor() {
    // Initialize all stages with empty arrays
    for (const stage of KILL_CHAIN_STAGES) {
      this.stageFindings.set(stage, []);
    }
  }

  /**
   * Add a finding to the kill chain tracker.
   *
   * @param finding - The Finding object from the scan.
   * @param stage - The kill chain stage this finding maps to.
   * @param category - The payload category of the matched pattern.
   */
  addFinding(
    finding: Finding,
    stage: KillChainStage,
    category: PayloadCategory,
  ): void {
    const stageList = this.stageFindings.get(stage);
    if (stageList) {
      stageList.push({ finding, stage, category });
    }
  }

  /**
   * Get the total number of tracked findings.
   */
  get totalFindings(): number {
    let count = 0;
    for (const findings of this.stageFindings.values()) {
      count += findings.length;
    }
    return count;
  }

  /**
   * Get findings for a specific stage.
   */
  getFindingsForStage(stage: KillChainStage): readonly KillChainFinding[] {
    return this.stageFindings.get(stage) ?? [];
  }

  /**
   * Calculate kill chain coverage across all stages.
   *
   * @returns A KillChainCoverage report with per-stage details and gap analysis.
   */
  getCoverage(): KillChainCoverage {
    const stages: StageCoverage[] = [];
    const gaps: KillChainStage[] = [];
    let coveredStages = 0;
    let totalFindings = 0;

    for (const stage of KILL_CHAIN_STAGES) {
      const findings = this.stageFindings.get(stage) ?? [];
      const covered = findings.length > 0;

      if (covered) {
        coveredStages++;
      } else {
        gaps.push(stage);
      }

      totalFindings += findings.length;

      stages.push({
        stage,
        name: KILL_CHAIN_STAGE_NAMES[stage],
        description: KILL_CHAIN_STAGE_DESCRIPTIONS[stage],
        findingsCount: findings.length,
        covered,
      });
    }

    const totalStages = KILL_CHAIN_STAGES.length;
    const coveragePercent = totalStages > 0
      ? Math.round((coveredStages / totalStages) * 100)
      : 0;

    return {
      totalStages,
      coveredStages,
      coveragePercent,
      stages,
      totalFindings,
      gaps,
    };
  }

  /**
   * Reset the tracker, clearing all tracked findings.
   */
  clear(): void {
    for (const stage of KILL_CHAIN_STAGES) {
      this.stageFindings.set(stage, []);
    }
  }
}
