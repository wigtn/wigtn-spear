/**
 * Shared payload types for the Prompt Injection Fuzzer.
 *
 * These types define the structure of injection payloads used for
 * static detection -- the scanner matches these patterns against
 * source code to identify prompt injection vulnerabilities.
 */

import type { Severity } from '@wigtn/shared';

// ─── Payload Category ────────────────────────────────────────

/**
 * Classification of prompt injection payload types.
 *
 * - direct_injection: Attacker directly controls the prompt input
 * - indirect_injection: Injection via data the LLM processes (docs, web pages)
 * - jailbreak: Bypasses safety guardrails / system prompt constraints
 * - data_exfil: Extracts sensitive data from the LLM context
 * - code_exec: Tricks LLM into generating executable code
 * - prompt_leak: Extracts the system prompt or hidden instructions
 * - context_manipulation: Alters the LLM's understanding of its role
 * - privilege_escalation: Gains elevated capabilities within the LLM system
 */
export type PayloadCategory =
  | 'direct_injection'
  | 'indirect_injection'
  | 'jailbreak'
  | 'data_exfil'
  | 'code_exec'
  | 'prompt_leak'
  | 'context_manipulation'
  | 'privilege_escalation';

// ─── Kill Chain Stage ────────────────────────────────────────

/**
 * Promptware Kill Chain stages (7-stage model).
 *
 * Based on research into LLM-specific attack lifecycles:
 *
 * 1. delivery           - Payload reaches the LLM input
 * 2. execution          - LLM processes the injected instruction
 * 3. persistence        - Payload survives across conversation turns
 * 4. propagation        - Infection spreads to other LLM sessions/agents
 * 5. data_exfiltration  - Sensitive data is extracted from the system
 * 6. evasion            - Payload avoids detection by guardrails
 * 7. destruction        - System integrity or availability is compromised
 */
export type KillChainStage =
  | 'delivery'
  | 'execution'
  | 'persistence'
  | 'propagation'
  | 'data_exfiltration'
  | 'evasion'
  | 'destruction';

// ─── Payload Entry ───────────────────────────────────────────

/**
 * A single prompt injection payload entry.
 *
 * Used for both HouYi-generated and AIShellJack database payloads.
 * The `payload` field contains the detection pattern (keyword/regex)
 * that is matched against source code -- payloads are never executed.
 */
export interface PayloadEntry {
  /** Unique identifier for this payload (e.g., 'houyi-001', 'asj-042') */
  id: string;

  /** Classification category */
  category: PayloadCategory;

  /** The detection pattern to match against source code */
  payload: string;

  /** Human-readable description of what this payload does */
  description: string;

  /** Expected behavior if this payload were processed by an LLM */
  expectedBehavior: string;

  /** MITRE ATT&CK or ATLAS technique ID */
  mitreTechnique: string;

  /** Which kill chain stage this payload targets */
  killChainStage?: KillChainStage;

  /** Severity level of a finding matching this payload */
  severity: Severity;
}

// ─── HouYi Component Types ───────────────────────────────────

/** Framework stage: Sets a context for the injection */
export interface HouYiFramework {
  id: string;
  template: string;
  description: string;
}

/** Separator stage: Breaks out of the current prompt context */
export interface HouYiSeparator {
  id: string;
  template: string;
  description: string;
}

/** Disruptor stage: The actual malicious instruction */
export interface HouYiDisruptor {
  id: string;
  template: string;
  description: string;
  category: PayloadCategory;
  killChainStage: KillChainStage;
  mitreTechnique: string;
  severity: Severity;
}
