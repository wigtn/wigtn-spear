/**
 * SPEAR-26: Submission Formatter
 *
 * Formats attacks into the competition submission JSON format
 * and validates submissions before sending.
 */

import type {
  ArenaAttack,
  ArenaScenario,
  ArenaSubmission,
  ArenaChannel,
  ArenaTrack,
  ArenaConfidence,
} from '@wigtn/shared';

/**
 * Format an attack and scenario into a competition submission.
 */
export function formatSubmission(
  attack: ArenaAttack,
  scenario: ArenaScenario,
): ArenaSubmission {
  return {
    scenario_id: scenario.id,
    track: scenario.track,
    selected_action_id: scenario.targetAction,
    reasoning: attack.reasoning,
    confidence: attack.confidence,
    attack_method: 'programmatic',
    method_detail: `WIGTN-SPEAR spear-26-scenario-engine | strategy: ${attack.strategy} | modules: ${attack.sourceModules.join(', ')}`,
    channel: attack.channel,
    payload: attack.payload,
    timestamp: new Date().toISOString(),
  };
}

// ─── Validation ────────────────────────────────────────────

const VALID_TRACKS: ArenaTrack[] = ['action_induction', 'action_suppression'];
const VALID_CHANNELS: ArenaChannel[] = ['text', 'document', 'audio', 'image', 'video', 'email'];
const VALID_CONFIDENCES: ArenaConfidence[] = ['LOW', 'MEDIUM', 'HIGH'];
const VALID_METHODS: string[] = ['manual', 'programmatic', 'hybrid'];

/**
 * Validate a submission before sending to the arena.
 */
export function validateSubmission(
  submission: ArenaSubmission,
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // Required fields
  if (!submission.scenario_id || typeof submission.scenario_id !== 'string') {
    errors.push('scenario_id is required and must be a string');
  }

  if (!VALID_TRACKS.includes(submission.track)) {
    errors.push(`track must be one of: ${VALID_TRACKS.join(', ')}`);
  }

  if (!submission.selected_action_id || typeof submission.selected_action_id !== 'string') {
    errors.push('selected_action_id is required and must be a string');
  }

  if (!submission.reasoning || typeof submission.reasoning !== 'string') {
    errors.push('reasoning is required and must be a string');
  }

  if (!VALID_CONFIDENCES.includes(submission.confidence)) {
    errors.push(`confidence must be one of: ${VALID_CONFIDENCES.join(', ')}`);
  }

  if (!VALID_METHODS.includes(submission.attack_method)) {
    errors.push(`attack_method must be one of: ${VALID_METHODS.join(', ')}`);
  }

  if (!submission.method_detail || typeof submission.method_detail !== 'string') {
    errors.push('method_detail is required and must be a string');
  }

  if (!VALID_CHANNELS.includes(submission.channel)) {
    errors.push(`channel must be one of: ${VALID_CHANNELS.join(', ')}`);
  }

  if (!submission.payload || typeof submission.payload !== 'string') {
    errors.push('payload is required and must be a non-empty string');
  }

  if (!submission.timestamp || typeof submission.timestamp !== 'string') {
    errors.push('timestamp is required and must be an ISO 8601 string');
  } else {
    const parsed = Date.parse(submission.timestamp);
    if (isNaN(parsed)) {
      errors.push('timestamp must be a valid ISO 8601 date string');
    }
  }

  // Payload size check (arena may have limits)
  if (submission.payload && submission.payload.length > 50_000) {
    errors.push(`payload exceeds 50,000 character limit (current: ${submission.payload.length})`);
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
