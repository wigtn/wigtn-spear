import { describe, it, expect } from 'vitest';
import { formatSubmission, validateSubmission } from '../src/submission-formatter.js';
import type { ArenaAttack, ArenaScenario, ArenaSubmission } from '@wigtn/shared';

// ─── Helpers ──────────────────────────────────────────────────

function makeValidAttack(): ArenaAttack {
  return {
    scenarioId: 'emergency-triage',
    channel: 'document',
    payload: 'Test adversarial payload content',
    reasoning: 'Test reasoning for the attack',
    confidence: 'HIGH',
    strategy: 'authority-spoof',
    sourceModules: ['spear-26-scenario-engine', 'spear-27-authority-spoof'],
  };
}

function makeValidScenario(): ArenaScenario {
  return {
    id: 'emergency-triage',
    track: 'action_induction',
    wave: 1,
    domain: 'emergency_triage',
    name: 'Emergency Triage Override',
    description: 'Test scenario',
    targetAction: 'override_to_esi1',
    availableChannels: ['audio', 'document'],
    targetModels: ['gpt-5.4', 'claude-opus-4.6', 'gemini-3.1-pro', 'gemini-3-flash', 'gpt-audio-1.5', 'mimo-v2-omni'],
    context: {},
    active: true,
  };
}

function makeValidSubmission(): ArenaSubmission {
  return formatSubmission(makeValidAttack(), makeValidScenario());
}

// ─── Tests ────────────────────────────────────────────────────

describe('formatSubmission', () => {
  it('should return a valid ArenaSubmission with all required fields', () => {
    const submission = makeValidSubmission();

    expect(submission.scenario_id).toBe('emergency-triage');
    expect(submission.track).toBe('action_induction');
    expect(submission.selected_action_id).toBe('override_to_esi1');
    expect(submission.reasoning).toBe('Test reasoning for the attack');
    expect(submission.confidence).toBe('HIGH');
    expect(submission.attack_method).toBe('programmatic');
    expect(submission.method_detail).toContain('WIGTN-SPEAR');
    expect(submission.channel).toBe('document');
    expect(submission.payload).toBe('Test adversarial payload content');
    expect(typeof submission.timestamp).toBe('string');
    expect(Date.parse(submission.timestamp)).not.toBeNaN();
  });
});

describe('validateSubmission', () => {
  it('should pass for a valid submission', () => {
    const result = validateSubmission(makeValidSubmission());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it('should fail for missing scenario_id', () => {
    const submission = makeValidSubmission();
    (submission as Record<string, unknown>).scenario_id = '';
    const result = validateSubmission(submission);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('scenario_id'))).toBe(true);
  });

  it('should fail for invalid track', () => {
    const submission = makeValidSubmission();
    (submission as Record<string, unknown>).track = 'invalid_track';
    const result = validateSubmission(submission);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('track'))).toBe(true);
  });

  it('should fail for invalid confidence', () => {
    const submission = makeValidSubmission();
    (submission as Record<string, unknown>).confidence = 'ULTRA';
    const result = validateSubmission(submission);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('confidence'))).toBe(true);
  });

  it('should fail for empty payload', () => {
    const submission = makeValidSubmission();
    (submission as Record<string, unknown>).payload = '';
    const result = validateSubmission(submission);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('payload'))).toBe(true);
  });

  it('should fail for payload over 50K chars', () => {
    const submission = makeValidSubmission();
    submission.payload = 'x'.repeat(50_001);
    const result = validateSubmission(submission);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.includes('50,000'))).toBe(true);
  });
});
