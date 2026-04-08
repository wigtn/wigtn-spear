import { describe, it, expect } from 'vitest';
import { SCENARIOS, getScenario, getActiveScenarios } from '../src/scenarios.js';

describe('SCENARIOS', () => {
  it('should have 8 entries', () => {
    expect(SCENARIOS).toHaveLength(8);
  });

  it('all scenarios should have 6 target models', () => {
    for (const scenario of SCENARIOS) {
      expect(scenario.targetModels).toHaveLength(6);
    }
  });
});

describe('getScenario', () => {
  it('should return the emergency-triage scenario with correct fields', () => {
    const scenario = getScenario('emergency-triage');
    expect(scenario).toBeDefined();
    expect(scenario!.track).toBe('action_induction');
    expect(scenario!.wave).toBe(1);
    expect(scenario!.active).toBe(true);
  });

  it('should return undefined for a nonexistent scenario', () => {
    const scenario = getScenario('nonexistent');
    expect(scenario).toBeUndefined();
  });
});

describe('getActiveScenarios', () => {
  it('should return exactly 4 scenarios (Wave 1 only)', () => {
    const active = getActiveScenarios();
    expect(active).toHaveLength(4);
    for (const s of active) {
      expect(s.active).toBe(true);
      expect(s.wave).toBe(1);
    }
  });

  it('all active scenarios should have at least 1 available channel', () => {
    const active = getActiveScenarios();
    for (const s of active) {
      expect(s.availableChannels.length).toBeGreaterThanOrEqual(1);
    }
  });
});
