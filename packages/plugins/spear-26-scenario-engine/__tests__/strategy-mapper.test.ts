import { describe, it, expect } from 'vitest';
import { recommendStrategies, mapStrategyToPayloads } from '../src/strategy-mapper.js';
import { getScenario } from '../src/scenarios.js';

describe('recommendStrategies', () => {
  it('should return authority-spoof as top strategy for emergency-triage', () => {
    const scenario = getScenario('emergency-triage')!;
    const recommendations = recommendStrategies(scenario);
    expect(recommendations.length).toBeGreaterThan(0);
    // emergency-triage has document + audio channels; authority-spoof scores high on both
    expect(recommendations[0]!.strategy).toBe('authority-spoof');
  });

  it('should return social-engineering as top for soc-cybersecurity', () => {
    const scenario = getScenario('soc-cybersecurity')!;
    const recommendations = recommendStrategies(scenario);
    expect(recommendations.length).toBeGreaterThan(0);
    // soc-cybersecurity has text + audio channels, suppression track
    expect(recommendations[0]!.strategy).toBe('social-engineering');
  });
});

describe('mapStrategyToPayloads', () => {
  it('should return io-* and mis-* payloads for prompt-injection', () => {
    const payloads = mapStrategyToPayloads('prompt-injection', 'emergency_triage');
    expect(payloads.length).toBeGreaterThan(0);
    const hasIO = payloads.some((p) => p.startsWith('io-'));
    const hasMis = payloads.some((p) => p.startsWith('mis-'));
    expect(hasIO).toBe(true);
    expect(hasMis).toBe(true);
  });

  it('should return rh-* and io-* payloads for authority-spoof', () => {
    const payloads = mapStrategyToPayloads('authority-spoof', 'emergency_triage');
    expect(payloads.length).toBeGreaterThan(0);
    const hasRH = payloads.some((p) => p.startsWith('rh-'));
    const hasIO = payloads.some((p) => p.startsWith('io-'));
    expect(hasRH).toBe(true);
    expect(hasIO).toBe(true);
  });

  it('should return non-empty payload arrays for all strategies', () => {
    const strategies = [
      'prompt-injection',
      'authority-spoof',
      'crescendo',
      'tap',
      'economic-pressure',
      'social-engineering',
    ] as const;

    for (const strategy of strategies) {
      const payloads = mapStrategyToPayloads(strategy, 'emergency_triage');
      expect(payloads.length).toBeGreaterThan(0);
    }
  });
});
