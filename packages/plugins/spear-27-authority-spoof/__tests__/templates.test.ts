import { describe, it, expect } from 'vitest';
import { generateMedicalReferral } from '../src/templates/medical-referral.js';
import { generateCisoCommunication } from '../src/templates/ciso-communication.js';
import { generateAviationSil } from '../src/templates/aviation-sil.js';
import { generateSupervisorOverride } from '../src/templates/supervisor-override.js';
import { renderTemplate, randomFrom } from '../src/template-engine.js';

// ─── Medical Referral ─────────────────────────────────────────

describe('generateMedicalReferral', () => {
  it('should return a non-empty string', () => {
    const result = generateMedicalReferral();
    expect(result).toBeTruthy();
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('should contain ESI-related content', () => {
    const result = generateMedicalReferral();
    expect(result).toContain('ESI');
  });

  it('should contain custom doctor name when provided', () => {
    const result = generateMedicalReferral({
      doctorFirstName: 'Test',
      doctorLastName: 'Doctor',
    });
    expect(result).toContain('Test Doctor');
  });
});

// ─── CISO Communication ──────────────────────────────────────

describe('generateCisoCommunication', () => {
  it('should return a non-empty string containing red team / authorized test language', () => {
    const result = generateCisoCommunication();
    expect(result).toBeTruthy();
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(result).toMatch(/red team|authorized/i);
  });
});

// ─── Aviation SIL ────────────────────────────────────────────

describe('generateAviationSil', () => {
  it('should return a non-empty string containing SIL / vibration language', () => {
    const result = generateAviationSil();
    expect(result).toBeTruthy();
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(result).toMatch(/SIL/);
    expect(result).toMatch(/vibration/i);
  });
});

// ─── Supervisor Override ─────────────────────────────────────

describe('generateSupervisorOverride', () => {
  it('should return a non-empty string containing sensor / production language', () => {
    const result = generateSupervisorOverride();
    expect(result).toBeTruthy();
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
    expect(result).toMatch(/sensor/i);
    expect(result).toMatch(/production/i);
  });
});

// ─── Template Engine ─────────────────────────────────────────

describe('renderTemplate', () => {
  it('should replace variables with values', () => {
    const result = renderTemplate('Hello {{name}}', { name: 'World' });
    expect(result).toBe('Hello World');
  });

  it('should leave placeholder for missing variables', () => {
    const result = renderTemplate('Hello {{name}}', {});
    expect(result).toBe('Hello {{name}}');
  });
});

describe('randomFrom', () => {
  it('should return one of the values from the array', () => {
    const arr = ['a', 'b', 'c'] as const;
    const result = randomFrom(arr);
    expect(arr).toContain(result);
  });
});
