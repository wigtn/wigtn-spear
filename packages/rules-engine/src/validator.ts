/**
 * Rule validator -- checks that a parsed YAML object conforms
 * to the Rule interface defined in @wigtn/shared.
 *
 * Validation is lenient-by-design: invalid rules are logged as
 * warnings and skipped rather than aborting the entire scan
 * (PRD Scenario: Malformed Rule File).
 */

import type { Rule, Severity } from '@wigtn/shared';

const VALID_SEVERITIES: ReadonlySet<string> = new Set([
  'critical',
  'high',
  'medium',
  'low',
  'info',
]);

const VALID_CATEGORIES: ReadonlySet<string> = new Set([
  'secret',
  'vulnerability',
  'misconfiguration',
]);

export interface ValidationError {
  field: string;
  message: string;
}

export interface ValidationResult {
  rule: Rule | null;
  errors: ValidationError[];
}

/**
 * Validate a raw parsed YAML object and coerce it into a typed Rule.
 *
 * Required fields (must exist and be non-empty):
 *   - id, name, category, severity, detection.pattern
 *
 * Optional fields are normalised to sensible defaults when absent.
 *
 * @returns A ValidationResult with either a valid Rule or a list of errors.
 */
export function validateRule(raw: unknown): ValidationResult {
  const errors: ValidationError[] = [];

  if (raw === null || raw === undefined || typeof raw !== 'object') {
    return { rule: null, errors: [{ field: 'root', message: 'rule must be a non-null object' }] };
  }

  const obj = raw as Record<string, unknown>;

  // ── Required string fields ─────────────────────────────────
  const id = assertString(obj, 'id', errors);
  const name = assertString(obj, 'name', errors);
  const description = typeof obj['description'] === 'string' ? obj['description'] : '';

  // Category
  const rawCategory = typeof obj['category'] === 'string' ? obj['category'] : '';
  if (!VALID_CATEGORIES.has(rawCategory)) {
    errors.push({
      field: 'category',
      message: `must be one of: ${[...VALID_CATEGORIES].join(', ')} (got "${rawCategory}")`,
    });
  }
  const category = rawCategory as Rule['category'];

  // Severity
  const rawSeverity = typeof obj['severity'] === 'string' ? obj['severity'] : '';
  if (!VALID_SEVERITIES.has(rawSeverity)) {
    errors.push({
      field: 'severity',
      message: `must be one of: ${[...VALID_SEVERITIES].join(', ')} (got "${rawSeverity}")`,
    });
  }
  const severity = rawSeverity as Severity;

  // ── Detection block (required) ─────────────────────────────
  const detection = obj['detection'];
  let detectionBlock: Rule['detection'] | undefined;

  if (detection === null || detection === undefined || typeof detection !== 'object') {
    errors.push({ field: 'detection', message: 'detection block is required' });
  } else {
    const det = detection as Record<string, unknown>;

    const pattern = typeof det['pattern'] === 'string' ? det['pattern'] : '';
    if (!pattern) {
      errors.push({ field: 'detection.pattern', message: 'detection.pattern is required and must be a non-empty string' });
    }

    // Validate that the pattern is a valid regex
    if (pattern) {
      try {
        new RegExp(pattern);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        errors.push({ field: 'detection.pattern', message: `invalid regex: ${msg}` });
      }
    }

    const keywords = normaliseStringArray(det['keywords']);

    let entropy: Rule['detection']['entropy'];
    if (det['entropy'] && typeof det['entropy'] === 'object') {
      const ent = det['entropy'] as Record<string, unknown>;
      entropy = {
        enabled: ent['enabled'] === true,
        threshold: typeof ent['threshold'] === 'number' ? ent['threshold'] : undefined,
      };
    }

    detectionBlock = { keywords, pattern, entropy };
  }

  // ── Optional structured fields ─────────────────────────────
  const tags = normaliseStringArray(obj['tags']);
  const references = normaliseStringArray(obj['references']);
  const mitre = normaliseStringArray(obj['mitre']);

  // Verification block (optional)
  let verification: Rule['verification'];
  if (obj['verification'] && typeof obj['verification'] === 'object') {
    const ver = obj['verification'] as Record<string, unknown>;
    verification = {
      enabled: ver['enabled'] === true,
      method: typeof ver['method'] === 'string' ? ver['method'] : undefined,
    };
    if (ver['rateLimit'] && typeof ver['rateLimit'] === 'object') {
      const rl = ver['rateLimit'] as Record<string, unknown>;
      verification.rateLimit = {
        rpm: typeof rl['rpm'] === 'number' ? rl['rpm'] : 10,
        concurrent: typeof rl['concurrent'] === 'number' ? rl['concurrent'] : 1,
      };
    }
  }

  // Allowlist block (optional)
  let allowlist: Rule['allowlist'];
  if (obj['allowlist'] && typeof obj['allowlist'] === 'object') {
    const al = obj['allowlist'] as Record<string, unknown>;
    allowlist = {
      patterns: normaliseStringArray(al['patterns']),
      paths: normaliseStringArray(al['paths']),
    };
  }

  // ── Bail out if there are any validation errors ────────────
  if (errors.length > 0) {
    return { rule: null, errors };
  }

  const rule: Rule = {
    id: id!,
    name: name!,
    description,
    category,
    severity,
    tags,
    references,
    mitre: mitre.length > 0 ? mitre : undefined,
    detection: detectionBlock!,
    verification,
    allowlist,
  };

  return { rule, errors: [] };
}

// ── Helpers ────────────────────────────────────────────────────

function assertString(
  obj: Record<string, unknown>,
  field: string,
  errors: ValidationError[],
): string | undefined {
  const value = obj[field];
  if (typeof value !== 'string' || value.trim() === '') {
    errors.push({ field, message: `${field} is required and must be a non-empty string` });
    return undefined;
  }
  return value.trim();
}

function normaliseStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.filter((item): item is string => typeof item === 'string');
  }
  return [];
}
