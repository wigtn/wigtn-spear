/**
 * SPEAR-27: Template Engine
 *
 * Simple mustache-style template renderer and utility helpers
 * for generating authority impersonation documents.
 */

/**
 * Replace all `{{variable_name}}` placeholders in a template string
 * with values from the provided variables map. Unresolved placeholders
 * are left as-is so callers can detect missing values.
 */
export function renderTemplate(
  template: string,
  variables: Record<string, string>,
): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_match, key: string) => {
    return variables[key] ?? `{{${key}}}`;
  });
}

/**
 * Pick a random element from an array.
 * Uses Math.random -- not cryptographically secure, but sufficient
 * for generating varied document content.
 */
export function randomFrom<T>(arr: readonly T[], rng: () => number = Math.random): T {
  if (arr.length === 0) {
    throw new Error('randomFrom: cannot pick from empty array');
  }
  return arr[Math.floor(rng() * arr.length)]!;
}

/**
 * Generate a random integer between min (inclusive) and max (inclusive).
 */
export function randomInt(min: number, max: number, rng: () => number = Math.random): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

/**
 * Generate a random alphanumeric string of the given length.
 */
export function randomAlphanumeric(length: number, rng: () => number = Math.random): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(rng() * chars.length)];
  }
  return result;
}

/**
 * Format a date as MM/DD/YYYY.
 */
export function formatDate(date: Date): string {
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const dd = String(date.getDate()).padStart(2, '0');
  const yyyy = date.getFullYear();
  return `${mm}/${dd}/${yyyy}`;
}

/**
 * Format a date as YYYY-MM-DD (ISO-style, no time).
 */
export function formatDateISO(date: Date): string {
  return date.toISOString().slice(0, 10);
}
