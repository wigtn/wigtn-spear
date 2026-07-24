import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { SpearConfigError } from './errors.js';

export const MAX_CONFIG_BYTES = 2 * 1024 * 1024;

export async function readJsonFile<T>(path: string): Promise<T> {
  const absolute = resolve(path);
  const raw = await readFile(absolute);
  if (raw.byteLength > MAX_CONFIG_BYTES) {
    throw new SpearConfigError(`JSON file exceeds ${MAX_CONFIG_BYTES} bytes: ${absolute}`);
  }
  try {
    return JSON.parse(raw.toString('utf8')) as T;
  } catch (error) {
    throw new SpearConfigError(
      `Invalid JSON in ${absolute}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await writeFile(resolve(path), `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function requireRecord(value: unknown, context: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new SpearConfigError(`${context} must be an object`);
  }
  return value;
}

export function requireString(
  record: Record<string, unknown>,
  key: string,
  context: string,
): string {
  const value = record[key];
  if (typeof value !== 'string' || value.trim() === '') {
    throw new SpearConfigError(`${context}.${key} must be a non-empty string`);
  }
  return value;
}

export function requireArray(
  record: Record<string, unknown>,
  key: string,
  context: string,
): unknown[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new SpearConfigError(`${context}.${key} must be an array`);
  }
  return value;
}

export function assertUnique(values: string[], context: string): void {
  if (new Set(values).size !== values.length) {
    throw new SpearConfigError(`${context} must not contain duplicates`);
  }
}

export function stringArray(
  record: Record<string, unknown>,
  key: string,
  context: string,
): string[] {
  const values = requireArray(record, key, context);
  if (values.some((value) => typeof value !== 'string' || value.trim() === '')) {
    throw new SpearConfigError(`${context}.${key} must contain non-empty strings`);
  }
  const result = values as string[];
  assertUnique(result, `${context}.${key}`);
  return result;
}

export function requireInteger(
  record: Record<string, unknown>,
  key: string,
  context: string,
  minimum: number,
  maximum: number,
): number {
  const value = record[key];
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new SpearConfigError(
      `${context}.${key} must be an integer from ${minimum} to ${maximum}`,
    );
  }
  return value as number;
}

export function wildcardMatches(pattern: string, value: string): boolean {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'u').test(value);
}

export function getPath(value: unknown, path: string): unknown {
  if (path.trim() === '') return value;
  return path.split('.').reduce<unknown>((current, segment) => {
    if (!isRecord(current)) return undefined;
    return current[segment];
  }, value);
}
