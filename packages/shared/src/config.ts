import { readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import type { SpearConfig } from './types/index.js';
import { DEFAULT_CONFIG } from './types/index.js';

const CONFIG_FILENAMES = ['.spearrc.yaml', '.spearrc.yml', '.spearrc.json'];
const GLOBAL_CONFIG_DIR = join(homedir(), '.config', 'wigtn-spear');

export function loadConfig(cwd: string, overrides: Partial<SpearConfig> = {}): SpearConfig {
  let fileConfig: Partial<SpearConfig> = {};

  // Search for config file in cwd
  for (const filename of CONFIG_FILENAMES) {
    const filepath = resolve(cwd, filename);
    if (existsSync(filepath)) {
      const raw = readFileSync(filepath, 'utf-8');
      if (filename.endsWith('.json')) {
        fileConfig = JSON.parse(raw) as Partial<SpearConfig>;
      }
      // YAML parsing will be added when rules-engine is ready
      break;
    }
  }

  return {
    ...DEFAULT_CONFIG,
    ...fileConfig,
    ...overrides,
  };
}

export function getGlobalConfigDir(): string {
  return GLOBAL_CONFIG_DIR;
}

export function getDbPath(cwd: string, config: SpearConfig): string {
  return resolve(cwd, config.dbPath);
}
