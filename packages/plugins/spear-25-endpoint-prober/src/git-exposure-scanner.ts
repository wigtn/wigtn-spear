/**
 * SPEAR-25: Git Exposure Scanner
 *
 * Checks for exposed .git directory on the target server.
 * An exposed .git directory allows full source code recovery,
 * commit history extraction, and credential harvesting.
 *
 * Checks 8 critical git paths and validates response content
 * to confirm genuine git exposure (not catch-all pages).
 *
 * @module git-exposure-scanner
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface GitExposureConfig {
  baseUrl: string;
  timeout?: number;
  logger?: SpearLogger;
}

export interface GitExposureResult {
  /** Whether .git directory is exposed */
  exposed: boolean;
  /** Individual path check results */
  paths: GitPathResult[];
  /** Extracted information from git config */
  gitConfig?: {
    remoteUrl?: string;
    userName?: string;
    userEmail?: string;
    branches?: string[];
  };
  /** Evidence summary */
  evidence: string;
}

export interface GitPathResult {
  path: string;
  accessible: boolean;
  status: number;
  contentValid: boolean;
  /** Brief description of what was found */
  description: string;
}

// ─── Git Paths to Check ──────────────────────────────────────

interface GitPathCheck {
  path: string;
  description: string;
  /** Validator to confirm the response is genuine git content */
  validate: (body: string, status: number) => boolean;
}

const GIT_PATHS: GitPathCheck[] = [
  {
    path: '/.git/HEAD',
    description: 'Git HEAD reference — confirms .git directory exists',
    validate: (body, status) =>
      status === 200 && /^ref: refs\/heads\/\w/.test(body.trim()),
  },
  {
    path: '/.git/config',
    description: 'Git config — may contain remote URLs and credentials',
    validate: (body, status) =>
      status === 200 && body.includes('[core]'),
  },
  {
    path: '/.git/logs/HEAD',
    description: 'Git reflog — reveals commit history and developer emails',
    validate: (body, status) =>
      status === 200 && /[0-9a-f]{40}/.test(body),
  },
  {
    path: '/.git/refs/heads/main',
    description: 'Main branch reference — reveals latest commit hash',
    validate: (body, status) =>
      status === 200 && /^[0-9a-f]{40}\s*$/.test(body.trim()),
  },
  {
    path: '/.git/refs/heads/master',
    description: 'Master branch reference — reveals latest commit hash',
    validate: (body, status) =>
      status === 200 && /^[0-9a-f]{40}\s*$/.test(body.trim()),
  },
  {
    path: '/.git/COMMIT_EDITMSG',
    description: 'Last commit message — reveals development context',
    validate: (body, status) =>
      status === 200 && body.trim().length > 0 && body.trim().length < 10000,
  },
  {
    path: '/.git/description',
    description: 'Repository description',
    validate: (body, status) =>
      status === 200 && body.trim().length > 0,
  },
  {
    path: '/.gitignore',
    description: 'Gitignore — reveals project structure and sensitive file patterns',
    validate: (body, status) =>
      status === 200 && (
        body.includes('node_modules') ||
        body.includes('.env') ||
        body.includes('__pycache__') ||
        body.includes('*.log') ||
        body.includes('dist/') ||
        body.includes('build/') ||
        body.includes('#')
      ),
  },
];

// ─── Scanner ──────────────────────────────────────────────────

/**
 * Scan for exposed .git directory on the target server.
 *
 * Checks 8 git-related paths in parallel and validates
 * response content to confirm genuine git exposure.
 */
export async function scanGitExposure(
  config: GitExposureConfig,
): Promise<GitExposureResult> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? 5000;

  config.logger?.info('git-exposure: scanning', { baseUrl });

  // Check all paths in parallel
  const pathResults = await Promise.all(
    GIT_PATHS.map((check) => checkGitPath(baseUrl, check, timeout)),
  );

  // Determine if truly exposed
  const validPaths = pathResults.filter((r) => r.contentValid);
  const exposed = validPaths.length >= 2; // Need at least 2 confirmed paths

  // Extract git config info if available
  let gitConfig: GitExposureResult['gitConfig'];
  const configResult = pathResults.find((r) => r.path === '/.git/config' && r.contentValid);
  if (configResult) {
    gitConfig = parseGitConfig(configResult.description);
  }

  // Build evidence
  let evidence: string;
  if (exposed) {
    const confirmedPaths = validPaths.map((r) => r.path).join(', ');
    evidence = `.git directory EXPOSED with ${validPaths.length} confirmed paths: ${confirmedPaths}`;

    if (gitConfig?.remoteUrl) {
      evidence += ` — Remote: ${gitConfig.remoteUrl}`;
    }
  } else if (validPaths.length === 1) {
    evidence = `Partial git exposure: ${validPaths[0]!.path} accessible but insufficient for confirmation`;
  } else {
    evidence = 'No git directory exposure detected';
  }

  config.logger?.info('git-exposure: complete', {
    exposed,
    confirmedPaths: validPaths.length,
    totalChecked: GIT_PATHS.length,
  });

  return {
    exposed,
    paths: pathResults,
    gitConfig,
    evidence,
  };
}

// ─── Path Checker ─────────────────────────────────────────────

async function checkGitPath(
  baseUrl: string,
  check: GitPathCheck,
  timeout: number,
): Promise<GitPathResult> {
  const url = baseUrl + check.path;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
        Accept: '*/*',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    const body = await response.text();
    const contentValid = check.validate(body, response.status);

    return {
      path: check.path,
      accessible: response.status === 200,
      status: response.status,
      contentValid,
      description: contentValid ? body.slice(0, 500) : check.description,
    };
  } catch {
    return {
      path: check.path,
      accessible: false,
      status: 0,
      contentValid: false,
      description: 'Network error or timeout',
    };
  } finally {
    clearTimeout(timer);
  }
}

// ─── Git Config Parser ────────────────────────────────────────

function parseGitConfig(configBody: string): GitExposureResult['gitConfig'] {
  const result: NonNullable<GitExposureResult['gitConfig']> = {};

  // Extract remote URL
  const remoteMatch = configBody.match(/url\s*=\s*(.+)/);
  if (remoteMatch) {
    result.remoteUrl = remoteMatch[1]!.trim();
  }

  // Extract user name
  const nameMatch = configBody.match(/name\s*=\s*(.+)/);
  if (nameMatch) {
    result.userName = nameMatch[1]!.trim();
  }

  // Extract user email
  const emailMatch = configBody.match(/email\s*=\s*(.+)/);
  if (emailMatch) {
    result.userEmail = emailMatch[1]!.trim();
  }

  return result;
}
