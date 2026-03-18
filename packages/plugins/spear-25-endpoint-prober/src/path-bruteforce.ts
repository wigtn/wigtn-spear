/**
 * SPEAR-25: Path Bruteforce Engine
 *
 * Probes ~120 common sensitive paths across 10 categories:
 *   - Admin panels, API docs, debug endpoints, git exposure
 *   - Config files, backup files, monitoring, infrastructure
 *   - CI/CD artifacts, sensitive data endpoints
 *
 * Uses baseline fingerprinting to filter catch-all route FPs.
 *
 * @module path-bruteforce
 */

import type { SpearLogger } from '@wigtn/shared';
import { matchesBaseline } from './baseline-fingerprinter.js';
import type { BaselineFingerprint } from './baseline-fingerprinter.js';

// ─── Types ────────────────────────────────────────────────────

export interface BruteforceConfig {
  baseUrl: string;
  baseline: BaselineFingerprint | null;
  timeout?: number;
  concurrency?: number;
  logger?: SpearLogger;
}

export interface BruteforceResult {
  path: string;
  fullUrl: string;
  status: number;
  contentType: string;
  bodySize: number;
  category: string;
  description: string;
  /** First 500 chars of body for evidence */
  bodyPreview: string;
  latencyMs: number;
}

// ─── Path Wordlist ────────────────────────────────────────────

interface PathEntry {
  path: string;
  category: string;
  description: string;
}

const PATH_WORDLIST: PathEntry[] = [
  // ── Admin Panels ──────────────────────────────
  { path: '/admin', category: 'admin', description: 'Admin panel' },
  { path: '/admin/', category: 'admin', description: 'Admin panel (trailing slash)' },
  { path: '/admin/login', category: 'admin', description: 'Admin login page' },
  { path: '/wp-admin', category: 'admin', description: 'WordPress admin' },
  { path: '/wp-login.php', category: 'admin', description: 'WordPress login' },
  { path: '/administrator', category: 'admin', description: 'Joomla admin' },
  { path: '/admin/dashboard', category: 'admin', description: 'Admin dashboard' },
  { path: '/_admin', category: 'admin', description: 'Hidden admin panel' },
  { path: '/panel', category: 'admin', description: 'Control panel' },
  { path: '/console', category: 'admin', description: 'Console' },
  { path: '/dashboard', category: 'admin', description: 'Dashboard' },
  { path: '/manage', category: 'admin', description: 'Management panel' },
  { path: '/backoffice', category: 'admin', description: 'Back office' },

  // ── API Documentation ─────────────────────────
  { path: '/swagger', category: 'api_docs', description: 'Swagger UI' },
  { path: '/swagger/', category: 'api_docs', description: 'Swagger UI (trailing slash)' },
  { path: '/swagger-ui.html', category: 'api_docs', description: 'Swagger UI HTML' },
  { path: '/swagger/index.html', category: 'api_docs', description: 'Swagger index' },
  { path: '/api-docs', category: 'api_docs', description: 'API documentation' },
  { path: '/api/docs', category: 'api_docs', description: 'API docs' },
  { path: '/docs', category: 'api_docs', description: 'Documentation' },
  { path: '/redoc', category: 'api_docs', description: 'ReDoc API docs' },
  { path: '/graphql', category: 'api_docs', description: 'GraphQL endpoint' },
  { path: '/graphiql', category: 'api_docs', description: 'GraphiQL IDE' },
  { path: '/playground', category: 'api_docs', description: 'API playground' },
  { path: '/openapi.json', category: 'api_docs', description: 'OpenAPI spec (JSON)' },
  { path: '/openapi.yaml', category: 'api_docs', description: 'OpenAPI spec (YAML)' },
  { path: '/v1/api-docs', category: 'api_docs', description: 'Versioned API docs' },
  { path: '/v2/api-docs', category: 'api_docs', description: 'Versioned API docs v2' },

  // ── Debug Endpoints ───────────────────────────
  { path: '/debug', category: 'debug', description: 'Debug endpoint' },
  { path: '/debug/pprof', category: 'debug', description: 'Go pprof profiler' },
  { path: '/debug/vars', category: 'debug', description: 'Go expvar' },
  { path: '/_debug', category: 'debug', description: 'Hidden debug' },
  { path: '/phpinfo.php', category: 'debug', description: 'PHP info' },
  { path: '/info.php', category: 'debug', description: 'PHP info (alt)' },
  { path: '/test', category: 'debug', description: 'Test endpoint' },
  { path: '/test.html', category: 'debug', description: 'Test page' },
  { path: '/status', category: 'debug', description: 'Status page' },
  { path: '/server-status', category: 'debug', description: 'Apache server status' },
  { path: '/server-info', category: 'debug', description: 'Apache server info' },

  // ── Health & Monitoring ───────────────────────
  { path: '/health', category: 'monitoring', description: 'Health check' },
  { path: '/healthz', category: 'monitoring', description: 'Kubernetes health' },
  { path: '/readyz', category: 'monitoring', description: 'Kubernetes readiness' },
  { path: '/livez', category: 'monitoring', description: 'Kubernetes liveness' },
  { path: '/metrics', category: 'monitoring', description: 'Prometheus metrics' },
  { path: '/actuator', category: 'monitoring', description: 'Spring Boot actuator' },
  { path: '/actuator/health', category: 'monitoring', description: 'Actuator health' },
  { path: '/actuator/env', category: 'monitoring', description: 'Actuator environment' },
  { path: '/actuator/beans', category: 'monitoring', description: 'Actuator beans' },
  { path: '/actuator/configprops', category: 'monitoring', description: 'Actuator config' },
  { path: '/actuator/mappings', category: 'monitoring', description: 'Actuator URL mappings' },
  { path: '/__health', category: 'monitoring', description: 'Hidden health check' },

  // ── Git Exposure ──────────────────────────────
  { path: '/.git/HEAD', category: 'git', description: 'Git HEAD reference' },
  { path: '/.git/config', category: 'git', description: 'Git config (may contain credentials)' },
  { path: '/.git/logs/HEAD', category: 'git', description: 'Git reflog' },
  { path: '/.git/refs/heads/main', category: 'git', description: 'Git main branch ref' },
  { path: '/.git/refs/heads/master', category: 'git', description: 'Git master branch ref' },
  { path: '/.gitignore', category: 'git', description: 'Gitignore (reveals project structure)' },
  { path: '/.svn/entries', category: 'git', description: 'SVN entries' },
  { path: '/.hg/store/00manifest.i', category: 'git', description: 'Mercurial manifest' },

  // ── Configuration Files ───────────────────────
  { path: '/.env', category: 'config', description: 'Environment variables' },
  { path: '/.env.local', category: 'config', description: 'Local env vars' },
  { path: '/.env.production', category: 'config', description: 'Production env vars' },
  { path: '/.env.development', category: 'config', description: 'Development env vars' },
  { path: '/config.json', category: 'config', description: 'JSON config' },
  { path: '/config.yaml', category: 'config', description: 'YAML config' },
  { path: '/config.yml', category: 'config', description: 'YAML config (alt)' },
  { path: '/wp-config.php', category: 'config', description: 'WordPress config' },
  { path: '/web.config', category: 'config', description: 'IIS config' },
  { path: '/.htaccess', category: 'config', description: 'Apache config' },
  { path: '/nginx.conf', category: 'config', description: 'Nginx config' },
  { path: '/package.json', category: 'config', description: 'Node.js package manifest' },
  { path: '/composer.json', category: 'config', description: 'PHP Composer manifest' },
  { path: '/Gemfile', category: 'config', description: 'Ruby Gemfile' },
  { path: '/requirements.txt', category: 'config', description: 'Python requirements' },
  { path: '/tsconfig.json', category: 'config', description: 'TypeScript config' },

  // ── Backup Files ──────────────────────────────
  { path: '/backup', category: 'backup', description: 'Backup directory' },
  { path: '/backup.sql', category: 'backup', description: 'SQL backup' },
  { path: '/backup.zip', category: 'backup', description: 'Zip backup' },
  { path: '/backup.tar.gz', category: 'backup', description: 'Tar backup' },
  { path: '/db.sql', category: 'backup', description: 'Database dump' },
  { path: '/dump.sql', category: 'backup', description: 'Database dump (alt)' },
  { path: '/database.sql', category: 'backup', description: 'Database backup' },
  { path: '/data.json', category: 'backup', description: 'Data export' },

  // ── Database UIs ──────────────────────────────
  { path: '/phpmyadmin', category: 'database', description: 'phpMyAdmin' },
  { path: '/adminer.php', category: 'database', description: 'Adminer DB' },
  { path: '/pgadmin', category: 'database', description: 'pgAdmin' },
  { path: '/mongo-express', category: 'database', description: 'Mongo Express' },
  { path: '/redis-commander', category: 'database', description: 'Redis Commander' },

  // ── Infrastructure ────────────────────────────
  { path: '/robots.txt', category: 'infra', description: 'Robots.txt (reveals paths)' },
  { path: '/sitemap.xml', category: 'infra', description: 'Sitemap' },
  { path: '/crossdomain.xml', category: 'infra', description: 'Flash crossdomain policy' },
  { path: '/security.txt', category: 'infra', description: 'Security.txt' },
  { path: '/.well-known/security.txt', category: 'infra', description: 'Security.txt (well-known)' },
  { path: '/favicon.ico', category: 'infra', description: 'Favicon (fingerprinting)' },
  { path: '/humans.txt', category: 'infra', description: 'Humans.txt' },
  { path: '/Dockerfile', category: 'infra', description: 'Dockerfile' },
  { path: '/docker-compose.yml', category: 'infra', description: 'Docker Compose' },
  { path: '/Makefile', category: 'infra', description: 'Makefile' },
  { path: '/Procfile', category: 'infra', description: 'Heroku Procfile' },

  // ── CI/CD Artifacts ───────────────────────────
  { path: '/.github/workflows', category: 'cicd', description: 'GitHub Actions workflows' },
  { path: '/.gitlab-ci.yml', category: 'cicd', description: 'GitLab CI config' },
  { path: '/Jenkinsfile', category: 'cicd', description: 'Jenkins pipeline' },
  { path: '/.circleci/config.yml', category: 'cicd', description: 'CircleCI config' },
  { path: '/.travis.yml', category: 'cicd', description: 'Travis CI config' },
  { path: '/deploy.sh', category: 'cicd', description: 'Deploy script' },

  // ── Sensitive Data ────────────────────────────
  { path: '/api/users', category: 'data', description: 'User list endpoint' },
  { path: '/api/v1/users', category: 'data', description: 'User list v1' },
  { path: '/users.json', category: 'data', description: 'User data export' },
  { path: '/api/config', category: 'data', description: 'Config API' },
  { path: '/api/settings', category: 'data', description: 'Settings API' },
  { path: '/api/internal', category: 'data', description: 'Internal API' },
  { path: '/api/debug', category: 'data', description: 'Debug API' },
  { path: '/internal', category: 'data', description: 'Internal endpoint' },
  { path: '/private', category: 'data', description: 'Private endpoint' },
  { path: '/secret', category: 'data', description: 'Secret endpoint' },
];

// ─── Bruteforce Engine ────────────────────────────────────────

/**
 * Bruteforce common sensitive paths on the target.
 * Uses baseline filtering to remove catch-all route false positives.
 *
 * @returns Array of accessible paths with metadata
 */
export async function bruteforcePaths(
  config: BruteforceConfig,
): Promise<BruteforceResult[]> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? 5000;
  const concurrency = config.concurrency ?? 10;
  const results: BruteforceResult[] = [];

  config.logger?.info('path-bruteforce: starting', {
    baseUrl,
    wordlistSize: PATH_WORDLIST.length,
    concurrency,
  });

  // Process in batches for concurrency control
  for (let i = 0; i < PATH_WORDLIST.length; i += concurrency) {
    const batch = PATH_WORDLIST.slice(i, i + concurrency);

    const batchResults = await Promise.all(
      batch.map((entry) => probePath(baseUrl, entry, config.baseline, timeout)),
    );

    for (const result of batchResults) {
      if (result) {
        results.push(result);
        config.logger?.debug('path-bruteforce: found', {
          path: result.path,
          status: result.status,
          category: result.category,
        });
      }
    }
  }

  config.logger?.info('path-bruteforce: complete', {
    totalProbed: PATH_WORDLIST.length,
    found: results.length,
  });

  return results;
}

// ─── Probing ──────────────────────────────────────────────────

async function probePath(
  baseUrl: string,
  entry: PathEntry,
  baseline: BaselineFingerprint | null,
  timeout: number,
): Promise<BruteforceResult | null> {
  const fullUrl = baseUrl + entry.path;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  const startTime = performance.now();

  try {
    const response = await fetch(fullUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; WIGTN-SPEAR/0.1.0)',
        Accept: '*/*',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    const body = await response.text();
    const latencyMs = Math.round(performance.now() - startTime);
    const contentType = response.headers.get('content-type') ?? '';

    // Filter: skip non-accessible responses
    if (response.status === 404 || response.status === 405 || response.status >= 500) {
      return null;
    }

    // Filter: skip baseline matches (catch-all route FPs)
    if (matchesBaseline(baseline, response.status, body)) {
      return null;
    }

    // Filter: skip empty/tiny responses for non-status endpoints
    if (body.length < 10 && !['monitoring', 'debug'].includes(entry.category)) {
      return null;
    }

    return {
      path: entry.path,
      fullUrl,
      status: response.status,
      contentType,
      bodySize: body.length,
      category: entry.category,
      description: entry.description,
      bodyPreview: body.slice(0, 500),
      latencyMs,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Get the path wordlist size (for logging/display).
 */
export function getWordlistSize(): number {
  return PATH_WORDLIST.length;
}
