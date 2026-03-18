/**
 * SPEAR-25: Admin Panel & API Docs Scanner
 *
 * Deep-analyzes paths discovered by the path bruteforce engine.
 * Detects and categorizes admin panels, API documentation,
 * debug endpoints, and database management UIs.
 *
 * For each discovered path, performs content-based classification
 * to determine the exact technology and risk level.
 *
 * @module admin-panel-scanner
 */

import type { SpearLogger, Severity } from '@wigtn/shared';
import type { BruteforceResult } from './path-bruteforce.js';

// ─── Types ────────────────────────────────────────────────────

export interface AdminScanResult {
  /** Detected admin panels */
  adminPanels: DetectedPanel[];
  /** Detected API documentation */
  apiDocs: DetectedApiDoc[];
  /** Detected debug endpoints */
  debugEndpoints: DetectedDebugEndpoint[];
  /** Detected database UIs */
  databaseUIs: DetectedDatabaseUI[];
}

export interface DetectedPanel {
  url: string;
  technology: string;
  authenticated: boolean;
  severity: Severity;
  evidence: string;
}

export interface DetectedApiDoc {
  url: string;
  type: 'swagger' | 'graphql' | 'redoc' | 'openapi' | 'other';
  hasAuth: boolean;
  endpointCount?: number;
  severity: Severity;
  evidence: string;
}

export interface DetectedDebugEndpoint {
  url: string;
  type: string;
  leaksInfo: boolean;
  severity: Severity;
  evidence: string;
}

export interface DetectedDatabaseUI {
  url: string;
  technology: string;
  authenticated: boolean;
  severity: Severity;
  evidence: string;
}

// ─── Detection Patterns ───────────────────────────────────────

interface DetectionPattern {
  /** Content patterns to match */
  patterns: RegExp[];
  /** Technology name */
  technology: string;
  /** Category */
  category: 'admin' | 'api_docs' | 'debug' | 'database';
}

const ADMIN_PATTERNS: DetectionPattern[] = [
  {
    patterns: [/wordpress/i, /wp-admin/i, /wp-login/i],
    technology: 'WordPress',
    category: 'admin',
  },
  {
    patterns: [/django/i, /csrfmiddlewaretoken/i, /__admin__/i],
    technology: 'Django Admin',
    category: 'admin',
  },
  {
    patterns: [/rails/i, /active_admin/i, /activeadmin/i],
    technology: 'Rails ActiveAdmin',
    category: 'admin',
  },
  {
    patterns: [/laravel/i, /nova/i, /laravel-nova/i],
    technology: 'Laravel Nova',
    category: 'admin',
  },
  {
    patterns: [/strapi/i, /strapi-admin/i],
    technology: 'Strapi',
    category: 'admin',
  },
  {
    patterns: [/directus/i],
    technology: 'Directus',
    category: 'admin',
  },
  {
    patterns: [/keystone/i, /keystonejs/i],
    technology: 'KeystoneJS',
    category: 'admin',
  },
  {
    patterns: [/admin.*login|login.*admin/i, /<form[^>]*action.*login/i],
    technology: 'Generic Admin Panel',
    category: 'admin',
  },
];

const API_DOC_PATTERNS: DetectionPattern[] = [
  {
    patterns: [/swagger-ui/i, /swagger-resources/i, /swaggerVersion/i],
    technology: 'Swagger UI',
    category: 'api_docs',
  },
  {
    patterns: [/graphql|graphiql|__schema/i],
    technology: 'GraphQL',
    category: 'api_docs',
  },
  {
    patterns: [/redoc/i, /redoc\.standalone/i],
    technology: 'ReDoc',
    category: 'api_docs',
  },
  {
    patterns: [/openapi|"swagger"\s*:\s*"[23]/i],
    technology: 'OpenAPI Spec',
    category: 'api_docs',
  },
];

const DEBUG_PATTERNS: DetectionPattern[] = [
  {
    patterns: [/phpinfo\(\)|php version|configuration/i],
    technology: 'phpinfo',
    category: 'debug',
  },
  {
    patterns: [/actuator|spring boot/i],
    technology: 'Spring Boot Actuator',
    category: 'debug',
  },
  {
    patterns: [/werkzeug|debugger/i],
    technology: 'Flask Werkzeug Debugger',
    category: 'debug',
  },
  {
    patterns: [/prometheus|# HELP|# TYPE/i],
    technology: 'Prometheus Metrics',
    category: 'debug',
  },
  {
    patterns: [/pprof|goroutine|heap/i],
    technology: 'Go pprof',
    category: 'debug',
  },
];

const DATABASE_PATTERNS: DetectionPattern[] = [
  {
    patterns: [/phpmyadmin/i, /pmahomme/i],
    technology: 'phpMyAdmin',
    category: 'database',
  },
  {
    patterns: [/adminer/i],
    technology: 'Adminer',
    category: 'database',
  },
  {
    patterns: [/pgadmin/i, /postgresql/i],
    technology: 'pgAdmin',
    category: 'database',
  },
  {
    patterns: [/mongo.*express/i],
    technology: 'Mongo Express',
    category: 'database',
  },
  {
    patterns: [/redis.*commander/i],
    technology: 'Redis Commander',
    category: 'database',
  },
];

// ─── Scanner ──────────────────────────────────────────────────

/**
 * Analyze paths discovered by the bruteforce engine to detect
 * admin panels, API docs, debug endpoints, and database UIs.
 */
export function analyzeDiscoveredPaths(
  bruteforceResults: BruteforceResult[],
  logger?: SpearLogger,
): AdminScanResult {
  const adminPanels: DetectedPanel[] = [];
  const apiDocs: DetectedApiDoc[] = [];
  const debugEndpoints: DetectedDebugEndpoint[] = [];
  const databaseUIs: DetectedDatabaseUI[] = [];

  for (const result of bruteforceResults) {
    const body = result.bodyPreview;

    // Check admin panels
    for (const pattern of ADMIN_PATTERNS) {
      if (pattern.patterns.some((p) => p.test(body) || p.test(result.path))) {
        const hasLoginForm = /<form[^>]*>/i.test(body) && /password|login/i.test(body);
        adminPanels.push({
          url: result.fullUrl,
          technology: pattern.technology,
          authenticated: hasLoginForm,
          severity: hasLoginForm ? 'high' : 'critical',
          evidence: `${pattern.technology} detected at ${result.path} (status ${result.status})` +
            (hasLoginForm ? ' — login form present' : ' — NO login required'),
        });
        break;
      }
    }

    // Check API docs
    for (const pattern of API_DOC_PATTERNS) {
      if (pattern.patterns.some((p) => p.test(body) || p.test(result.path))) {
        const docType = detectApiDocType(pattern.technology);
        apiDocs.push({
          url: result.fullUrl,
          type: docType,
          hasAuth: /authorization|bearer|api.key/i.test(body),
          severity: 'high',
          evidence: `${pattern.technology} exposed at ${result.path} (status ${result.status})`,
        });
        break;
      }
    }

    // Check debug endpoints
    for (const pattern of DEBUG_PATTERNS) {
      if (pattern.patterns.some((p) => p.test(body))) {
        const leaksInfo = /version|path|host|port|database|password|secret|key|env/i.test(body);
        debugEndpoints.push({
          url: result.fullUrl,
          type: pattern.technology,
          leaksInfo,
          severity: leaksInfo ? 'critical' : 'high',
          evidence: `${pattern.technology} exposed at ${result.path}` +
            (leaksInfo ? ' — leaks sensitive information' : ''),
        });
        break;
      }
    }

    // Check database UIs
    for (const pattern of DATABASE_PATTERNS) {
      if (pattern.patterns.some((p) => p.test(body) || p.test(result.path))) {
        const hasLogin = /password|login|username/i.test(body);
        databaseUIs.push({
          url: result.fullUrl,
          technology: pattern.technology,
          authenticated: hasLogin,
          severity: 'critical',
          evidence: `${pattern.technology} exposed at ${result.path}` +
            (hasLogin ? ' — login page present' : ' — NO authentication'),
        });
        break;
      }
    }
  }

  logger?.info('admin-panel-scanner: analysis complete', {
    adminPanels: adminPanels.length,
    apiDocs: apiDocs.length,
    debugEndpoints: debugEndpoints.length,
    databaseUIs: databaseUIs.length,
  });

  return { adminPanels, apiDocs, debugEndpoints, databaseUIs };
}

// ─── Helpers ──────────────────────────────────────────────────

function detectApiDocType(
  technology: string,
): DetectedApiDoc['type'] {
  if (technology.includes('Swagger')) return 'swagger';
  if (technology.includes('GraphQL')) return 'graphql';
  if (technology.includes('ReDoc')) return 'redoc';
  if (technology.includes('OpenAPI')) return 'openapi';
  return 'other';
}
