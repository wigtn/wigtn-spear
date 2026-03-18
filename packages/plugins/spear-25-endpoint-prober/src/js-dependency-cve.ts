/**
 * SPEAR-25: Deployed JS Dependency CVE Scanner
 *
 * Extracts library version information from deployed JavaScript bundles
 * and matches them against a built-in CVE database for the top 50 JS libraries.
 *
 * Version extraction methods:
 *   - JS comment headers: `/*! jQuery v3.6.0 *​/`
 *   - In-code VERSION constants: `version = "4.17.20"`
 *   - Sourcemap source paths: `node_modules/lodash@4.17.20/`
 *
 * @module js-dependency-cve
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface DetectedDependency {
  /** Library name (e.g. "jquery") */
  name: string;
  /** Detected version string (e.g. "3.6.0") */
  version: string;
  /** How the version was detected */
  source: 'comment_header' | 'version_constant' | 'sourcemap_path';
  /** Script URL or sourcemap URL where detected */
  detectedIn: string;
}

export interface DependencyCveMatch {
  /** Library name */
  name: string;
  /** Detected version */
  version: string;
  /** CVE identifier */
  cveId: string;
  /** Brief description */
  description: string;
  /** CVSS score */
  cvss: number;
  /** Severity level */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Version that fixes the CVE */
  fixVersion: string;
  /** Detection source */
  detectedIn: string;
}

export interface DependencyCveResult {
  /** Libraries detected in deployed JS */
  dependencies: DetectedDependency[];
  /** CVE matches found */
  cves: DependencyCveMatch[];
}

// ─── Version Detection Patterns ───────────────────────────────

interface LibraryPattern {
  name: string;
  /** Pattern to match in JS content -- capture group 1 must be the version */
  regex: RegExp;
  source: 'comment_header' | 'version_constant';
}

const LIBRARY_PATTERNS: readonly LibraryPattern[] = [
  // jQuery
  { name: 'jquery', regex: /[/*! ]*jQuery\s+(?:JavaScript Library\s+)?v(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Lodash
  { name: 'lodash', regex: /[/*! ]*lodash\s+(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  { name: 'lodash', regex: /var\s+VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, source: 'version_constant' },
  // React
  { name: 'react', regex: /[/*! ]*React\s+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  { name: 'react', regex: /ReactVersion\s*=\s*['"](\d+\.\d+\.\d+)['"]/, source: 'version_constant' },
  // Angular
  { name: 'angular', regex: /[/*! ]*@angular\/core[@\s]+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Vue
  { name: 'vue', regex: /[/*! ]*Vue\.js\s+v(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  { name: 'vue', regex: /Vue\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, source: 'version_constant' },
  // Axios
  { name: 'axios', regex: /[/*! ]*axios\s+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Moment.js
  { name: 'moment', regex: /[/*! ]*[Mm]oment\.js\s+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Bootstrap
  { name: 'bootstrap', regex: /[/*! ]*Bootstrap\s+v(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Handlebars
  { name: 'handlebars', regex: /[/*! ]*[Hh]andlebars\s+v?(\d+\.\d+\.\d+)/, source: 'comment_header' },
  // Underscore
  { name: 'underscore', regex: /[/*! ]*Underscore\.js\s+(\d+\.\d+\.\d+)/, source: 'comment_header' },
  // Socket.io
  { name: 'socket.io', regex: /[/*! ]*socket\.io\s+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // DOMPurify
  { name: 'dompurify', regex: /[/*! ]*DOMPurify\s+(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Next.js
  { name: 'next', regex: /next\/version.*?['"](\d+\.\d+\.\d+)['"]/, source: 'version_constant' },
  // D3
  { name: 'd3', regex: /[/*! ]*d3\.js\s+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Chart.js
  { name: 'chart.js', regex: /[/*! ]*Chart\.js\s+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Highlight.js
  { name: 'highlight.js', regex: /[/*! ]*highlight\.js\s+(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Marked
  { name: 'marked', regex: /[/*! ]*marked\s+v?(\d+\.\d+\.\d+)/i, source: 'comment_header' },
  // Swiper
  { name: 'swiper', regex: /[/*! ]*Swiper\s+(\d+\.\d+\.\d+)/i, source: 'comment_header' },
];

/** Pattern to detect libraries from sourcemap source paths */
const SOURCEMAP_PATH_REGEX = /node_modules\/(@?[\w.-]+(?:\/[\w.-]+)?)@(\d+\.\d+\.\d+)\//g;
const SOURCEMAP_PATH_REGEX2 = /node_modules\/([\w.-]+)\/(?:.*?version.*?['"](\d+\.\d+\.\d+)['"])/;

// ─── CVE Database ─────────────────────────────────────────────

interface CveEntry {
  library: string;
  cveId: string;
  description: string;
  cvss: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Affected version range: versions < fixVersion are affected */
  fixVersion: string;
  /** Minimum affected version (optional, for ranges) */
  minAffected?: string;
}

/**
 * Built-in CVE database for top JS libraries.
 * This covers high-impact CVEs that are commonly exploitable in production.
 */
const CVE_DATABASE: readonly CveEntry[] = [
  // jQuery
  { library: 'jquery', cveId: 'CVE-2020-11022', description: 'XSS via HTML passed to jQuery DOM manipulation methods', cvss: 6.1, severity: 'medium', fixVersion: '3.5.0' },
  { library: 'jquery', cveId: 'CVE-2020-11023', description: 'XSS via <option> elements passed to jQuery DOM manipulation', cvss: 6.1, severity: 'medium', fixVersion: '3.5.0' },
  { library: 'jquery', cveId: 'CVE-2019-11358', description: 'Prototype pollution in jQuery.extend', cvss: 6.1, severity: 'medium', fixVersion: '3.4.0' },

  // Lodash
  { library: 'lodash', cveId: 'CVE-2021-23337', description: 'Command injection via template', cvss: 7.2, severity: 'high', fixVersion: '4.17.21' },
  { library: 'lodash', cveId: 'CVE-2020-28500', description: 'ReDoS via toNumber, trim, trimEnd', cvss: 5.3, severity: 'medium', fixVersion: '4.17.21' },
  { library: 'lodash', cveId: 'CVE-2020-8203', description: 'Prototype pollution via zipObjectDeep', cvss: 7.4, severity: 'high', fixVersion: '4.17.20' },
  { library: 'lodash', cveId: 'CVE-2019-10744', description: 'Prototype pollution via defaultsDeep', cvss: 9.1, severity: 'critical', fixVersion: '4.17.12' },

  // Angular
  { library: 'angular', cveId: 'CVE-2024-8373', description: 'XSS via HTML sanitization bypass', cvss: 6.1, severity: 'medium', fixVersion: '18.2.0' },

  // Vue
  { library: 'vue', cveId: 'CVE-2024-6783', description: 'XSS via server-side rendering', cvss: 6.1, severity: 'medium', fixVersion: '3.4.31', minAffected: '3.0.0' },

  // Axios
  { library: 'axios', cveId: 'CVE-2023-45857', description: 'CSRF via XSRF-TOKEN cookie exposure to third parties', cvss: 6.5, severity: 'medium', fixVersion: '1.6.0', minAffected: '0.8.1' },

  // Moment.js
  { library: 'moment', cveId: 'CVE-2022-31129', description: 'ReDoS via crafted date string', cvss: 7.5, severity: 'high', fixVersion: '2.29.4' },
  { library: 'moment', cveId: 'CVE-2022-24785', description: 'Path traversal via locale string', cvss: 7.5, severity: 'high', fixVersion: '2.29.2' },

  // Bootstrap
  { library: 'bootstrap', cveId: 'CVE-2024-6531', description: 'XSS via carousel component', cvss: 6.4, severity: 'medium', fixVersion: '5.3.4', minAffected: '5.0.0' },
  { library: 'bootstrap', cveId: 'CVE-2024-6484', description: 'XSS via tooltip/popover components', cvss: 6.4, severity: 'medium', fixVersion: '5.3.4', minAffected: '5.0.0' },

  // Handlebars
  { library: 'handlebars', cveId: 'CVE-2021-23369', description: 'Remote code execution via crafted template', cvss: 9.8, severity: 'critical', fixVersion: '4.7.7' },
  { library: 'handlebars', cveId: 'CVE-2019-19919', description: 'Prototype pollution via template', cvss: 9.8, severity: 'critical', fixVersion: '4.5.3' },

  // Socket.io
  { library: 'socket.io', cveId: 'CVE-2024-38355', description: 'Denial of Service via malformed packet', cvss: 7.3, severity: 'high', fixVersion: '4.7.6' },

  // DOMPurify
  { library: 'dompurify', cveId: 'CVE-2024-47875', description: 'XSS bypass via mXSS in nested templates', cvss: 7.1, severity: 'high', fixVersion: '3.1.7', minAffected: '3.0.0' },

  // Marked
  { library: 'marked', cveId: 'CVE-2022-21681', description: 'ReDoS via crafted markdown input', cvss: 7.5, severity: 'high', fixVersion: '4.0.10' },

  // Highlight.js
  { library: 'highlight.js', cveId: 'CVE-2021-32879', description: 'ReDoS via crafted code snippet', cvss: 7.5, severity: 'high', fixVersion: '11.0.0' },

  // Swiper
  { library: 'swiper', cveId: 'CVE-2024-48948', description: 'XSS via crafted slide content', cvss: 6.1, severity: 'medium', fixVersion: '11.1.10' },

  // Underscore
  { library: 'underscore', cveId: 'CVE-2021-25946', description: 'Arbitrary code injection via template', cvss: 9.8, severity: 'critical', fixVersion: '1.13.1' },

  // D3
  { library: 'd3', cveId: 'CVE-2023-46308', description: 'Prototype pollution via d3-scaleChromatic', cvss: 7.5, severity: 'high', fixVersion: '7.9.0' },

  // Next.js
  { library: 'next', cveId: 'CVE-2024-46982', description: 'Cache poisoning via crafted request', cvss: 7.5, severity: 'high', fixVersion: '14.2.10', minAffected: '13.0.0' },
  { library: 'next', cveId: 'CVE-2024-34350', description: 'SSRF via Server Actions redirect', cvss: 7.5, severity: 'high', fixVersion: '14.1.1', minAffected: '13.4.0' },
];

// ─── Core Functions ───────────────────────────────────────────

/**
 * Detect JS library versions from bundle content and match against CVE database.
 *
 * @param jsContents - Array of { content, url } pairs from downloaded JS bundles
 * @param sourcemapSources - Optional array of source file paths from sourcemaps
 * @param logger - Optional logger
 */
export function scanDependencyCves(
  jsContents: Array<{ content: string; url: string }>,
  sourcemapSources?: Array<{ sources: string[]; url: string }>,
  logger?: SpearLogger,
): DependencyCveResult {
  const result: DependencyCveResult = {
    dependencies: [],
    cves: [],
  };

  const seen = new Set<string>();

  // Method 1+2: Scan JS content for comment headers and VERSION constants
  for (const { content, url } of jsContents) {
    for (const pattern of LIBRARY_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (!match) continue;

      const version = match[1]!;
      const key = `${pattern.name}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      result.dependencies.push({
        name: pattern.name,
        version,
        source: pattern.source,
        detectedIn: url,
      });
    }
  }

  // Method 3: Extract from sourcemap source paths
  if (sourcemapSources) {
    for (const { sources, url } of sourcemapSources) {
      for (const sourcePath of sources) {
        const re = new RegExp(SOURCEMAP_PATH_REGEX.source, SOURCEMAP_PATH_REGEX.flags);
        let match;
        while ((match = re.exec(sourcePath)) !== null) {
          const name = match[1]!.replace(/^@/, '');
          const version = match[2]!;
          const key = `${name}@${version}`;
          if (seen.has(key)) continue;
          seen.add(key);

          result.dependencies.push({
            name,
            version,
            source: 'sourcemap_path',
            detectedIn: url,
          });
        }
      }
    }
  }

  logger?.info('js-dependency-cve: detected libraries', {
    count: result.dependencies.length,
    libraries: result.dependencies.map((d) => `${d.name}@${d.version}`),
  });

  // Match against CVE database
  for (const dep of result.dependencies) {
    for (const cve of CVE_DATABASE) {
      if (cve.library !== dep.name) continue;
      if (!isAffected(dep.version, cve.fixVersion, cve.minAffected)) continue;

      result.cves.push({
        name: dep.name,
        version: dep.version,
        cveId: cve.cveId,
        description: cve.description,
        cvss: cve.cvss,
        severity: cve.severity,
        fixVersion: cve.fixVersion,
        detectedIn: dep.detectedIn,
      });
    }
  }

  logger?.info('js-dependency-cve: CVE matches', {
    cves: result.cves.length,
    matches: result.cves.map((c) => `${c.name}@${c.version} → ${c.cveId}`),
  });

  return result;
}

// ─── Semver Comparison ────────────────────────────────────────

/**
 * Parse a semver string into [major, minor, patch].
 * Returns null if the string is not a valid semver.
 */
function parseSemver(version: string): [number, number, number] | null {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

/**
 * Compare two semver versions.
 * Returns -1 if a < b, 0 if a === b, 1 if a > b.
 */
function compareSemver(a: [number, number, number], b: [number, number, number]): number {
  for (let i = 0; i < 3; i++) {
    if (a[i]! < b[i]!) return -1;
    if (a[i]! > b[i]!) return 1;
  }
  return 0;
}

/**
 * Check if a version is affected by a CVE.
 * Affected = version < fixVersion AND version >= minAffected (if specified).
 */
function isAffected(version: string, fixVersion: string, minAffected?: string): boolean {
  const v = parseSemver(version);
  const fix = parseSemver(fixVersion);
  if (!v || !fix) return false;

  // Version must be less than fixVersion
  if (compareSemver(v, fix) >= 0) return false;

  // If minAffected is specified, version must be >= minAffected
  if (minAffected) {
    const min = parseSemver(minAffected);
    if (min && compareSemver(v, min) < 0) return false;
  }

  return true;
}
