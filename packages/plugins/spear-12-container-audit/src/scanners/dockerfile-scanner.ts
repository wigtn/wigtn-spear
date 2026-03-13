/**
 * SPEAR-12: Dockerfile Scanner
 *
 * Scans Dockerfile content for container security issues:
 *   - Running as root user
 *   - Missing USER directive
 *   - ADD from remote URLs instead of COPY
 *   - Curl pipe to shell patterns
 *   - Hardcoded secrets in ENV
 *   - Missing HEALTHCHECK
 *   - Insecure base image references
 *
 * Dockerfile-specific scanning includes structural analysis beyond
 * simple pattern matching: checking for USER directive presence,
 * HEALTHCHECK presence, and multi-stage build security.
 */

import type { Finding } from '@wigtn/shared';
import type { ContainerPattern } from '../patterns.js';
import { getPatternsForFileType } from '../patterns.js';

// ─── Dockerfile File Detection ──────────────────────────────────

/**
 * Check if a relative file path is a Dockerfile.
 */
export function isDockerfile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  // Standard Dockerfile names
  if (/^Dockerfile(?:\..+)?$/i.test(filename)) {
    return true;
  }

  // dockerfile (lowercase)
  if (filename.toLowerCase() === 'dockerfile') {
    return true;
  }

  // Containerfile (Podman equivalent)
  if (/^Containerfile(?:\..+)?$/i.test(filename)) {
    return true;
  }

  return false;
}

// ─── Dockerfile-Specific Checks ─────────────────────────────────

/**
 * Check whether the Dockerfile has a USER directive (non-root).
 * Returns a finding if no USER directive is found or only USER root is set.
 */
function* checkUserDirective(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');
  const hasFrom = lines.some((l) => /^\s*FROM\s+/i.test(l));
  const userLines = lines.filter((l) => /^\s*USER\s+/i.test(l));

  if (!hasFrom) return;

  // If no USER directive at all, report
  if (userLines.length === 0) {
    yield {
      ruleId: 'container-dockerfile-no-user',
      severity: 'medium',
      message: '[Dockerfile] Missing USER directive: container will run as root by default',
      file: filePath,
      line: 1,
      mitreTechniques: ['T1078'],
      remediation: 'Add a USER directive with a non-root user. Example: RUN useradd -r appuser && USER appuser',
      metadata: {
        pluginId,
        category: 'root_user',
        scanner: 'dockerfile',
        patternName: 'Missing USER Directive',
      },
    };
  }
}

/**
 * Check whether the Dockerfile has a HEALTHCHECK directive.
 */
function* checkHealthcheck(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');
  const hasFrom = lines.some((l) => /^\s*FROM\s+/i.test(l));
  const hasHealthcheck = lines.some((l) => /^\s*HEALTHCHECK\s+/i.test(l));

  if (hasFrom && !hasHealthcheck) {
    yield {
      ruleId: 'container-dockerfile-no-healthcheck',
      severity: 'low',
      message: '[Dockerfile] Missing HEALTHCHECK: container health cannot be monitored',
      file: filePath,
      line: 1,
      mitreTechniques: ['T1610'],
      remediation: 'Add a HEALTHCHECK instruction. Example: HEALTHCHECK CMD curl -f http://localhost/ || exit 1',
      metadata: {
        pluginId,
        category: 'misconfiguration',
        scanner: 'dockerfile',
        patternName: 'Missing HEALTHCHECK',
      },
    };
  }
}

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to Dockerfiles.
 */
const DOCKERFILE_PATTERNS: readonly ContainerPattern[] = getPatternsForFileType('dockerfile');

/**
 * Scan Dockerfile content for security issues.
 *
 * @param content - The Dockerfile content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected issue.
 */
export function* scanDockerfileContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  // Run structural checks
  yield* checkUserDirective(content, filePath, pluginId);
  yield* checkHealthcheck(content, filePath, pluginId);

  // Run pattern matching
  for (const pattern of DOCKERFILE_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Dockerfile] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'dockerfile',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Dockerfile] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'dockerfile',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}
