/**
 * SPEAR-12: Docker Compose Scanner
 *
 * Scans docker-compose.yml/yaml content for container security issues:
 *   - Privileged containers
 *   - Dangerous capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE)
 *   - Host namespace sharing (PID, network, IPC)
 *   - Sensitive volume mounts (Docker socket, /etc, /proc, SSH keys)
 *   - Exposed ports on all interfaces
 *   - Database ports exposed to host
 *   - Environment variable secrets
 *   - Insecure registries and untagged images
 */

import type { Finding } from '@wigtn/shared';
import type { ContainerPattern } from '../patterns.js';
import { getPatternsForFileType } from '../patterns.js';

// ─── Compose File Detection ─────────────────────────────────────

/**
 * Check if a relative file path is a Docker Compose configuration file.
 */
export function isComposeFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  // Standard compose file names
  if (/^(?:docker-)?compose(?:\..+)?\.ya?ml$/i.test(filename)) {
    return true;
  }

  // docker-compose.yml, docker-compose.yaml
  if (/^docker-compose\.ya?ml$/i.test(filename)) {
    return true;
  }

  // compose.yml, compose.yaml
  if (/^compose\.ya?ml$/i.test(filename)) {
    return true;
  }

  return false;
}

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to Docker Compose files.
 */
const COMPOSE_PATTERNS: readonly ContainerPattern[] = getPatternsForFileType('compose');

/**
 * Scan Docker Compose file content for security issues.
 *
 * @param content - The compose file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected issue.
 */
export function* scanComposeContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of COMPOSE_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Docker Compose] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'compose',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Docker Compose] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'compose',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}
