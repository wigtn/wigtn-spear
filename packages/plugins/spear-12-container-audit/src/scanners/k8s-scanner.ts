/**
 * SPEAR-12: Kubernetes Manifest Scanner
 *
 * Scans Kubernetes YAML manifests for container security issues:
 *   - Privileged pod security contexts
 *   - Dangerous capabilities
 *   - Host namespace sharing (PID, network, IPC)
 *   - Sensitive hostPath volume mounts
 *   - Running as root user
 *   - Missing security context fields
 *   - Disabled seccomp/AppArmor profiles
 *   - Missing resource limits
 *   - Read-write root filesystem
 *
 * Target files:
 *   - *.yaml / *.yml files containing Kubernetes resource kinds
 *   - Files in k8s/, kubernetes/, deploy/, manifests/ directories
 */

import type { Finding } from '@wigtn/shared';
import type { ContainerPattern } from '../patterns.js';
import { getPatternsForFileType } from '../patterns.js';

// ─── K8s Manifest Detection ────────────────────────────────────

/** Kubernetes resource kind indicators in YAML files. */
const K8S_KIND_PATTERN = /(?:^|\n)\s*kind\s*:\s*(?:Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|ReplicationController)/im;

/** Directory names commonly containing K8s manifests. */
const K8S_DIRS = ['k8s', 'kubernetes', 'deploy', 'manifests', 'helm', 'charts'];

/**
 * Check if a relative file path is a Kubernetes manifest.
 *
 * Note: This is a heuristic check based on file location and extension.
 * The actual content must also be validated for K8s kind fields.
 */
export function isK8sManifest(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';

  // Must be YAML
  if (ext !== 'yml' && ext !== 'yaml') {
    return false;
  }

  // Check if in a known K8s directory
  const parts = normalized.split('/');
  for (const part of parts) {
    if (K8S_DIRS.includes(part.toLowerCase())) {
      return true;
    }
  }

  return false;
}

/**
 * Validate that YAML content contains Kubernetes resource definitions.
 */
export function isK8sContent(content: string): boolean {
  return K8S_KIND_PATTERN.test(content);
}

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to Kubernetes manifests.
 */
const K8S_PATTERNS: readonly ContainerPattern[] = getPatternsForFileType('k8s');

/**
 * Scan Kubernetes manifest content for security issues.
 *
 * @param content - The K8s YAML content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected issue.
 */
export function* scanK8sContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  // Only scan if the content is actually a K8s manifest
  if (!isK8sContent(content)) {
    return;
  }

  const lines = content.split('\n');

  for (const pattern of K8S_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[K8s Manifest] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'k8s',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[K8s Manifest] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'k8s',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}
