/**
 * SPEAR-15: VS Code Extension Scanner
 *
 * Scans VS Code extension manifests and source files for security issues:
 *   - Excessive permission requests (activationEvents: ["*"])
 *   - Untrusted workspace support with full capabilities
 *   - Outbound network access to non-Microsoft endpoints
 *   - Custom telemetry endpoints
 *   - Child process spawning and dynamic code evaluation
 *   - Post-install script execution
 *   - Workspace data exfiltration patterns
 *
 * Target files:
 *   - package.json (with contributes/activationEvents fields)
 *   - .vscode/extensions.json
 *   - Extension source files (*.js, *.ts)
 */

import type { Finding } from '@wigtn/shared';
import type { IdePattern } from '../patterns.js';
import { getPatternsForPlatform } from '../patterns.js';

// ─── VS Code File Detection ────────────────────────────────────

/**
 * Check if a relative file path is a VS Code extension-related file.
 */
export function isVscodeFile(relativePath: string): boolean {
  const normalized = relativePath.replace(/\\/g, '/');
  const filename = normalized.split('/').pop() ?? '';

  // .vscode/extensions.json
  if (normalized === '.vscode/extensions.json' || normalized.endsWith('/.vscode/extensions.json')) {
    return true;
  }

  // package.json in extension root (must contain VS Code extension indicators)
  if (filename === 'package.json') {
    return true;
  }

  // Extension source files
  if (normalized.includes('/src/') || normalized.includes('/out/')) {
    const ext = filename.split('.').pop()?.toLowerCase() ?? '';
    if (ext === 'js' || ext === 'ts') {
      return true;
    }
  }

  return false;
}

/**
 * Check if a package.json contains VS Code extension indicators.
 */
export function isVscodeExtensionManifest(content: string): boolean {
  return (
    content.includes('"engines"') && content.includes('"vscode"')
  ) || (
    content.includes('"activationEvents"')
  ) || (
    content.includes('"contributes"')
  );
}

// ─── Scan Function ─────────────────────────────────────────────

/**
 * All patterns applicable to VS Code extensions.
 */
const VSCODE_PATTERNS: readonly IdePattern[] = getPatternsForPlatform('vscode');

/**
 * Scan VS Code extension file content for security issues.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected issue.
 */
export function* scanVscodeContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');
  const filename = filePath.split('/').pop() ?? '';

  // For package.json, verify it is a VS Code extension manifest
  if (filename === 'package.json' && !isVscodeExtensionManifest(content)) {
    return;
  }

  for (const pattern of VSCODE_PATTERNS) {
    if (pattern.pattern.test(content)) {
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[VS Code Extension] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              category: pattern.category,
              scanner: 'vscode',
              patternName: pattern.name,
            },
          };
        }
      }

      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[VS Code Extension] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            category: pattern.category,
            scanner: 'vscode',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}
