/**
 * SPEAR-13: Azure Credential Scanner
 *
 * Scans file content for Microsoft Azure credential patterns including:
 *   - Client secrets and application credentials
 *   - Storage connection strings (account keys)
 *   - SQL connection strings with embedded passwords
 *   - CosmosDB, Service Bus, Event Hub connection strings
 *   - SAS tokens and SAS URLs
 *   - Managed identity / IMDS token endpoints
 *   - Key Vault URL references
 *
 * This scanner applies both Azure-specific and generic patterns from
 * patterns.ts, consistent with the scanner pattern in spear-10.
 */

import type { Finding } from '@wigtn/shared';
import type { CredentialPattern } from '../patterns.js';
import { ALL_PATTERNS } from '../patterns.js';

// ─── Pattern Selection ──────────────────────────────────────────

/**
 * All patterns applicable to Azure credential scanning.
 * Includes Azure-specific patterns plus generic patterns that can
 * detect cross-cloud credentials (private keys, IMDS, env vars).
 */
const AZURE_PATTERNS: readonly CredentialPattern[] = ALL_PATTERNS.filter(
  (p) => p.provider === 'azure' || p.provider === 'generic',
);

// ─── Azure Identity Types ───────────────────────────────────────

export interface AzureIdentityRef {
  type: 'client-secret' | 'connection-string' | 'sas-token' | 'managed-identity';
  clientId?: string;
  tenantId?: string;
  resourceType?: string;
  line?: number;
}

// ─── Scan Function ──────────────────────────────────────────────

/**
 * Scan file content against all Azure-applicable credential patterns.
 *
 * @param content - The file content to scan.
 * @param filePath - Relative path of the file (for Finding.file).
 * @param pluginId - Plugin ID for metadata.
 * @yields Finding objects for each detected pattern match.
 */
export function* scanAzureContent(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const lines = content.split('\n');

  for (const pattern of AZURE_PATTERNS) {
    // Test against full content first for multi-line patterns
    if (pattern.pattern.test(content)) {
      // Reset regex lastIndex for stateless matching
      pattern.pattern.lastIndex = 0;

      // Find the specific line(s) that match
      let matchFound = false;

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex]!;
        if (pattern.pattern.test(line)) {
          pattern.pattern.lastIndex = 0;
          matchFound = true;
          yield {
            ruleId: pattern.id,
            severity: pattern.severity,
            message: `[Azure] ${pattern.name}: ${pattern.description}`,
            file: filePath,
            line: lineIndex + 1,
            mitreTechniques: pattern.mitre,
            remediation: pattern.remediation,
            metadata: {
              pluginId,
              provider: pattern.provider,
              category: pattern.category,
              scanner: 'azure',
              patternName: pattern.name,
            },
          };
        }
      }

      // If the pattern matched full content but no individual line, report on line 1
      if (!matchFound) {
        yield {
          ruleId: pattern.id,
          severity: pattern.severity,
          message: `[Azure] ${pattern.name}: ${pattern.description}`,
          file: filePath,
          line: 1,
          mitreTechniques: pattern.mitre,
          remediation: pattern.remediation,
          metadata: {
            pluginId,
            provider: pattern.provider,
            category: pattern.category,
            scanner: 'azure',
            patternName: pattern.name,
          },
        };
      }
    }
  }
}

// ─── Azure Identity Extraction ──────────────────────────────────

/**
 * Extract Azure identity references from file content.
 *
 * Identifies client IDs, tenant IDs, connection string types, and
 * managed identity endpoints for the IAM mapper module.
 *
 * @param content - The file content to analyze.
 * @returns Array of Azure identity references found.
 */
export function extractAzureIdentityRefs(content: string): AzureIdentityRef[] {
  const refs: AzureIdentityRef[] = [];
  const lines = content.split('\n');

  const uuidRegex = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex]!;

    // Detect client secret assignments
    if (/(?:AZURE_CLIENT_SECRET|client_secret|clientSecret)/i.test(line)) {
      const clientIdMatch = content.match(
        /(?:AZURE_CLIENT_ID|client_id|clientId)\s*[:=]\s*['"`]?([0-9a-f-]{36})['"`]?/i,
      );
      const tenantIdMatch = content.match(
        /(?:AZURE_TENANT_ID|tenant_id|tenantId)\s*[:=]\s*['"`]?([0-9a-f-]{36})['"`]?/i,
      );

      refs.push({
        type: 'client-secret',
        clientId: clientIdMatch?.[1],
        tenantId: tenantIdMatch?.[1],
        line: lineIndex + 1,
      });
    }

    // Detect connection strings
    if (/DefaultEndpointsProtocol=|AccountKey=/i.test(line)) {
      const resourceMatch = line.match(/AccountName=([^;]+)/i);
      refs.push({
        type: 'connection-string',
        resourceType: resourceMatch ? `storage:${resourceMatch[1]}` : 'storage',
        line: lineIndex + 1,
      });
    }

    // Detect SAS tokens
    if (/sig=[A-Za-z0-9%+/=]+/i.test(line)) {
      refs.push({
        type: 'sas-token',
        line: lineIndex + 1,
      });
    }

    // Detect managed identity endpoints
    if (/169\.254\.169\.254\/metadata\/identity|IDENTITY_ENDPOINT|MSI_ENDPOINT/i.test(line)) {
      refs.push({
        type: 'managed-identity',
        line: lineIndex + 1,
      });
    }
  }

  return refs;
}
