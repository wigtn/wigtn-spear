/**
 * SPEAR-13: IAM Role Chain Mapper
 *
 * Maps discovered credentials to IAM role chains and permission scopes
 * across all three cloud providers.
 *
 * The IAM mapper receives credential references extracted by the
 * provider-specific scanners and builds a unified view of:
 *
 *   1. Identity graph -- Which IAM identities are referenced
 *   2. Role chains    -- AWS assumed-role chains, GCP impersonation chains
 *   3. Scope mapping  -- What resources/permissions each identity has access to
 *   4. Risk scoring   -- How dangerous each discovered credential chain is
 *
 * This module performs static analysis only. It does not make API calls
 * to verify permissions. The goal is to identify potential privilege
 * escalation paths from the code alone.
 *
 * MITRE ATT&CK:
 *   T1078     -- Valid Accounts
 *   T1078.004 -- Valid Accounts: Cloud Accounts
 *   T1098     -- Account Manipulation
 */

import type { Finding, Severity } from '@wigtn/shared';
import type { IAMRoleChainEntry } from './scanners/aws-scanner.js';
import type { GCPServiceAccountRef } from './scanners/gcp-scanner.js';
import type { AzureIdentityRef } from './scanners/azure-scanner.js';
import type { IMDSAccessPoint } from './scanners/imds-scanner.js';

// ─── Types ──────────────────────────────────────────────────────

export interface IAMIdentity {
  provider: 'aws' | 'gcp' | 'azure';
  identifier: string;
  type: string;
  file: string;
  line?: number;
  riskScore: number;
  riskFactors: string[];
}

export interface IAMChain {
  provider: 'aws' | 'gcp' | 'azure';
  identities: IAMIdentity[];
  chainType: 'assume-role' | 'impersonation' | 'managed-identity' | 'direct';
  maxRiskScore: number;
}

export interface IAMMappingResult {
  identities: IAMIdentity[];
  chains: IAMChain[];
  imdsAccess: IMDSAccessPoint[];
  findings: Finding[];
}

// ─── IAM Mapper ─────────────────────────────────────────────────

/**
 * Map discovered credentials to IAM role chains and generate findings
 * for privilege escalation risks.
 *
 * @param awsEntries - AWS IAM role chain entries from the AWS scanner.
 * @param gcpRefs - GCP service account references from the GCP scanner.
 * @param azureRefs - Azure identity references from the Azure scanner.
 * @param imdsPoints - IMDS access points from the IMDS scanner.
 * @param filePath - Source file path for finding attribution.
 * @param pluginId - Plugin ID for metadata.
 * @returns Combined IAM mapping result with findings.
 */
export function mapIAMChains(
  awsEntries: IAMRoleChainEntry[],
  gcpRefs: GCPServiceAccountRef[],
  azureRefs: AzureIdentityRef[],
  imdsPoints: IMDSAccessPoint[],
  filePath: string,
  pluginId: string,
): IAMMappingResult {
  const identities: IAMIdentity[] = [];
  const chains: IAMChain[] = [];
  const findings: Finding[] = [];

  // ── AWS Identity Mapping ──────────────────────────────────────

  for (const entry of awsEntries) {
    const riskFactors: string[] = [];
    let riskScore = 0;

    if (entry.type === 'assumed-role') {
      riskFactors.push('assumed-role chain detected');
      riskScore += 30;
    }
    if (entry.type === 'user') {
      riskFactors.push('direct IAM user reference (not role-based)');
      riskScore += 20;
    }
    if (entry.roleName?.toLowerCase().includes('admin')) {
      riskFactors.push('admin role name detected');
      riskScore += 40;
    }
    if (entry.roleName?.toLowerCase().includes('root')) {
      riskFactors.push('root role reference');
      riskScore += 50;
    }
    if (entry.roleName?.includes('*')) {
      riskFactors.push('wildcard in role path');
      riskScore += 30;
    }

    identities.push({
      provider: 'aws',
      identifier: entry.arn,
      type: entry.type,
      file: filePath,
      line: entry.line,
      riskScore: Math.min(riskScore, 100),
      riskFactors,
    });
  }

  // Build AWS assume-role chains
  const awsAssumedRoles = awsEntries.filter((e) => e.type === 'assumed-role');
  const awsRoles = awsEntries.filter((e) => e.type === 'role');

  if (awsAssumedRoles.length > 0 || awsRoles.length > 0) {
    const chainIdentities = [...awsAssumedRoles, ...awsRoles].map((entry) => {
      const identity = identities.find((i) => i.identifier === entry.arn);
      return identity!;
    }).filter(Boolean);

    if (chainIdentities.length > 0) {
      const maxRisk = Math.max(...chainIdentities.map((i) => i.riskScore));
      chains.push({
        provider: 'aws',
        identities: chainIdentities,
        chainType: awsAssumedRoles.length > 0 ? 'assume-role' : 'direct',
        maxRiskScore: maxRisk,
      });

      if (awsAssumedRoles.length >= 2) {
        findings.push({
          ruleId: 'iam-chain-aws-multi-hop',
          severity: scoreSeverity(maxRisk),
          message:
            `[IAM Chain] Multi-hop AWS assumed-role chain detected: ` +
            `${awsAssumedRoles.length} assumed roles found in ${filePath}. ` +
            `This indicates a role chaining pattern that may enable privilege escalation.`,
          file: filePath,
          line: awsAssumedRoles[0]?.line,
          mitreTechniques: ['T1078.004', 'T1098'],
          remediation:
            'Review the assumed-role chain for least privilege. ' +
            'Ensure each role in the chain has minimal permissions and the chain is authorized.',
          metadata: {
            pluginId,
            category: 'iam_chain',
            provider: 'aws',
            chainLength: awsAssumedRoles.length,
            roles: awsAssumedRoles.map((e) => e.arn),
          },
        });
      }
    }
  }

  // ── GCP Identity Mapping ──────────────────────────────────────

  for (const ref of gcpRefs) {
    const riskFactors: string[] = [];
    let riskScore = 0;

    if (ref.hasPrivateKey) {
      riskFactors.push('private key present in same file');
      riskScore += 50;
    }
    if (ref.isImpersonation) {
      riskFactors.push('service account impersonation chain');
      riskScore += 30;
    }
    if (ref.email.includes('compute@developer')) {
      riskFactors.push('default compute engine service account');
      riskScore += 20;
    }
    if (ref.email.includes('appspot')) {
      riskFactors.push('App Engine default service account');
      riskScore += 15;
    }

    identities.push({
      provider: 'gcp',
      identifier: ref.email,
      type: ref.isImpersonation ? 'impersonated-sa' : 'service-account',
      file: filePath,
      line: ref.line,
      riskScore: Math.min(riskScore, 100),
      riskFactors,
    });
  }

  // Build GCP impersonation chains
  const gcpImpersonations = gcpRefs.filter((r) => r.isImpersonation);
  if (gcpImpersonations.length > 0) {
    const chainIdentities = gcpImpersonations.map((ref) => {
      const identity = identities.find((i) => i.identifier === ref.email);
      return identity!;
    }).filter(Boolean);

    if (chainIdentities.length > 0) {
      const maxRisk = Math.max(...chainIdentities.map((i) => i.riskScore));
      chains.push({
        provider: 'gcp',
        identities: chainIdentities,
        chainType: 'impersonation',
        maxRiskScore: maxRisk,
      });

      findings.push({
        ruleId: 'iam-chain-gcp-impersonation',
        severity: scoreSeverity(maxRisk),
        message:
          `[IAM Chain] GCP service account impersonation chain detected in ${filePath}. ` +
          `${gcpImpersonations.length} impersonated service account(s) found.`,
        file: filePath,
        line: gcpImpersonations[0]?.line,
        mitreTechniques: ['T1078.004', 'T1098'],
        remediation:
          'Review service account impersonation chains. ' +
          'Ensure each impersonation is authorized and follows the principle of least privilege.',
        metadata: {
          pluginId,
          category: 'iam_chain',
          provider: 'gcp',
          accounts: gcpImpersonations.map((r) => r.email),
        },
      });
    }
  }

  // ── Azure Identity Mapping ────────────────────────────────────

  for (const ref of azureRefs) {
    const riskFactors: string[] = [];
    let riskScore = 0;

    if (ref.type === 'client-secret') {
      riskFactors.push('client secret credential');
      riskScore += 40;
    }
    if (ref.type === 'connection-string') {
      riskFactors.push('connection string with embedded key');
      riskScore += 35;
    }
    if (ref.type === 'sas-token') {
      riskFactors.push('shared access signature token');
      riskScore += 25;
    }
    if (ref.type === 'managed-identity') {
      riskFactors.push('managed identity endpoint reference');
      riskScore += 15;
    }

    identities.push({
      provider: 'azure',
      identifier: ref.clientId ?? ref.resourceType ?? ref.type,
      type: ref.type,
      file: filePath,
      line: ref.line,
      riskScore: Math.min(riskScore, 100),
      riskFactors,
    });
  }

  // Build Azure managed identity chain
  const azureManagedIdentities = azureRefs.filter((r) => r.type === 'managed-identity');
  const azureClientSecrets = azureRefs.filter((r) => r.type === 'client-secret');

  if (azureManagedIdentities.length > 0 && azureClientSecrets.length > 0) {
    const allAzureIdentities = identities.filter((i) => i.provider === 'azure');
    const maxRisk = allAzureIdentities.length > 0
      ? Math.max(...allAzureIdentities.map((i) => i.riskScore))
      : 0;

    chains.push({
      provider: 'azure',
      identities: allAzureIdentities,
      chainType: 'managed-identity',
      maxRiskScore: maxRisk,
    });

    findings.push({
      ruleId: 'iam-chain-azure-mixed-auth',
      severity: scoreSeverity(maxRisk),
      message:
        `[IAM Chain] Mixed Azure authentication detected in ${filePath}: ` +
        `both managed identity endpoints and client secret credentials found. ` +
        `This may indicate credential confusion or fallback patterns.`,
      file: filePath,
      mitreTechniques: ['T1078.004'],
      remediation:
        'Use a single authentication method per service. ' +
        'Prefer managed identities over client secrets where possible.',
      metadata: {
        pluginId,
        category: 'iam_chain',
        provider: 'azure',
        managedIdentityCount: azureManagedIdentities.length,
        clientSecretCount: azureClientSecrets.length,
      },
    });
  }

  // ── IMDS Findings ─────────────────────────────────────────────

  const credentialFetchPoints = imdsPoints.filter((p) => p.type === 'credential-fetch');
  if (credentialFetchPoints.length > 0) {
    findings.push({
      ruleId: 'imds-credential-fetch',
      severity: 'critical',
      message:
        `[IMDS] Direct credential fetch via metadata service detected in ${filePath}. ` +
        `${credentialFetchPoints.length} credential endpoint(s) accessed across ` +
        `${new Set(credentialFetchPoints.map((p) => p.provider)).size} provider(s).`,
      file: filePath,
      line: credentialFetchPoints[0]?.line,
      mitreTechniques: ['T1552', 'T1078.004'],
      remediation:
        'Remove direct IMDS credential fetch calls. ' +
        'Use cloud SDK credential provider chains which handle IMDS securely with proper token rotation.',
      metadata: {
        pluginId,
        category: 'metadata_service',
        endpoints: credentialFetchPoints.map((p) => ({
          provider: p.provider,
          url: p.url,
          line: p.line,
        })),
      },
    });
  }

  return {
    identities,
    chains,
    imdsAccess: imdsPoints,
    findings,
  };
}

// ─── Utility Functions ──────────────────────────────────────────

/**
 * Convert a numeric risk score (0-100) to a severity level.
 */
function scoreSeverity(score: number): Severity {
  if (score >= 70) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 30) return 'medium';
  if (score >= 10) return 'low';
  return 'info';
}
