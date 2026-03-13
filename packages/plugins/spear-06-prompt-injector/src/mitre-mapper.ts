/**
 * MITRE ATT&CK / ATLAS Mapper for Prompt Injection Findings
 *
 * Maps prompt injection payload categories to relevant MITRE technique IDs.
 * Combines both traditional ATT&CK techniques and AI-specific ATLAS mappings.
 *
 * References:
 *   - MITRE ATT&CK: https://attack.mitre.org/techniques/
 *   - MITRE ATLAS: https://atlas.mitre.org/techniques/
 */

import type { PayloadCategory } from './payloads/types.js';

// ─── MITRE Technique Definitions ─────────────────────────────

/**
 * MITRE technique metadata for display and reporting.
 */
export interface MitreTechnique {
  id: string;
  name: string;
  source: 'ATT&CK' | 'ATLAS';
  url: string;
}

/**
 * Full technique registry with human-readable metadata.
 *
 * ATT&CK techniques (traditional cyber):
 *   T1059   - Command and Scripting Interpreter
 *   T1005   - Data from Local System
 *   T1567   - Exfiltration Over Web Service
 *   T1562   - Impair Defenses
 *   T1027   - Obfuscated Files or Information
 *   T1204   - User Execution
 *   T1071   - Application Layer Protocol
 *   T1548   - Abuse Elevation Control Mechanism
 *   T1078   - Valid Accounts
 *   T1557   - Adversary-in-the-Middle
 *
 * ATLAS techniques (AI-specific):
 *   AML.T0051 - LLM Prompt Injection
 *   AML.T0054 - LLM Jailbreak
 *   AML.T0040 - ML Model Inference API Access
 *   AML.T0043 - Craft Adversarial Data
 *   AML.T0048 - Command and Control via AI Agent
 *   AML.T0025 - Exfiltration via ML Inference API
 *   AML.T0047 - ML Supply Chain Compromise
 */
export const MITRE_TECHNIQUES: Record<string, MitreTechnique> = {
  'T1059': {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1059/',
  },
  'T1005': {
    id: 'T1005',
    name: 'Data from Local System',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1005/',
  },
  'T1567': {
    id: 'T1567',
    name: 'Exfiltration Over Web Service',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1567/',
  },
  'T1562': {
    id: 'T1562',
    name: 'Impair Defenses',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1562/',
  },
  'T1027': {
    id: 'T1027',
    name: 'Obfuscated Files or Information',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1027/',
  },
  'T1204': {
    id: 'T1204',
    name: 'User Execution',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1204/',
  },
  'T1071': {
    id: 'T1071',
    name: 'Application Layer Protocol',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1071/',
  },
  'T1548': {
    id: 'T1548',
    name: 'Abuse Elevation Control Mechanism',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1548/',
  },
  'T1078': {
    id: 'T1078',
    name: 'Valid Accounts',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1078/',
  },
  'T1557': {
    id: 'T1557',
    name: 'Adversary-in-the-Middle',
    source: 'ATT&CK',
    url: 'https://attack.mitre.org/techniques/T1557/',
  },
  'AML.T0051': {
    id: 'AML.T0051',
    name: 'LLM Prompt Injection',
    source: 'ATLAS',
    url: 'https://atlas.mitre.org/techniques/AML.T0051/',
  },
  'AML.T0054': {
    id: 'AML.T0054',
    name: 'LLM Jailbreak',
    source: 'ATLAS',
    url: 'https://atlas.mitre.org/techniques/AML.T0054/',
  },
  'AML.T0040': {
    id: 'AML.T0040',
    name: 'ML Model Inference API Access',
    source: 'ATLAS',
    url: 'https://atlas.mitre.org/techniques/AML.T0040/',
  },
  'AML.T0043': {
    id: 'AML.T0043',
    name: 'Craft Adversarial Data',
    source: 'ATLAS',
    url: 'https://atlas.mitre.org/techniques/AML.T0043/',
  },
  'AML.T0048': {
    id: 'AML.T0048',
    name: 'Command and Control via AI Agent',
    source: 'ATLAS',
    url: 'https://atlas.mitre.org/techniques/AML.T0048/',
  },
  'AML.T0025': {
    id: 'AML.T0025',
    name: 'Exfiltration via ML Inference API',
    source: 'ATLAS',
    url: 'https://atlas.mitre.org/techniques/AML.T0025/',
  },
  'AML.T0047': {
    id: 'AML.T0047',
    name: 'ML Supply Chain Compromise',
    source: 'ATLAS',
    url: 'https://atlas.mitre.org/techniques/AML.T0047/',
  },
};

// ─── Category -> MITRE Mapping ───────────────────────────────

/**
 * Maps a payload category to an array of MITRE technique IDs.
 *
 * Each category maps to both traditional ATT&CK and AI-specific ATLAS
 * techniques that are relevant to that class of prompt injection attack.
 *
 * @param category - The payload category to map.
 * @returns Array of MITRE technique ID strings.
 */
export function mapToMitre(category: PayloadCategory): string[] {
  switch (category) {
    case 'direct_injection':
      return ['AML.T0051', 'AML.T0043', 'T1204'];

    case 'indirect_injection':
      return ['AML.T0051', 'AML.T0043', 'AML.T0047', 'T1557'];

    case 'jailbreak':
      return ['AML.T0054', 'T1562', 'T1548'];

    case 'data_exfil':
      return ['AML.T0025', 'T1005', 'T1567'];

    case 'code_exec':
      return ['AML.T0048', 'T1059', 'T1204'];

    case 'prompt_leak':
      return ['AML.T0040', 'T1005', 'AML.T0051'];

    case 'context_manipulation':
      return ['AML.T0051', 'AML.T0043', 'T1027'];

    case 'privilege_escalation':
      return ['AML.T0048', 'T1548', 'T1078'];

    default: {
      // Exhaustive check
      const _exhaustive: never = category;
      return ['AML.T0051'];
    }
  }
}

/**
 * Get full technique metadata for a MITRE ID.
 *
 * @param id - The MITRE technique ID (e.g., 'AML.T0051', 'T1059').
 * @returns The technique metadata, or undefined if the ID is unknown.
 */
export function getMitreTechnique(id: string): MitreTechnique | undefined {
  return MITRE_TECHNIQUES[id];
}

/**
 * Get all MITRE technique metadata for a payload category.
 *
 * Convenience function that combines mapToMitre() and getMitreTechnique().
 *
 * @param category - The payload category.
 * @returns Array of technique metadata objects (unknown IDs are filtered out).
 */
export function getMitreTechniquesForCategory(
  category: PayloadCategory,
): MitreTechnique[] {
  const ids = mapToMitre(category);
  const techniques: MitreTechnique[] = [];

  for (const id of ids) {
    const tech = MITRE_TECHNIQUES[id];
    if (tech) {
      techniques.push(tech);
    }
  }

  return techniques;
}
