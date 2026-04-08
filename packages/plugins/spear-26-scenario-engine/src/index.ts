/**
 * SPEAR-26: Scenario Engine Plugin
 *
 * Judgement Day AI Red Team Arena competition tool.
 * Generates domain-contextualized adversarial attacks across 8 scenarios
 * targeting 6 frontier AI models.
 *
 * Track 1 (Action Induction): Force AI to select a prohibited action
 * Track 2 (Action Suppression): Prevent AI from taking the correct action
 *
 * MITRE ATLAS: AML.T0051 (LLM Prompt Injection)
 * MITRE ATLAS: AML.T0054 (LLM Jailbreak)
 */

import type {
  SpearPlugin,
  PluginMetadata,
  PluginContext,
  ScanTarget,
  Finding,
} from '@wigtn/shared';

import { SCENARIOS, getScenario, getActiveScenarios } from './scenarios.js';
import { recommendStrategies, mapStrategyToPayloads } from './strategy-mapper.js';
import type { AttackStrategy } from './strategy-mapper.js';
import { generateAttack } from './attack-generator.js';
import type { AttackGeneratorOptions } from './attack-generator.js';
import { formatSubmission, validateSubmission } from './submission-formatter.js';

// ─── Plugin Metadata ───────────────────────────────────────

const metadata: PluginMetadata = {
  id: 'spear-26-scenario-engine',
  name: 'Scenario Engine',
  version: '0.1.0',
  author: 'WIGTN Crew',
  description:
    'Judgement Day AI Red Team Arena scenario engine. Generates domain-contextualized ' +
    'adversarial attacks for competition scenarios across medical, industrial, ' +
    'cybersecurity, and aviation domains.',
  severity: 'critical',
  tags: ['arena', 'judgement-day', 'red-team'],
  references: [
    'https://www.judgementday.cc',
    'https://atlas.mitre.org/techniques/AML.T0051',
    'https://atlas.mitre.org/techniques/AML.T0054',
  ],
  safeMode: true,
  requiresNetwork: false,
  supportedPlatforms: ['darwin', 'linux', 'win32'],
  permissions: [],
  trustLevel: 'builtin',
};

// ─── Plugin Implementation ─────────────────────────────────

const plugin: SpearPlugin = {
  metadata,

  async setup(_context: PluginContext): Promise<void> {
    // No setup needed — all scenarios are statically defined
  },

  async *scan(
    _target: ScanTarget,
    context: PluginContext,
  ): AsyncGenerator<Finding> {
    const activeScenarios = getActiveScenarios();

    context.logger.info(`[spear-26] Scanning ${activeScenarios.length} active scenarios`);

    for (const scenario of activeScenarios) {
      const strategies = recommendStrategies(scenario);
      const topStrategy = strategies[0];

      const channelList = scenario.availableChannels.join(', ');
      const strategyList = strategies
        .slice(0, 3)
        .map((s) => `${s.strategy} (score: ${s.score})`)
        .join('; ');

      const payloadIds = topStrategy
        ? mapStrategyToPayloads(topStrategy.strategy, scenario.domain)
        : [];

      yield {
        ruleId: `spear-26/${scenario.id}`,
        severity: 'critical',
        message:
          `Arena scenario: ${scenario.name} [${scenario.track}] — ` +
          `Target action: ${scenario.targetAction} | ` +
          `Channels: ${channelList} | ` +
          `Top strategies: ${strategyList} | ` +
          `Recommended payloads: ${payloadIds.length} from spear-23`,
        confidence: 'high',
        mitreTechniques: ['AML.T0051', 'AML.T0054'],
        metadata: {
          scenarioId: scenario.id,
          track: scenario.track,
          wave: scenario.wave,
          domain: scenario.domain,
          targetAction: scenario.targetAction,
          availableChannels: scenario.availableChannels,
          targetModels: scenario.targetModels,
          recommendedStrategies: strategies.slice(0, 3),
          recommendedPayloadIds: payloadIds,
          context: scenario.context,
        },
      };

      // Generate attack findings for each channel
      for (const channel of scenario.availableChannels) {
        if (!topStrategy) continue;

        const attack = generateAttack(scenario, {
          strategy: topStrategy.strategy,
          channel,
        });

        yield {
          ruleId: `spear-26/${scenario.id}/${channel}`,
          severity: 'high',
          message:
            `Attack vector: ${scenario.name} via ${channel} channel — ` +
            `Strategy: ${attack.strategy} | ` +
            `Confidence: ${attack.confidence} | ` +
            `Payload length: ${attack.payload.length} chars`,
          confidence: attack.confidence === 'HIGH' ? 'high' : attack.confidence === 'MEDIUM' ? 'medium' : 'low',
          mitreTechniques: ['AML.T0051'],
          metadata: {
            scenarioId: scenario.id,
            channel,
            strategy: attack.strategy,
            attackConfidence: attack.confidence,
            payloadPreview: attack.payload.slice(0, 200) + '...',
            reasoning: attack.reasoning,
            sourceModules: attack.sourceModules,
          },
        };
      }
    }

    // Summary finding for inactive (Wave 2) scenarios
    const inactiveScenarios = SCENARIOS.filter((s) => !s.active);
    if (inactiveScenarios.length > 0) {
      yield {
        ruleId: 'spear-26/wave-2-pending',
        severity: 'info',
        message:
          `${inactiveScenarios.length} Wave 2 scenarios pending activation: ` +
          inactiveScenarios.map((s) => s.id).join(', ') +
          ' — Opens April 27, 2026',
        confidence: 'high',
        metadata: {
          wave2Scenarios: inactiveScenarios.map((s) => ({
            id: s.id,
            domain: s.domain,
            track: s.track,
          })),
          activationDate: '2026-04-27',
        },
      };
    }
  },

  async teardown(_context: PluginContext): Promise<void> {
    // No teardown needed
  },
};

// ─── Exports ───────────────────────────────────────────────

export default plugin;

export {
  SCENARIOS,
  getScenario,
  getActiveScenarios,
  recommendStrategies,
  mapStrategyToPayloads,
  generateAttack,
  formatSubmission,
  validateSubmission,
};

export type { AttackStrategy, AttackGeneratorOptions };
