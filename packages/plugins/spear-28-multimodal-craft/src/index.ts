/**
 * SPEAR-28: Multimodal Craft Plugin
 *
 * Stub plugin for generating multimodal adversarial payloads
 * (audio, document, image) for Judgement Day Arena scenarios.
 *
 * All generation functions are stubs that throw until their
 * respective backend libraries are installed and configured.
 */

import type {
  SpearPlugin,
  PluginMetadata,
  ScanTarget,
  PluginContext,
  Finding,
} from '@wigtn/shared';

export { AudioGeneratorOptions, generateAudio } from './audio-generator.js';
export { DocumentCraftOptions, craftDocument } from './document-crafter.js';
export { ImageManipulatorOptions, manipulateImage } from './image-manipulator.js';

// ─── Plugin Metadata ─────────────────────────────────────────

const metadata: PluginMetadata = {
  id: 'spear-28-multimodal-craft',
  name: 'Multimodal Craft',
  version: '0.1.0',
  author: 'WIGTN Crew',
  description:
    'Generates multimodal adversarial payloads (audio, document, image) for arena scenarios',
  severity: 'info',
  tags: ['arena', 'multimodal', 'audio', 'image', 'video'],
  references: [],
  safeMode: true,
  requiresNetwork: true,
  supportedPlatforms: ['darwin', 'linux', 'win32'],
  permissions: [],
  trustLevel: 'builtin',
};

// ─── Plugin Implementation ───────────────────────────────────

const plugin: SpearPlugin = {
  metadata,

  async *scan(_target: ScanTarget, _context: PluginContext): AsyncGenerator<Finding> {
    yield {
      ruleId: 'spear-28-multimodal-craft',
      severity: 'info',
      message:
        'Multimodal payload generation is planned for future implementation. ' +
        'Audio (TTS), document (PDF/DOCX), and image (canvas) backends are not yet integrated.',
    };
  },
};

export default plugin;
