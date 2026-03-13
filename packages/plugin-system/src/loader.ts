/**
 * PluginLoader - Loads, validates, and indexes plugins.
 *
 * Phase 1 scope:
 *   - Only builtin plugins (no Ed25519 signature verification)
 *   - No dynamic loading from npm / filesystem
 *   - Validation of plugin metadata on registration
 *
 * Future phases will add:
 *   - Phase 2: Worker Thread sandboxing
 *   - Phase 4: Ed25519 signature verification for verified/community plugins
 */

import type { SpearPlugin, PluginMetadata, PluginPermission, Platform } from '@wigtn/shared';

// ─── Errors ────────────────────────────────────────────────

/**
 * Thrown when plugin metadata fails validation.
 */
export class PluginValidationError extends Error {
  public readonly pluginId: string;
  public readonly violations: readonly string[];

  constructor(pluginId: string, violations: string[]) {
    super(
      `Plugin "${pluginId}" has invalid metadata:\n` +
      violations.map((v) => `  - ${v}`).join('\n')
    );
    this.name = 'PluginValidationError';
    this.pluginId = pluginId;
    this.violations = violations;
  }
}

/**
 * Thrown when attempting to register a plugin whose ID is already taken.
 */
export class DuplicatePluginError extends Error {
  public readonly pluginId: string;

  constructor(pluginId: string) {
    super(`Plugin with id "${pluginId}" is already registered`);
    this.name = 'DuplicatePluginError';
    this.pluginId = pluginId;
  }
}

// ─── Validation Helpers ────────────────────────────────────

const VALID_PERMISSIONS: readonly string[] = [
  'fs:read',
  'fs:read-global',
  'git:read',
  'net:outbound',
  'net:listen',
  'process:read',
  'exec:child',
  'db:write',
];

const VALID_PLATFORMS: readonly string[] = ['darwin', 'linux', 'win32'];
const VALID_SEVERITIES: readonly string[] = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_TRUST_LEVELS: readonly string[] = ['builtin', 'verified', 'community', 'untrusted'];

/**
 * Semver-like pattern: major.minor.patch with optional pre-release.
 */
const SEMVER_PATTERN = /^\d+\.\d+\.\d+(?:-[\w.]+)?$/;

/**
 * Plugin ID pattern: lowercase alphanumeric with hyphens, 3-64 chars.
 */
const PLUGIN_ID_PATTERN = /^[a-z][a-z0-9-]{2,63}$/;

// ─── PluginLoader ──────────────────────────────────────────

export class PluginLoader {
  private readonly plugins: Map<string, SpearPlugin> = new Map();

  /**
   * Tag index for fast lookup by tag.
   * Maps tag -> Set of plugin IDs.
   */
  private readonly tagIndex: Map<string, Set<string>> = new Map();

  /**
   * Register a plugin after validating its metadata.
   *
   * @throws PluginValidationError if metadata is invalid
   * @throws DuplicatePluginError if a plugin with the same ID already exists
   */
  register(plugin: SpearPlugin): void {
    this.validateMetadata(plugin.metadata);

    const { id } = plugin.metadata;

    if (this.plugins.has(id)) {
      throw new DuplicatePluginError(id);
    }

    this.plugins.set(id, plugin);

    // Build tag index
    for (const tag of plugin.metadata.tags) {
      let ids = this.tagIndex.get(tag);
      if (!ids) {
        ids = new Set();
        this.tagIndex.set(tag, ids);
      }
      ids.add(id);
    }
  }

  /**
   * Get a plugin by its unique identifier.
   */
  get(id: string): SpearPlugin | undefined {
    return this.plugins.get(id);
  }

  /**
   * Return all registered plugins in registration order.
   */
  getAll(): SpearPlugin[] {
    return [...this.plugins.values()];
  }

  /**
   * Return plugins that have a specific tag.
   * Uses the pre-built tag index for O(1) lookup.
   */
  getByTag(tag: string): SpearPlugin[] {
    const ids = this.tagIndex.get(tag);
    if (!ids) return [];

    const result: SpearPlugin[] = [];
    for (const id of ids) {
      const plugin = this.plugins.get(id);
      if (plugin) result.push(plugin);
    }
    return result;
  }

  /**
   * Return the total number of registered plugins.
   */
  get size(): number {
    return this.plugins.size;
  }

  /**
   * Check whether a plugin with the given ID is registered.
   */
  has(id: string): boolean {
    return this.plugins.has(id);
  }

  /**
   * Validate plugin metadata according to the WIGTN-SPEAR plugin contract.
   * Collects all violations and throws a single error with all of them.
   */
  private validateMetadata(metadata: PluginMetadata): void {
    const violations: string[] = [];

    // id
    if (!metadata.id || typeof metadata.id !== 'string') {
      violations.push('id is required and must be a non-empty string');
    } else if (!PLUGIN_ID_PATTERN.test(metadata.id)) {
      violations.push(
        `id "${metadata.id}" must be lowercase alphanumeric with hyphens, 3-64 chars, starting with a letter`
      );
    }

    // name
    if (!metadata.name || typeof metadata.name !== 'string') {
      violations.push('name is required and must be a non-empty string');
    }

    // version
    if (!metadata.version || typeof metadata.version !== 'string') {
      violations.push('version is required and must be a non-empty string');
    } else if (!SEMVER_PATTERN.test(metadata.version)) {
      violations.push(
        `version "${metadata.version}" must follow semver (e.g. 1.0.0)`
      );
    }

    // author
    if (!metadata.author || typeof metadata.author !== 'string') {
      violations.push('author is required and must be a non-empty string');
    }

    // description
    if (!metadata.description || typeof metadata.description !== 'string') {
      violations.push('description is required and must be a non-empty string');
    }

    // severity
    if (!VALID_SEVERITIES.includes(metadata.severity)) {
      violations.push(
        `severity "${metadata.severity}" must be one of: ${VALID_SEVERITIES.join(', ')}`
      );
    }

    // tags
    if (!Array.isArray(metadata.tags)) {
      violations.push('tags must be an array');
    } else if (metadata.tags.length === 0) {
      violations.push('tags must contain at least one entry');
    }

    // references
    if (!Array.isArray(metadata.references)) {
      violations.push('references must be an array');
    }

    // safeMode
    if (typeof metadata.safeMode !== 'boolean') {
      violations.push('safeMode must be a boolean');
    }

    // requiresNetwork
    if (typeof metadata.requiresNetwork !== 'boolean') {
      violations.push('requiresNetwork must be a boolean');
    }

    // supportedPlatforms
    if (!Array.isArray(metadata.supportedPlatforms)) {
      violations.push('supportedPlatforms must be an array');
    } else {
      for (const p of metadata.supportedPlatforms) {
        if (!VALID_PLATFORMS.includes(p)) {
          violations.push(
            `supportedPlatform "${p}" must be one of: ${VALID_PLATFORMS.join(', ')}`
          );
        }
      }
      if (metadata.supportedPlatforms.length === 0) {
        violations.push('supportedPlatforms must contain at least one platform');
      }
    }

    // permissions
    if (!Array.isArray(metadata.permissions)) {
      violations.push('permissions must be an array');
    } else {
      for (const perm of metadata.permissions) {
        if (!VALID_PERMISSIONS.includes(perm)) {
          violations.push(
            `permission "${perm}" is not a valid PluginPermission`
          );
        }
      }
    }

    // trustLevel
    if (!VALID_TRUST_LEVELS.includes(metadata.trustLevel)) {
      violations.push(
        `trustLevel "${metadata.trustLevel}" must be one of: ${VALID_TRUST_LEVELS.join(', ')}`
      );
    }

    // Cross-field validations
    if (metadata.requiresNetwork && metadata.safeMode) {
      violations.push(
        'a plugin requiring network access (requiresNetwork: true) cannot be safe-mode compatible (safeMode: true)'
      );
    }

    if (
      metadata.requiresNetwork &&
      Array.isArray(metadata.permissions) &&
      !metadata.permissions.includes('net:outbound' as PluginPermission) &&
      !metadata.permissions.includes('net:listen' as PluginPermission)
    ) {
      violations.push(
        'a plugin with requiresNetwork: true must declare "net:outbound" or "net:listen" in permissions'
      );
    }

    if (violations.length > 0) {
      throw new PluginValidationError(metadata.id ?? 'unknown', violations);
    }
  }
}
