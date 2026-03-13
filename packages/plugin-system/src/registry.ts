/**
 * PluginRegistry - Singleton-style registry managing the full plugin lifecycle.
 *
 * Lifecycle per scan: register -> setup -> scan (yields Findings) -> teardown
 *
 * Design decisions:
 *   - AsyncGenerator-based scanning (FR-006) for streaming results
 *   - Safe mode enforcement at the registry level (FR-070)
 *   - Platform compatibility check before execution
 *   - Graceful teardown even on scan failure (try/finally)
 *
 * Phase 1 limitations:
 *   - All plugins run in the main thread (Worker sandboxing deferred to Phase 2)
 *   - Only builtin plugins (signature verification deferred to Phase 4)
 */

import { platform as osPlatform } from 'node:os';

import type {
  SpearPlugin,
  PluginMetadata,
  ScanTarget,
  PluginContext,
  Finding,
  Platform,
} from '@wigtn/shared';

import { PluginLoader } from './loader.js';

// ─── Errors ────────────────────────────────────────────────

/**
 * Thrown when a requested plugin is not found in the registry.
 */
export class PluginNotFoundError extends Error {
  public readonly pluginId: string;

  constructor(pluginId: string) {
    super(`Plugin not found: "${pluginId}"`);
    this.name = 'PluginNotFoundError';
    this.pluginId = pluginId;
  }
}

/**
 * Thrown when a plugin is incompatible with the current scan context.
 */
export class PluginIncompatibleError extends Error {
  public readonly pluginId: string;
  public readonly reason: string;

  constructor(pluginId: string, reason: string) {
    super(`Plugin "${pluginId}" is incompatible: ${reason}`);
    this.name = 'PluginIncompatibleError';
    this.pluginId = pluginId;
    this.reason = reason;
  }
}

/**
 * Thrown when plugin.setup() fails. Wraps the original cause.
 */
export class PluginSetupError extends Error {
  public readonly pluginId: string;
  public readonly cause: unknown;

  constructor(pluginId: string, cause: unknown) {
    const causeMsg = cause instanceof Error ? cause.message : String(cause);
    super(`Plugin "${pluginId}" failed during setup: ${causeMsg}`);
    this.name = 'PluginSetupError';
    this.pluginId = pluginId;
    this.cause = cause;
  }
}

// ─── PluginRegistry ────────────────────────────────────────

export class PluginRegistry {
  private readonly loader: PluginLoader;

  constructor() {
    this.loader = new PluginLoader();
  }

  /**
   * Register an array of builtin plugins.
   * Each plugin is validated by the PluginLoader on registration.
   *
   * Plugins that fail validation are logged and skipped rather than
   * aborting the entire registration batch -- consistent with the PRD
   * "malformed rule" scenario (skip with warning, continue).
   */
  registerBuiltin(
    plugins: SpearPlugin[],
    logger?: { warn(msg: string, data?: Record<string, unknown>): void }
  ): void {
    for (const plugin of plugins) {
      try {
        this.loader.register(plugin);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (logger) {
          logger.warn(`Skipping plugin registration: ${msg}`, {
            pluginId: plugin.metadata?.id ?? 'unknown',
          });
        }
        // Continue registering remaining plugins
      }
    }
  }

  /**
   * Run a scan with a specific plugin, yielding Findings as they are produced.
   *
   * Lifecycle:
   *   1. Lookup plugin by ID
   *   2. Validate mode compatibility (safe mode check)
   *   3. Validate platform compatibility
   *   4. Call setup() if defined
   *   5. Yield findings from scan()
   *   6. Call teardown() in finally block (always runs)
   *
   * @throws PluginNotFoundError - plugin ID not registered
   * @throws PluginIncompatibleError - mode or platform mismatch
   * @throws PluginSetupError - setup() threw an error
   */
  async *runPlugin(
    pluginId: string,
    target: ScanTarget,
    context: PluginContext
  ): AsyncGenerator<Finding> {
    const plugin = this.loader.get(pluginId);
    if (!plugin) {
      throw new PluginNotFoundError(pluginId);
    }

    this.assertCompatibility(plugin, context);

    // Lifecycle: setup
    if (plugin.setup) {
      try {
        await plugin.setup(context);
      } catch (err) {
        throw new PluginSetupError(pluginId, err);
      }
    }

    // Lifecycle: scan -> teardown (teardown always runs)
    try {
      yield* plugin.scan(target, context);
    } finally {
      if (plugin.teardown) {
        try {
          await plugin.teardown(context);
        } catch (err) {
          // Log teardown errors but do not propagate -- findings already yielded
          // are still valid. This follows the principle that teardown failures
          // should not discard scan results.
          context.logger.warn(
            `Plugin "${pluginId}" teardown failed: ${err instanceof Error ? err.message : String(err)}`,
            { pluginId }
          );
        }
      }
    }
  }

  /**
   * Run a scan across all applicable plugins, yielding Findings from each.
   *
   * "Applicable" means:
   *   - Compatible with the current scan mode (safe/aggressive)
   *   - Compatible with the current OS platform
   *
   * Plugins that fail setup or throw during scan are caught, logged,
   * and skipped -- remaining plugins continue executing.
   */
  async *runAll(
    target: ScanTarget,
    context: PluginContext
  ): AsyncGenerator<Finding> {
    const plugins = this.loader.getAll();

    for (const plugin of plugins) {
      // Skip incompatible plugins silently
      if (!this.isCompatible(plugin, context)) {
        context.logger.debug(
          `Skipping plugin "${plugin.metadata.id}": incompatible with current context`,
          {
            pluginId: plugin.metadata.id,
            mode: context.mode,
            platform: osPlatform(),
          }
        );
        continue;
      }

      try {
        yield* this.runPlugin(plugin.metadata.id, target, context);
      } catch (err) {
        // Log and continue to the next plugin
        context.logger.error(
          `Plugin "${plugin.metadata.id}" failed: ${err instanceof Error ? err.message : String(err)}`,
          { pluginId: plugin.metadata.id }
        );
      }
    }
  }

  /**
   * Run a scan with all plugins matching a specific tag.
   * Follows the same error-resilience strategy as runAll().
   */
  async *runByTag(
    tag: string,
    target: ScanTarget,
    context: PluginContext
  ): AsyncGenerator<Finding> {
    const plugins = this.loader.getByTag(tag);

    for (const plugin of plugins) {
      if (!this.isCompatible(plugin, context)) {
        context.logger.debug(
          `Skipping plugin "${plugin.metadata.id}" (tag: ${tag}): incompatible with current context`,
          { pluginId: plugin.metadata.id, tag }
        );
        continue;
      }

      try {
        yield* this.runPlugin(plugin.metadata.id, target, context);
      } catch (err) {
        context.logger.error(
          `Plugin "${plugin.metadata.id}" failed: ${err instanceof Error ? err.message : String(err)}`,
          { pluginId: plugin.metadata.id, tag }
        );
      }
    }
  }

  /**
   * List metadata for all registered plugins.
   * Useful for CLI `spear plugin list` and dashboard API.
   */
  list(): PluginMetadata[] {
    return this.loader.getAll().map((p) => p.metadata);
  }

  /**
   * Get a specific plugin by ID (delegates to loader).
   */
  get(pluginId: string): SpearPlugin | undefined {
    return this.loader.get(pluginId);
  }

  /**
   * Check if a plugin is registered.
   */
  has(pluginId: string): boolean {
    return this.loader.has(pluginId);
  }

  /**
   * Return the total number of registered plugins.
   */
  get size(): number {
    return this.loader.size;
  }

  // ─── Private Helpers ───────────────────────────────────────

  /**
   * Assert that a plugin is compatible with the current context.
   * Throws PluginIncompatibleError on the first incompatibility found.
   */
  private assertCompatibility(
    plugin: SpearPlugin,
    context: PluginContext
  ): void {
    const { metadata } = plugin;

    // Safe mode check: plugins that are NOT safe-mode compatible
    // cannot run when the scan mode is 'safe'.
    if (context.mode === 'safe' && !metadata.safeMode) {
      throw new PluginIncompatibleError(
        metadata.id,
        `plugin requires aggressive mode (safeMode: false), but current mode is "safe"`
      );
    }

    // Platform check
    const currentPlatform = osPlatform() as Platform;
    if (
      metadata.supportedPlatforms.length > 0 &&
      !metadata.supportedPlatforms.includes(currentPlatform)
    ) {
      throw new PluginIncompatibleError(
        metadata.id,
        `plugin supports platforms [${metadata.supportedPlatforms.join(', ')}], ` +
        `but current platform is "${currentPlatform}"`
      );
    }
  }

  /**
   * Non-throwing compatibility check (used for filtering in runAll/runByTag).
   */
  private isCompatible(plugin: SpearPlugin, context: PluginContext): boolean {
    const { metadata } = plugin;

    if (context.mode === 'safe' && !metadata.safeMode) {
      return false;
    }

    const currentPlatform = osPlatform() as Platform;
    if (
      metadata.supportedPlatforms.length > 0 &&
      !metadata.supportedPlatforms.includes(currentPlatform)
    ) {
      return false;
    }

    return true;
  }
}
