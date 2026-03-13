/**
 * @wigtn/plugin-system
 *
 * Plugin lifecycle management for WIGTN-SPEAR attack modules.
 * Handles registration, validation, permission enforcement, and scan execution.
 *
 * Usage:
 *   import { PluginRegistry, GrantedPermissions } from '@wigtn/plugin-system';
 *
 *   const registry = new PluginRegistry();
 *   registry.registerBuiltin([secretScanner, gitMiner]);
 *
 *   for await (const finding of registry.runAll(target, context)) {
 *     // process finding
 *   }
 */

// Permissions
export {
  GrantedPermissions,
  PermissionDeniedError,
  UntrustedPluginError,
} from './permissions.js';

// Loader
export {
  PluginLoader,
  PluginValidationError,
  DuplicatePluginError,
} from './loader.js';

// Registry
export {
  PluginRegistry,
  PluginNotFoundError,
  PluginIncompatibleError,
  PluginSetupError,
} from './registry.js';
