/**
 * Plugin Permission System
 *
 * Implements the Trust Level -> Permission mapping defined in PRD Section 5.4.1.
 * Controls which capabilities are available to plugins based on their trust level.
 *
 * Trust Level hierarchy:
 *   builtin    -> all permissions (WIGTN official modules)
 *   verified   -> only declared permissions (signed third-party)
 *   community  -> fs:read, git:read, db:write only (unsigned, restricted)
 *   untrusted  -> BLOCKED (signature mismatch or missing)
 */

import type { TrustLevel, PluginPermission } from '@wigtn/shared';

// ─── Constants ─────────────────────────────────────────────

/**
 * The complete set of all permissions recognized by the plugin system.
 */
const ALL_PERMISSIONS: readonly PluginPermission[] = [
  'fs:read',
  'fs:read-global',
  'git:read',
  'net:outbound',
  'net:listen',
  'process:read',
  'exec:child',
  'db:write',
] as const;

/**
 * The restricted permission set available to community (unsigned) plugins.
 * These are low-risk, read-oriented permissions that cannot exfiltrate data
 * or execute arbitrary processes.
 */
const COMMUNITY_PERMISSIONS: readonly PluginPermission[] = [
  'fs:read',
  'git:read',
  'db:write',
] as const;

// ─── Errors ────────────────────────────────────────────────

/**
 * Thrown when a plugin attempts to use a permission it was not granted.
 */
export class PermissionDeniedError extends Error {
  public readonly permission: PluginPermission;
  public readonly trustLevel: TrustLevel;

  constructor(permission: PluginPermission, trustLevel: TrustLevel) {
    super(
      `Permission denied: "${permission}" is not granted for trust level "${trustLevel}"`
    );
    this.name = 'PermissionDeniedError';
    this.permission = permission;
    this.trustLevel = trustLevel;
  }
}

/**
 * Thrown when an untrusted plugin attempts to execute.
 * Untrusted plugins are completely blocked from running.
 */
export class UntrustedPluginError extends Error {
  public readonly pluginId: string;

  constructor(pluginId: string) {
    super(
      `Plugin "${pluginId}" is untrusted and cannot be executed. ` +
      `Signature verification failed or no signature found.`
    );
    this.name = 'UntrustedPluginError';
    this.pluginId = pluginId;
  }
}

// ─── GrantedPermissions ────────────────────────────────────

/**
 * Resolved set of permissions for a plugin based on its trust level
 * and declared permission requirements.
 *
 * Resolution rules:
 * - builtin:   all permissions are granted regardless of declaration
 * - verified:  only permissions declared in metadata.permissions are granted
 * - community: intersection of declared permissions and COMMUNITY_PERMISSIONS
 * - untrusted: constructor throws UntrustedPluginError (no execution allowed)
 */
export class GrantedPermissions {
  private readonly granted: ReadonlySet<PluginPermission>;
  private readonly trustLevel: TrustLevel;

  constructor(
    pluginId: string,
    trustLevel: TrustLevel,
    declared: readonly PluginPermission[]
  ) {
    this.trustLevel = trustLevel;
    this.granted = new Set(
      this.resolvePermissions(pluginId, trustLevel, declared)
    );
  }

  /**
   * Check whether a specific permission has been granted.
   */
  has(perm: PluginPermission): boolean {
    return this.granted.has(perm);
  }

  /**
   * Assert that a permission is granted, throwing PermissionDeniedError if not.
   * Use this at the boundary of privileged operations inside plugins.
   */
  assert(perm: PluginPermission): void {
    if (!this.granted.has(perm)) {
      throw new PermissionDeniedError(perm, this.trustLevel);
    }
  }

  /**
   * Return a snapshot of all granted permissions (useful for logging/auditing).
   */
  list(): readonly PluginPermission[] {
    return [...this.granted];
  }

  /**
   * Resolve the effective permission set for a given trust level.
   */
  private resolvePermissions(
    pluginId: string,
    trustLevel: TrustLevel,
    declared: readonly PluginPermission[]
  ): PluginPermission[] {
    switch (trustLevel) {
      case 'builtin':
        // Builtin plugins get every permission -- they are part of the core distribution.
        return [...ALL_PERMISSIONS];

      case 'verified':
        // Verified plugins get exactly the permissions they declare in metadata.
        // Invalid/unknown permission strings are silently dropped.
        return declared.filter((p) =>
          (ALL_PERMISSIONS as readonly string[]).includes(p)
        );

      case 'community':
        // Community plugins are restricted to the safe subset, further intersected
        // with what they actually declared.
        return declared.filter((p) =>
          (COMMUNITY_PERMISSIONS as readonly string[]).includes(p)
        );

      case 'untrusted':
        throw new UntrustedPluginError(pluginId);
    }
  }
}
