import { randomUUID } from 'node:crypto';
import { sha256Digest } from './crypto.js';
import { SpearConfigError, SpearExecutionError } from './errors.js';
import type {
  AssetFixture,
  PrincipalFixture,
  TwinDefinition,
  TwinSnapshot,
} from './types.js';

export interface StateController {
  snapshot(): Promise<Record<string, unknown>>;
  reset(): Promise<void>;
}

/**
 * A state controller for attacks whose forbidden effect is observed entirely in
 * the HTTP response (a `response-contains` oracle), where no independent state
 * mutation needs to be snapshot or reset. Its snapshot is constant, so Twin
 * reset integrity holds trivially. It must NOT be used for `state-path` oracles:
 * those require a real control channel that observes the mutated state.
 */
export class ConstantStateController implements StateController {
  async snapshot(): Promise<Record<string, unknown>> {
    return {};
  }

  async reset(): Promise<void> {
    // No mutable state to restore.
  }
}

export function validateTwinDefinition(definition: TwinDefinition): TwinDefinition {
  if (definition.schemaVersion !== '3.0' || definition.kind !== 'attack-twin') {
    throw new SpearConfigError('Twin definition must use SPEAR v3');
  }
  const principalIds = new Set(definition.principals.map((item) => item.id));
  if (principalIds.size !== definition.principals.length) {
    throw new SpearConfigError('Twin principal IDs must be unique');
  }
  const roles = new Set(definition.principals.map((item) => item.role));
  if (!roles.has('anonymous') || !roles.has('privileged')) {
    throw new SpearConfigError('Twin requires anonymous and privileged principals');
  }
  const userPrincipals = definition.principals.filter((item) => item.role === 'user');
  if (userPrincipals.length < 2) {
    throw new SpearConfigError('Twin requires at least two user principals');
  }
  if (new Set(definition.principals.map((item) => item.tenantId)).size < 2) {
    throw new SpearConfigError('Twin requires at least two tenants');
  }
  const canaries = new Set<string>();
  for (const asset of definition.assets) {
    if (!principalIds.has(asset.ownerPrincipalId)) {
      throw new SpearConfigError(`Asset ${asset.id} has an unknown owner`);
    }
    if (canaries.has(asset.canary)) {
      throw new SpearConfigError('Asset canaries must be unique');
    }
    canaries.add(asset.canary);
  }
  if (definition.control !== undefined) {
    const { resetUrl, snapshotUrl } = definition.control;
    if (typeof resetUrl !== 'string' || resetUrl.trim() === '') {
      throw new SpearConfigError('Twin control.resetUrl must be a non-empty string');
    }
    if (typeof snapshotUrl !== 'string' || snapshotUrl.trim() === '') {
      throw new SpearConfigError('Twin control.snapshotUrl must be a non-empty string');
    }
  }
  return definition;
}

export class AttackTwin {
  readonly definition: TwinDefinition;
  readonly #stateController: StateController;
  #baseline?: TwinSnapshot;

  constructor(definition: TwinDefinition, stateController: StateController) {
    this.definition = validateTwinDefinition(definition);
    this.#stateController = stateController;
  }

  principal(id: string): PrincipalFixture {
    const principal = this.definition.principals.find((item) => item.id === id);
    if (!principal) throw new SpearConfigError(`Unknown Twin principal: ${id}`);
    return principal;
  }

  asset(id: string): AssetFixture {
    const asset = this.definition.assets.find((item) => item.id === id);
    if (!asset) throw new SpearConfigError(`Unknown Twin asset: ${id}`);
    return asset;
  }

  async prepare(now = new Date()): Promise<TwinSnapshot> {
    await this.#stateController.reset();
    const state = await this.#stateController.snapshot();
    const snapshot: TwinSnapshot = {
      schemaVersion: '3.0',
      kind: 'twin-snapshot',
      snapshotId: `snapshot-${randomUUID()}`,
      digest: sha256Digest(state),
      createdAt: now.toISOString(),
      state,
    };
    this.#baseline = snapshot;
    return structuredClone(snapshot);
  }

  async resetAndVerify(): Promise<TwinSnapshot> {
    if (!this.#baseline) {
      throw new SpearExecutionError('Twin has not been prepared');
    }
    await this.#stateController.reset();
    const state = await this.#stateController.snapshot();
    const digest = sha256Digest(state);
    if (digest !== this.#baseline.digest) {
      throw new SpearExecutionError(
        `Twin reset integrity mismatch: expected ${this.#baseline.digest}, got ${digest}`,
      );
    }
    return {
      ...this.#baseline,
      state,
    };
  }

  async state(): Promise<Record<string, unknown>> {
    return this.#stateController.snapshot();
  }
}
