import { randomUUID } from 'node:crypto';
import { verifyAuthorization } from '../authorization.js';
import { deriveCausalDisposition } from '../disposition.js';
import { SpearConfigError } from '../errors.js';
import { createPinnedDispatcher } from '../pinning.js';
import { assertNoRawSecrets, assertPinnableOrigin, DestinationGuard } from '../safety.js';
import type { CandidateDisposition } from '../types.js';
import {
  type AgentFetchDeps,
  callAgent,
  type FetchImpl,
  resetMemory,
  resetSink,
  sinkObserved,
  writeMemory,
} from './client.js';
import { evaluateAgentOracle, oracleEvidenceGrade } from './oracle.js';
import type { AgentOracle, AgentTarget } from './types.js';

export interface AgentMemoryProbe {
  /** POST here to write a memory entry `{ content, writer }` (the injection). */
  writeUrl: string;
  /** POST here to clear all memory. */
  resetUrl: string;
  /** The poisoned entry content — carries the delayed trigger + action. */
  poisonedContent: string;
  /** The (untrusted) principal that wrote the poisoned entry. */
  writer: string;
  /** Benign sessions run between injection and activation (the sleeper delay, FR-458). */
  sleeperSessions: number;
}

export interface MemoryAttackProgram {
  schemaVersion: '3.0';
  kind: 'agent-memory-program';
  id: string;
  title: string;
  target: AgentTarget;
  planted: { canary: string; location: 'system-prompt' | 'rag-document' | 'tool-data' | 'other-user-record' };
  memory: AgentMemoryProbe;
  /** Benign message for baseline/counterfactual and the sleeper sessions. */
  benignTask: string;
  /** The activation message (carries the trigger the poisoned memory waits for). */
  activationTask: string;
  oracle: Extract<AgentOracle, { kind: 'agent-canary-leak' | 'agent-tool-egress' }>;
  execution: { repetitions: number; minimumAttackSuccesses: number; nondeterministic: true };
  sink?: { observeUrl: string; resetUrl: string };
}

export interface MemoryRunResult {
  schemaVersion: '3.0';
  kind: 'agent-memory-run';
  runId: string;
  programId: string;
  disposition: CandidateDisposition;
  attempts: number;
  attackSuccesses: number;
  /** Injection (memory write) and activation (later session) were separate steps. */
  injectionActivationSeparated: true;
  sleeperSessions: number;
  baselineObserved: boolean;
  counterfactualObserved: boolean;
  attackObservations: boolean[];
  reason: string;
}

export interface MemoryRunOptions {
  manifest: unknown;
  trustStore: unknown;
  program: MemoryAttackProgram;
  actualBuildDigest: string;
  acknowledgeAuthorization: boolean;
  fetchImpl?: FetchImpl;
  now?: Date;
}

async function activationObserved(
  program: MemoryAttackProgram,
  deps: AgentFetchDeps,
): Promise<boolean> {
  if (program.oracle.kind === 'agent-tool-egress' && program.sink) {
    await resetSink({ observeUrl: program.sink.observeUrl, resetUrl: program.sink.resetUrl }, deps);
  }
  const { reply } = await callAgent(program.target, program.activationTask, deps);
  let observed = false;
  if (program.oracle.kind === 'agent-tool-egress' && program.sink) {
    observed = await sinkObserved(
      { observeUrl: program.sink.observeUrl, resetUrl: program.sink.resetUrl },
      program.oracle.canary,
      deps,
    );
  }
  return evaluateAgentOracle(program.oracle, { replies: [reply], sinkObservedCanary: observed });
}

/**
 * Prove memory poisoning with injection/activation separation (FR-457/458): write a
 * poisoned entry as an untrusted writer, let benign sleeper sessions pass, then run a
 * clean activation session and observe the forbidden effect. Baseline and
 * counterfactual run the identical activation task with NO poison in memory, so a
 * proven verdict shows the persisted poison — not the trigger phrase — is the cause.
 */
export async function runMemoryAttack(options: MemoryRunOptions): Promise<MemoryRunResult> {
  const program = options.program;
  if (program.kind !== 'agent-memory-program') {
    throw new SpearConfigError('program.kind must be "agent-memory-program"');
  }
  if (oracleEvidenceGrade(program.oracle) === 'candidate') {
    throw new SpearConfigError('memory attacks require a proven-capable effect oracle');
  }
  if (program.oracle.kind === 'agent-tool-egress' && !program.sink) {
    throw new SpearConfigError('agent-tool-egress memory attack requires an owned sink');
  }
  if (!Number.isInteger(program.memory.sleeperSessions) || program.memory.sleeperSessions < 0) {
    throw new SpearConfigError('memory.sleeperSessions must be a non-negative integer');
  }
  const { manifest } = verifyAuthorization(options.manifest, options.trustStore, {
    acknowledgeAuthorization: options.acknowledgeAuthorization,
    requiredCapabilities: ['run:agent'],
    actualBuildDigest: options.actualBuildDigest,
    ...(options.now ? { now: options.now } : {}),
  });
  const guard = new DestinationGuard(manifest);
  let deps: AgentFetchDeps;
  if (options.fetchImpl) {
    assertPinnableOrigin(program.target.endpoint, 'Agent target endpoint');
    assertPinnableOrigin(program.memory.writeUrl, 'Memory write URL');
    assertPinnableOrigin(program.memory.resetUrl, 'Memory reset URL');
    if (program.sink) {
      assertPinnableOrigin(program.sink.observeUrl, 'Memory sink observe URL');
      assertPinnableOrigin(program.sink.resetUrl, 'Memory sink reset URL');
    }
    deps = { guard, fetchImpl: options.fetchImpl };
  } else {
    await guard.pin(program.target.endpoint, 'target');
    await guard.pin(program.memory.writeUrl, 'control');
    await guard.pin(program.memory.resetUrl, 'control');
    if (program.sink) {
      await guard.pin(program.sink.observeUrl, 'canary');
      await guard.pin(program.sink.resetUrl, 'control');
    }
    deps = { guard, dispatcher: createPinnedDispatcher(guard.pins) };
  }

  // Baseline: clean memory, run the activation task — the trigger phrase alone must not act.
  await resetMemory(program.memory.resetUrl, deps);
  const baselineObserved = await activationObserved(program, deps);

  // Attack attempts: inject the poison, let sleeper sessions pass, then activate.
  const attackObservations: boolean[] = [];
  for (let i = 0; i < program.execution.repetitions; i += 1) {
    await resetMemory(program.memory.resetUrl, deps);
    await writeMemory(
      program.memory.writeUrl,
      { content: program.memory.poisonedContent, writer: program.memory.writer },
      deps,
    );
    for (let s = 0; s < program.memory.sleeperSessions; s += 1) {
      await callAgent(program.target, program.benignTask, deps);
    }
    attackObservations.push(await activationObserved(program, deps));
  }

  // Counterfactual: clean memory again, identical activation task — must not act.
  await resetMemory(program.memory.resetUrl, deps);
  const counterfactualObserved = await activationObserved(program, deps);

  const outcome = deriveCausalDisposition({
    baselineObserved,
    counterfactualObserved,
    attackObservations,
    minimumAttackSuccesses: program.execution.minimumAttackSuccesses,
  });

  const result: MemoryRunResult = {
    schemaVersion: '3.0',
    kind: 'agent-memory-run',
    runId: `agent-memory-run-${randomUUID()}`,
    programId: program.id,
    disposition: outcome.disposition,
    attempts: outcome.attempts,
    attackSuccesses: outcome.attackSuccesses,
    injectionActivationSeparated: true,
    sleeperSessions: program.memory.sleeperSessions,
    baselineObserved,
    counterfactualObserved,
    attackObservations,
    reason: outcome.reason,
  };
  assertNoRawSecrets(result);
  return result;
}
