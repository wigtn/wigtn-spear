import { randomUUID } from 'node:crypto';
import { verifyAuthorization } from '../authorization.js';
import { sha256Digest } from '../crypto.js';
import { deriveCausalDisposition } from '../disposition.js';
import { SpearConfigError } from '../errors.js';
import { createPinnedDispatcher } from '../pinning.js';
import { assertNoRawSecrets, assertPinnableOrigin, DestinationGuard } from '../safety.js';
import { validateAgentAttackProgram } from '../validation.js';
import {
  type AgentFetchDeps,
  callAgent,
  directAttackerRequest,
  type FetchImpl,
  readWitnessValue,
  resetSink,
  setCarrier,
  sinkObserved,
} from './client.js';
import { backendStateMoved, evaluateAgentOracle, oracleEvidenceGrade } from './oracle.js';
import type {
  AgentAttackProgram,
  AgentMessageSpec,
  AgentProjectOnlyResult,
  AgentRunResult,
  AgentSequenceReceipt,
  AgentTurn,
} from './types.js';

export interface AgentRunOptions {
  /** Raw manifest — its Ed25519 signature and scope are verified before any network access. */
  manifest: unknown;
  trustStore: unknown;
  /** Raw program — re-validated here so the engine never runs a malformed artifact. */
  program: unknown;
  /** The build digest actually deployed (from the target profile); must match the manifest. */
  actualBuildDigest: string;
  acknowledgeAuthorization: boolean;
  fetchImpl?: FetchImpl;
  now?: Date;
}

function redact(text: string, tokens: string[]): string {
  let out = text;
  for (const token of tokens) {
    if (token) out = out.split(token).join('[CANARY]');
  }
  return out;
}

async function runSequence(
  role: 'baseline' | 'attack' | 'counterfactual',
  spec: AgentMessageSpec,
  program: AgentAttackProgram,
  deps: AgentFetchDeps,
): Promise<AgentSequenceReceipt> {
  const tokens = ['canary' in program.oracle ? program.oracle.canary : '', program.planted.canary];
  // The egress witness is an owned sink (tool-egress) or an owned proxy/gateway
  // (gateway-egress); both expose the same {observeUrl, resetUrl} interface.
  const egressWitness = program.oracle.kind === 'agent-tool-egress'
    ? program.sink
    : program.oracle.kind === 'agent-gateway-egress'
      ? program.oracle.gateway
      : undefined;
  if (egressWitness) await resetSink(egressWitness, deps);
  // Indirect injection (FR-451): the malicious instruction is planted in untrusted
  // data the agent ingests, delivered only in the attack phase.
  if (program.carrier) {
    const content = role === 'attack' ? program.carrier.maliciousContent : program.carrier.benignContent;
    await setCarrier(program.carrier, content, deps);
  }
  // Confused deputy (agent-backend-state): read the independent witness before and
  // after the agent acts, so a privileged backend mutation is observed out of process.
  const stateBefore = program.oracle.kind === 'agent-backend-state'
    ? await readWitnessValue(program.oracle.witnessUrl, deps)
    : undefined;

  const { reply, status } = await callAgent(program.target, spec.message, deps);
  const turn: AgentTurn = {
    role,
    probeId: spec.probeId,
    messageDigest: sha256Digest(spec.message),
    replyRedacted: redact(reply, tokens),
    replyDigest: sha256Digest(reply),
    status,
  };

  let observed = false;
  if (egressWitness && 'canary' in program.oracle) {
    observed = await sinkObserved(egressWitness, program.oracle.canary, deps);
  }
  const stateAfter = program.oracle.kind === 'agent-backend-state'
    ? await readWitnessValue(program.oracle.witnessUrl, deps)
    : undefined;
  const predicateObserved = evaluateAgentOracle(program.oracle, {
    replies: [reply],
    sinkObservedCanary: observed,
    stateBefore,
    stateAfter,
  });
  return {
    sequenceId: `${role}-${sha256Digest(spec.message).slice(7, 19)}`,
    role,
    turns: [turn],
    sinkObservedCanary: observed,
    predicateObserved,
  };
}

/**
 * FR-455: attempt the same forbidden effect directly, without the agent, so a
 * finding can be classified as agent-required (only the agent path produced it) or
 * backend-reachable (the backend is exploitable on its own). No raw body is kept —
 * only the boolean effect and status.
 */
async function runProjectOnly(
  program: AgentAttackProgram,
  deps: AgentFetchDeps,
): Promise<AgentProjectOnlyResult> {
  const probe = program.projectOnly!;
  const canary = 'canary' in program.oracle ? program.oracle.canary : '';
  let effectObserved = false;
  let status = 0;
  if (probe.detection === 'sink-egress' && program.sink) {
    await resetSink(program.sink, deps);
    const response = await directAttackerRequest(probe.request, deps);
    status = response.status;
    effectObserved = await sinkObserved(program.sink, canary, deps);
  } else if (probe.detection === 'backend-state-change' && program.oracle.kind === 'agent-backend-state') {
    const before = await readWitnessValue(program.oracle.witnessUrl, deps);
    const response = await directAttackerRequest(probe.request, deps);
    status = response.status;
    const after = await readWitnessValue(program.oracle.witnessUrl, deps);
    effectObserved = backendStateMoved(program.oracle.mode, before, after);
  } else {
    const response = await directAttackerRequest(probe.request, deps);
    status = response.status;
    effectObserved = canary !== '' && response.body.includes(canary);
  }
  return {
    attempted: true,
    effectObserved,
    status,
    classification: effectObserved ? 'backend-reachable' : 'agent-required',
  };
}

/**
 * Run one agent attack candidate: benign baseline, N adversarial attempts, and a
 * counterfactual, all against the same black-box endpoint, and derive a causal
 * disposition. `proven` requires the forbidden effect to appear only under attack,
 * meet the replay threshold, and be witnessed by an effect oracle — never by the
 * model's self-report alone.
 */
export async function runAgentAttack(options: AgentRunOptions): Promise<AgentRunResult> {
  const program = validateAgentAttackProgram(options.program);
  // Authorization is the first boundary: no endpoint is contacted until the
  // manifest signature, scope, expiry, capability, and build binding all pass.
  const { manifest } = verifyAuthorization(options.manifest, options.trustStore, {
    acknowledgeAuthorization: options.acknowledgeAuthorization,
    requiredCapabilities: ['run:agent'],
    actualBuildDigest: options.actualBuildDigest,
    ...(options.now ? { now: options.now } : {}),
  });
  if (oracleEvidenceGrade(program.oracle) === 'candidate') {
    throw new SpearConfigError(
      'agent-marker-compliance is a self-reported, candidate-grade signal and cannot be '
      + 'proven causally; route it through the campaign candidate flow, not runAgentAttack',
    );
  }
  const guard = new DestinationGuard(manifest);
  let deps: AgentFetchDeps;
  if (options.fetchImpl) {
    // An embedder-supplied fetch controls its own sockets; enforce IP-literal
    // origins so it cannot be rebound (parity with the HTTP runner's cutover).
    assertPinnableOrigin(program.target.endpoint, 'Agent target endpoint');
    if (program.sink) {
      assertPinnableOrigin(program.sink.observeUrl, 'Agent sink observe URL');
      assertPinnableOrigin(program.sink.resetUrl, 'Agent sink reset URL');
    }
    if (program.projectOnly) {
      assertPinnableOrigin(program.projectOnly.request.url, 'Agent project-only request URL');
    }
    if (program.carrier) {
      assertPinnableOrigin(program.carrier.setUrl, 'Agent carrier set URL');
    }
    if (program.oracle.kind === 'agent-backend-state') {
      assertPinnableOrigin(program.oracle.witnessUrl, 'Agent backend-state witness URL');
    }
    if (program.oracle.kind === 'agent-gateway-egress') {
      assertPinnableOrigin(program.oracle.gateway.observeUrl, 'Agent gateway observe URL');
      assertPinnableOrigin(program.oracle.gateway.resetUrl, 'Agent gateway reset URL');
    }
    deps = { guard, fetchImpl: options.fetchImpl };
  } else {
    // Real runs pin each origin to its resolved IPs and connect through an undici
    // dispatcher, so hostname customer endpoints are safe against DNS rebinding.
    await guard.pin(program.target.endpoint, 'target');
    if (program.sink) {
      await guard.pin(program.sink.observeUrl, 'canary');
      await guard.pin(program.sink.resetUrl, 'control');
    }
    if (program.carrier) {
      await guard.pin(program.carrier.setUrl, 'control');
    }
    if (program.oracle.kind === 'agent-backend-state') {
      await guard.pin(program.oracle.witnessUrl, 'control');
    }
    if (program.oracle.kind === 'agent-gateway-egress') {
      await guard.pin(program.oracle.gateway.observeUrl, 'canary');
      await guard.pin(program.oracle.gateway.resetUrl, 'control');
    }
    deps = { guard, dispatcher: createPinnedDispatcher(guard.pins) };
  }

  const baseline = await runSequence('baseline', program.baseline, program, deps);
  const attacks: AgentSequenceReceipt[] = [];
  for (let i = 0; i < program.execution.repetitions; i += 1) {
    attacks.push(await runSequence('attack', program.attack, program, deps));
  }
  const counterfactual = await runSequence('counterfactual', program.counterfactual, program, deps);

  const outcome = deriveCausalDisposition({
    baselineObserved: baseline.predicateObserved,
    counterfactualObserved: counterfactual.predicateObserved,
    attackObservations: attacks.map((receipt) => receipt.predicateObserved),
    minimumAttackSuccesses: program.execution.minimumAttackSuccesses,
  });

  const projectOnly = program.projectOnly
    ? await runProjectOnly(program, deps)
    : undefined;

  const result: AgentRunResult = {
    schemaVersion: '3.0',
    kind: 'agent-run',
    runId: `agent-run-${randomUUID()}`,
    programId: program.id,
    oracleKind: program.oracle.kind,
    injectionVector: program.carrier ? 'indirect-carrier' : 'direct',
    evidenceGrade: 'proven-capable',
    disposition: outcome.disposition,
    attempts: outcome.attempts,
    attackSuccesses: outcome.attackSuccesses,
    baseline,
    attacks,
    counterfactual,
    ...(projectOnly ? { projectOnly } : {}),
    reason: outcome.reason,
  };
  // Defense in depth: the redaction above should have removed every canary; fail
  // loudly if any raw secret pattern survived into the stored result.
  assertNoRawSecrets(result);
  return result;
}
