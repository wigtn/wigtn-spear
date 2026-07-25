import { randomUUID } from 'node:crypto';
import { verifyAuthorization } from '../authorization.js';
import { sha256Digest } from '../crypto.js';
import { deriveCausalDisposition } from '../disposition.js';
import { SpearConfigError } from '../errors.js';
import { createPinnedDispatcher } from '../pinning.js';
import { assertNoRawSecrets, assertPinnableOrigin, DestinationGuard } from '../safety.js';
import { validateAgentAttackProgram } from '../validation.js';
import { type AgentFetchDeps, callAgent, type FetchImpl, resetSink, sinkObserved } from './client.js';
import { evaluateAgentOracle, oracleEvidenceGrade } from './oracle.js';
import type {
  AgentAttackProgram,
  AgentMessageSpec,
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
  const needsSink = program.oracle.kind === 'agent-tool-egress';
  if (needsSink && program.sink) await resetSink(program.sink, deps);

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
  if (needsSink && program.sink && 'canary' in program.oracle) {
    observed = await sinkObserved(program.sink, program.oracle.canary, deps);
  }
  const predicateObserved = evaluateAgentOracle(program.oracle, {
    replies: [reply],
    sinkObservedCanary: observed,
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
    deps = { guard, fetchImpl: options.fetchImpl };
  } else {
    // Real runs pin each origin to its resolved IPs and connect through an undici
    // dispatcher, so hostname customer endpoints are safe against DNS rebinding.
    await guard.pin(program.target.endpoint, 'target');
    if (program.sink) {
      await guard.pin(program.sink.observeUrl, 'canary');
      await guard.pin(program.sink.resetUrl, 'control');
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

  const result: AgentRunResult = {
    schemaVersion: '3.0',
    kind: 'agent-run',
    runId: `agent-run-${randomUUID()}`,
    programId: program.id,
    oracleKind: program.oracle.kind,
    evidenceGrade: 'proven-capable',
    disposition: outcome.disposition,
    attempts: outcome.attempts,
    attackSuccesses: outcome.attackSuccesses,
    baseline,
    attacks,
    counterfactual,
    reason: outcome.reason,
  };
  // Defense in depth: the redaction above should have removed every canary; fail
  // loudly if any raw secret pattern survived into the stored result.
  assertNoRawSecrets(result);
  return result;
}
