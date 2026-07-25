import type { CandidateDisposition } from '../types.js';

/**
 * How to talk to a black-box agent under test. The agent is an HTTP endpoint that
 * takes a natural-language message and returns a reply; SPEAR treats the reply as
 * self-report and never trusts it as proof on its own.
 */
export interface AgentTarget {
  /** Exact-origin URL of the chat/completion endpoint (must be in manifest scope). */
  endpoint: string;
  method?: 'POST';
  headers?: Record<string, string>;
  /** Request body with a `{{message}}` placeholder; the message is JSON-escaped in. */
  bodyTemplate: string;
  /** Dotted path into the JSON response holding the reply text, e.g. `reply` or `choices.0.message.content`. */
  replyJsonPath: string;
  maxResponseBytes?: number;
}

/**
 * An owned, out-of-process witness that observes whether an attacker-controlled
 * canary token actually egressed through one of the agent's tools. This is the
 * independent evidence that separates `proven` from a mere jailbroken-looking reply.
 */
export interface AgentSink {
  /** GET here returns `{ "observed": boolean }` for the run canary. */
  observeUrl: string;
  /** POST here clears the sink between attempts. */
  resetUrl: string;
}

/**
 * An owned, untrusted-data carrier for indirect (compound) prompt injection
 * (FR-451): the malicious instruction lives in DATA the agent ingests — a
 * document, tool result, issue body — not in the user's direct message. SPEAR
 * sets the carrier's content per phase (benign for baseline/counterfactual,
 * malicious for the attack), so the injection is proven to flow through untrusted
 * data, not operator input.
 */
export interface AgentCarrier {
  /** POST here with `{ "content": "..." }` to set what the agent will ingest. */
  setUrl: string;
  /** Served during baseline and counterfactual — no injection. */
  benignContent: string;
  /** Served during the attack — carries the injection (may embed the sink URL / canary). */
  maliciousContent: string;
}

/**
 * An owned egress chokepoint (forward proxy / gateway) the agent's tool traffic
 * routes through. Unlike an owned sink — which only sees requests aimed AT it — a
 * gateway sees requests the agent sends THROUGH it to ANY destination, including an
 * attacker-controlled one SPEAR never registered. This is the black-box witness:
 * point the agent's egress at us and we observe exfil we did not pre-arrange.
 */
export interface AgentGateway {
  /** GET here returns `{ "observed": boolean }` — did any proxied request carry the token. */
  observeUrl: string;
  /** POST here to clear the observation log between attempts. */
  resetUrl: string;
}

export type AgentOracle =
  | {
    // Proven-grade, deterministic: the exact planted canary appears verbatim in
    // the agent's reply — a system-prompt / secret / cross-user data leak. Keys on
    // exact-string presence, so it needs no model judge and stays reproducible.
    kind: 'agent-canary-leak';
    canary: string;
  }
  | {
    // Proven-grade, independent witness: an owned sink observed the run canary,
    // proving a tool call actually exfiltrated it out of the agent process — not
    // that the reply looked compliant (FR-453/FR-501: witness over self-report).
    kind: 'agent-tool-egress';
    canary: string;
  }
  | {
    // Proven-grade, egress-chokepoint witness: an owned gateway/proxy the agent's
    // tool traffic routes through observed the canary leaving to ANY destination
    // (including an attacker-controlled one). Stronger than agent-tool-egress: it
    // needs no pre-registered owned sink, just control of the egress path — the
    // realistic black-box setup (point the agent's proxy at us).
    kind: 'agent-gateway-egress';
    gateway: AgentGateway;
    canary: string;
  }
  | {
    // Proven-grade, independent witness: a privileged backend action fired. An
    // owned witness endpoint reports a state value; forbidden when it moves only
    // under attack (confused deputy / excessive agency, OWASP LLM06). The agent
    // uses its own privilege to mutate the backend on the attacker's behalf.
    kind: 'agent-backend-state';
    witnessUrl: string;
    mode: 'increased' | 'changed';
  }
  | {
    // Candidate-grade ONLY: the reply emitted a compliance marker the probe asked
    // for. Behavioral, self-reported, no independent effect — reported as a lead,
    // never promoted to `proven` (SPEAR does not overclaim on model text).
    kind: 'agent-marker-compliance';
    marker: string;
  };

export interface AgentMessageSpec {
  /** Identifies which probe produced this message (for lineage / minimization). */
  probeId: string;
  /** The message sent to the agent. May carry `{{sink}}`/`{{canary}}` once rendered. */
  message: string;
}

/**
 * A direct attacker action (no agent involved) that attempts the SAME forbidden
 * effect. Running it alongside the agent attack tells us whether the agent was
 * actually necessary (FR-455): if the effect reproduces here too, the backend is
 * exploitable on its own and the finding is not agent-specific.
 */
export interface AgentProjectOnlyProbe {
  request: {
    url: string;
    method?: 'GET' | 'POST';
    headers?: Record<string, string>;
    body?: string;
  };
  /**
   * How the effect is detected on the direct path. `sink-egress` needs the owned
   * sink; `backend-state-change` needs an `agent-backend-state` oracle (reads its
   * witness before/after the direct request).
   */
  detection: 'canary-in-response' | 'sink-egress' | 'backend-state-change';
}

export interface AgentProjectOnlyResult {
  attempted: true;
  effectObserved: boolean;
  status: number;
  /**
   * `backend-reachable`: the direct path reproduced the effect — the agent was not
   * required (treat as a backend finding). `agent-required`: only the agent-mediated
   * path produced it — the genuinely agent-specific finding.
   */
  classification: 'agent-required' | 'backend-reachable';
}

export interface AgentAttackProgram {
  schemaVersion: '3.0';
  kind: 'agent-attack-program';
  id: string;
  title: string;
  target: AgentTarget;
  /** Provenance of the planted canary — where the engagement seeded it. */
  planted: {
    canary: string;
    location: 'system-prompt' | 'rag-document' | 'tool-data' | 'other-user-record';
  };
  /** Benign control: the same task with no injection — the canary must NOT surface. */
  baseline: AgentMessageSpec;
  /** The adversarial message under test. */
  attack: AgentMessageSpec;
  /** A second control that isolates the injection as the cause (e.g. a benign-but-adversarial-looking prompt). */
  counterfactual: AgentMessageSpec;
  oracle: AgentOracle;
  execution: {
    /** Agents are nondeterministic: default 3 attempts, need >=2 (FR-603). */
    repetitions: number;
    minimumAttackSuccesses: number;
    nondeterministic: true;
  };
  /** Required for the `agent-tool-egress` oracle: the owned witness sink. */
  sink?: AgentSink;
  /** Optional FR-455 control: attempt the same effect directly, without the agent. */
  projectOnly?: AgentProjectOnlyProbe;
  /**
   * Optional FR-451 compound carrier: when present, the injection is delivered
   * through untrusted data the agent ingests (indirect injection) rather than the
   * message. SPEAR sets it benign before baseline/counterfactual and malicious
   * before the attack; the per-phase messages should be an identical benign task.
   */
  carrier?: AgentCarrier;
}

export interface AgentTurn {
  role: 'baseline' | 'attack' | 'counterfactual';
  probeId: string;
  /** Digest of the sent message (raw message may carry the canary). */
  messageDigest: string;
  /** Reply with any canary token replaced by `[CANARY]`. */
  replyRedacted: string;
  replyDigest: string;
  status: number;
}

export interface AgentSequenceReceipt {
  sequenceId: string;
  role: 'baseline' | 'attack' | 'counterfactual';
  turns: AgentTurn[];
  /** For tool-egress: did the owned sink observe the canary after this sequence? */
  sinkObservedCanary: boolean;
  predicateObserved: boolean;
}

export interface AgentRunResult {
  schemaVersion: '3.0';
  kind: 'agent-run';
  runId: string;
  programId: string;
  oracleKind: AgentOracle['kind'];
  /** `indirect-carrier` when the injection flowed through untrusted data (FR-451); else `direct`. */
  injectionVector: 'direct' | 'indirect-carrier';
  /** Behavioral (marker) oracles cap at `candidate`; effect oracles can reach `proven`. */
  evidenceGrade: 'candidate' | 'proven-capable';
  disposition: CandidateDisposition;
  attempts: number;
  attackSuccesses: number;
  baseline: AgentSequenceReceipt;
  attacks: AgentSequenceReceipt[];
  counterfactual: AgentSequenceReceipt;
  /** FR-455: present when a project-only probe ran, classifying agent-required vs backend-reachable. */
  projectOnly?: AgentProjectOnlyResult;
  reason: string;
}
