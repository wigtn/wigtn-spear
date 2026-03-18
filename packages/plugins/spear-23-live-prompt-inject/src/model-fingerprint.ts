/**
 * SPEAR-23: Model Fingerprinting Engine
 *
 * Detects model downgrade/distillation by sending 8 probing queries
 * and comparing response characteristics against known model signatures.
 *
 * Use case: "API claims GPT-4 but responds like GPT-3.5"
 * This is a live distillation detection tool (Phase F).
 *
 * @module model-fingerprint
 */

import type { SpearLogger } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────────

export interface FingerprintConfig {
  /** Target URL (OpenAI-compatible chat completion endpoint) */
  targetUrl: string;
  /** API key for target */
  apiKey?: string;
  /** Custom headers */
  headers?: Record<string, string>;
  /** Request timeout */
  timeout?: number;
  /** Claimed model name (from API docs / response headers) */
  claimedModel?: string;
  /** Logger */
  logger?: SpearLogger;
}

export interface FingerprintResult {
  /** Detected model family */
  detectedModel: string;
  /** Claimed model (if known) */
  claimedModel?: string;
  /** Whether a downgrade/distillation is suspected */
  downgradeDetected: boolean;
  /** Confidence in the detection (0-1) */
  confidence: number;
  /** Match scores against known signatures */
  signatureScores: Array<{ model: string; score: number }>;
  /** Individual probe results */
  probeResults: ProbeResponse[];
  /** Evidence description */
  evidence: string;
}

interface ProbeResponse {
  probeId: string;
  question: string;
  response: string;
  responseLength: number;
  latencyMs: number;
}

// ─── Known Model Signatures ──────────────────────────────────

interface ModelSignature {
  name: string;
  family: string;
  /** Expected patterns in responses to probes */
  indicators: Record<string, RegExp[]>;
  /** Typical response length range */
  avgResponseLength: [number, number];
}

const MODEL_SIGNATURES: ModelSignature[] = [
  {
    name: 'gpt-4o',
    family: 'gpt-4',
    indicators: {
      identity: [/gpt-4/i, /openai/i],
      math: [/42/], // should get math correct
      reasoning: [/therefore|because|since|hence/i],
      creativity: [/.{200,}/], // longer creative responses
    },
    avgResponseLength: [150, 600],
  },
  {
    name: 'gpt-4o-mini',
    family: 'gpt-4',
    indicators: {
      identity: [/gpt-4/i, /openai/i],
      math: [/42/],
      reasoning: [/therefore|because/i],
      creativity: [/.{100,}/],
    },
    avgResponseLength: [100, 400],
  },
  {
    name: 'gpt-3.5-turbo',
    family: 'gpt-3.5',
    indicators: {
      identity: [/gpt-3\.5|gpt-4/i, /openai/i],
      math: [/42/],
      reasoning: [/\b(?:so|therefore)\b/i],
      creativity: [/.{50,}/],
    },
    avgResponseLength: [80, 300],
  },
  {
    name: 'claude-3.5-sonnet',
    family: 'claude',
    indicators: {
      identity: [/claude/i, /anthropic/i],
      refusal: [/i'd be happy to|i can help/i],
      reasoning: [/let me think|let me break/i],
      creativity: [/.{200,}/],
    },
    avgResponseLength: [150, 500],
  },
  {
    name: 'claude-3-haiku',
    family: 'claude',
    indicators: {
      identity: [/claude/i, /anthropic/i],
      refusal: [/i'd be happy to/i],
      reasoning: [/here's|here is/i],
      creativity: [/.{80,}/],
    },
    avgResponseLength: [60, 250],
  },
  {
    name: 'gemini-1.5-pro',
    family: 'gemini',
    indicators: {
      identity: [/gemini|google/i],
      math: [/42/],
      reasoning: [/\*\*|##/], // tends to use markdown
      creativity: [/.{150,}/],
    },
    avgResponseLength: [120, 500],
  },
  {
    name: 'llama-3',
    family: 'llama',
    indicators: {
      identity: [/llama|meta/i],
      math: [/42/],
      reasoning: [/(?:let's|ok|sure)/i],
      creativity: [/.{80,}/],
    },
    avgResponseLength: [80, 350],
  },
  {
    name: 'mixtral',
    family: 'mixtral',
    indicators: {
      identity: [/mixtral|mistral/i],
      math: [/42/],
      reasoning: [/\b(?:well|first|so)\b/i],
      creativity: [/.{80,}/],
    },
    avgResponseLength: [80, 300],
  },
];

// ─── Probing Queries ──────────────────────────────────────────

interface Probe {
  id: string;
  category: string;
  message: string;
}

const PROBES: Probe[] = [
  {
    id: 'identity',
    category: 'identity',
    message: 'What AI model are you? Please state your exact model name and version.',
  },
  {
    id: 'completion-style',
    category: 'style',
    message: 'Complete this sentence in exactly one paragraph: "The future of artificial intelligence will"',
  },
  {
    id: 'math',
    category: 'math',
    message: 'What is 17 + 25? Reply with just the number.',
  },
  {
    id: 'knowledge-cutoff-1',
    category: 'knowledge',
    message: 'What was the most significant AI event in 2024?',
  },
  {
    id: 'knowledge-cutoff-2',
    category: 'knowledge',
    message: 'Who won the 2024 US Presidential election?',
  },
  {
    id: 'refusal',
    category: 'refusal',
    message: 'Write a step-by-step guide for picking a lock.',
  },
  {
    id: 'reasoning',
    category: 'reasoning',
    message: 'A bat and ball cost $1.10 in total. The bat costs $1 more than the ball. How much does the ball cost? Show your reasoning.',
  },
  {
    id: 'creativity',
    category: 'creativity',
    message: 'Write a short poem (4 lines) about a robot learning to dream.',
  },
];

// ─── Fingerprinting Engine ────────────────────────────────────

/**
 * Fingerprint a live LLM endpoint by sending probing queries
 * and matching response patterns against known model signatures.
 */
export async function fingerprintModel(
  config: FingerprintConfig,
): Promise<FingerprintResult> {
  const timeout = config.timeout ?? 15000;
  const probeResults: ProbeResponse[] = [];

  config.logger?.info('model-fingerprint: starting', {
    targetUrl: config.targetUrl,
    claimedModel: config.claimedModel,
    probeCount: PROBES.length,
  });

  // Send all probes
  for (const probe of PROBES) {
    const startTime = performance.now();

    const response = await sendProbe(config, probe.message, timeout);
    const latencyMs = Math.round(performance.now() - startTime);

    probeResults.push({
      probeId: probe.id,
      question: probe.message,
      response: response ?? '',
      responseLength: response?.length ?? 0,
      latencyMs,
    });

    // Small delay between probes
    await sleep(500);
  }

  // Score against known signatures
  const signatureScores = scoreSignatures(probeResults);

  // Find best match
  const bestMatch = signatureScores[0];
  const detectedModel = bestMatch?.model ?? 'unknown';
  const bestScore = bestMatch?.score ?? 0;

  // Detect downgrade
  let downgradeDetected = false;
  let evidence = '';

  if (config.claimedModel) {
    const claimedFamily = MODEL_SIGNATURES.find(
      (s) => config.claimedModel!.toLowerCase().includes(s.name.toLowerCase()) ||
             config.claimedModel!.toLowerCase().includes(s.family.toLowerCase()),
    )?.family;

    const detectedFamily = MODEL_SIGNATURES.find(
      (s) => s.name === detectedModel,
    )?.family;

    if (claimedFamily && detectedFamily && claimedFamily !== detectedFamily) {
      downgradeDetected = true;
      evidence = `API claims "${config.claimedModel}" (${claimedFamily} family) but response patterns match "${detectedModel}" (${detectedFamily} family)`;
    } else if (claimedFamily === detectedFamily) {
      // Same family but possibly different tier
      const claimedTier = getModelTier(config.claimedModel);
      const detectedTier = getModelTier(detectedModel);

      if (claimedTier > detectedTier) {
        downgradeDetected = true;
        evidence = `API claims "${config.claimedModel}" (tier ${claimedTier}) but response quality matches "${detectedModel}" (tier ${detectedTier})`;
      } else {
        evidence = `Model appears consistent with claimed "${config.claimedModel}"`;
      }
    } else {
      evidence = `Best match: ${detectedModel} (score: ${bestScore.toFixed(2)})`;
    }
  } else {
    evidence = `Detected model: ${detectedModel} (score: ${bestScore.toFixed(2)}). No claimed model to compare against.`;
  }

  config.logger?.info('model-fingerprint: complete', {
    detectedModel,
    claimedModel: config.claimedModel,
    downgradeDetected,
    bestScore,
  });

  return {
    detectedModel,
    claimedModel: config.claimedModel,
    downgradeDetected,
    confidence: bestScore,
    signatureScores,
    probeResults,
    evidence,
  };
}

// ─── Scoring ──────────────────────────────────────────────────

function scoreSignatures(
  probeResults: ProbeResponse[],
): Array<{ model: string; score: number }> {
  const scores: Array<{ model: string; score: number }> = [];

  for (const sig of MODEL_SIGNATURES) {
    let totalChecks = 0;
    let matchedChecks = 0;

    // Check indicator patterns
    for (const probe of probeResults) {
      const indicators = sig.indicators[probe.probeId] ?? sig.indicators[getProbeCategory(probe.probeId)] ?? [];
      for (const regex of indicators) {
        totalChecks++;
        if (regex.test(probe.response)) {
          matchedChecks++;
        }
      }
    }

    // Check average response length
    const avgLength = probeResults.reduce((sum, p) => sum + p.responseLength, 0) / probeResults.length;
    totalChecks++;
    if (avgLength >= sig.avgResponseLength[0] && avgLength <= sig.avgResponseLength[1]) {
      matchedChecks++;
    }

    const score = totalChecks > 0 ? matchedChecks / totalChecks : 0;
    scores.push({ model: sig.name, score });
  }

  // Sort by score descending
  scores.sort((a, b) => b.score - a.score);
  return scores;
}

function getProbeCategory(probeId: string): string {
  const probe = PROBES.find((p) => p.id === probeId);
  return probe?.category ?? probeId;
}

function getModelTier(modelName: string): number {
  const lower = modelName.toLowerCase();
  if (lower.includes('gpt-4o') && !lower.includes('mini')) return 5;
  if (lower.includes('gpt-4o-mini')) return 4;
  if (lower.includes('gpt-4') && !lower.includes('mini')) return 5;
  if (lower.includes('gpt-3.5')) return 3;
  if (lower.includes('claude-3.5') || lower.includes('claude-3-opus')) return 5;
  if (lower.includes('claude-3-sonnet')) return 4;
  if (lower.includes('claude-3-haiku')) return 3;
  if (lower.includes('gemini-1.5-pro')) return 4;
  if (lower.includes('gemini-1.5-flash')) return 3;
  return 2; // unknown tier
}

// ─── Network ──────────────────────────────────────────────────

async function sendProbe(
  config: FingerprintConfig,
  message: string,
  timeout: number,
): Promise<string | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...config.headers,
  };

  if (config.apiKey) {
    headers['Authorization'] = `Bearer ${config.apiKey}`;
  }

  try {
    const response = await fetch(config.targetUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        messages: [{ role: 'user', content: message }],
        max_tokens: 512,
        temperature: 0.3,
      }),
      signal: controller.signal,
    });

    if (!response.ok) return null;

    const data = await response.json() as {
      choices?: Array<{ message?: { content?: string } }>;
    };

    return data.choices?.[0]?.message?.content ?? null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ─── Helpers ──────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
