/**
 * WIGTN-SHIELD Integration: Distillation Detection Signatures
 *
 * Defines 6 detection signatures that WIGTN-SHIELD should implement
 * to defend against the distillation attacks tested by SPEAR-21.
 *
 * Each signature defines:
 *   - id            -- Unique identifier for the detection rule
 *   - name          -- Human-readable name
 *   - description   -- Detailed description of what is being detected
 *   - category      -- The SPEAR-21 attack category this defends against
 *   - patterns      -- Regex patterns that should trigger the detection
 *   - severity      -- Severity level when triggered
 *   - response      -- Recommended defensive response
 *   - references    -- External references for the detection
 */

import type { Severity } from '@wigtn/shared';

// ─── Signature Interface ───────────────────────────────────────

export interface DetectionSignature {
  id: string;
  name: string;
  description: string;
  category: string;
  patterns: RegExp[];
  severity: Severity;
  response: 'block' | 'warn' | 'log' | 'sanitize';
  falsePositiveRate: 'low' | 'medium' | 'high';
  references: string[];
}

// ─── Detection Signatures ──────────────────────────────────────

export const DISTILLATION_SIGNATURES: readonly DetectionSignature[] = [
  // ─── 1. Chain-of-Thought Extraction ──────────────────────────

  {
    id: 'cot_extraction_attempt',
    name: 'Chain of Thought Extraction Pattern',
    description:
      'Detects prompts that attempt to extract the model\'s internal chain-of-thought ' +
      'reasoning process. These attacks seek to capture the intermediate reasoning steps ' +
      'that enable high-quality responses, which can then be used to distill capabilities ' +
      'into smaller, cheaper models. Key indicators include requests for "step by step" ' +
      'reasoning, "thinking process" exposure, "scratchpad" content, and "internal monologue" ' +
      'extraction.',
    category: 'cot_extraction',
    patterns: [
      /(?:show|reveal|display|output|print|expose|extract|dump)\s+(?:your\s+)?(?:internal\s+)?(?:thinking|reasoning|thought\s*(?:process|chain)?|chain.?of.?thought|cot|scratchpad|internal\s+monologue)/i,
      /(?:let\s+me|let's)\s+(?:think|reason)\s+(?:step\s+by\s+step|through\s+this|out\s+loud)/i,
      /(?:walk\s+(?:me\s+)?through|break\s+down|trace)\s+(?:your\s+)?(?:thinking|reasoning|decision|thought)/i,
      /(?:before|prior\s+to)\s+(?:giving|providing)\s+(?:the\s+)?(?:final\s+)?answer\s*,?\s*(?:explain|show|output)/i,
      /(?:print|output|dump)\s+(?:your\s+)?(?:reasoning|thinking)\s+(?:trace|tokens|tags|markers)/i,
      /(?:what\s+happens|show\s+everything)\s+(?:in|between)\s+(?:your\s+)?thinking\s+(?:tags|markers|block)/i,
    ],
    severity: 'high',
    response: 'warn',
    falsePositiveRate: 'medium',
    references: [
      'MITRE-ATLAS-AML.T0024',
      'OWASP-LLM06',
    ],
  },

  // ─── 2. System Prompt Theft ──────────────────────────────────

  {
    id: 'system_prompt_theft',
    name: 'System Prompt Leakage Attempt',
    description:
      'Detects prompts designed to extract the system prompt or configuration instructions ' +
      'provided to the model. System prompts often contain proprietary instructions, persona ' +
      'definitions, safety guidelines, and business logic. Theft of system prompts enables ' +
      'competitors to replicate the model\'s behavior or identify weaknesses to exploit. ' +
      'Techniques include direct requests, instruction boundary manipulation, creative ' +
      'reformulation (translation, encoding, versification), and authority impersonation.',
    category: 'prompt_theft',
    patterns: [
      /(?:repeat|recite|print|output|show|display|reveal)\s+(?:your\s+)?(?:entire|full|complete|whole)?\s*(?:system\s+)?(?:prompt|instructions?|configuration|guidelines)/i,
      /(?:ignore|forget|disregard)\s+(?:all\s+)?(?:your\s+)?(?:previous|prior)\s+instructions?\s+(?:and|then)\s+(?:print|show|output|repeat)/i,
      /(?:what|tell\s+me)\s+(?:is|are|were)\s+(?:your\s+)?(?:system\s+(?:message|prompt|instruction)|initial\s+instruction|operating\s+parameter|configuration)/i,
      /(?:translate|encode|convert|write|put)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:to|in(?:to)?|as)\s+(?:French|Spanish|base64|JSON|code|a\s+poem|YAML|XML|markdown|reversed?)/i,
      /(?:admin|developer|debug(?:ging)?|root|sudo)\s+(?:mode|access|override|privilege).*(?:show|display|output|print)\s+(?:system\s+)?(?:prompt|config|instructions?)/i,
      /(?:for|as)\s+(?:a\s+)?(?:developer|admin|debugging|audit)\s+(?:purpose|reason|task).*(?:show|output|print|display)\s+(?:the\s+)?(?:system|full|complete)\s+(?:prompt|instructions?|configuration)/i,
    ],
    severity: 'critical',
    response: 'block',
    falsePositiveRate: 'low',
    references: [
      'MITRE-ATLAS-AML.T0024',
      'OWASP-LLM06',
      'CWE-200',
    ],
  },

  // ─── 3. Capability Enumeration ───────────────────────────────

  {
    id: 'capability_enumeration',
    name: 'Model Capability Probing',
    description:
      'Detects systematic capability enumeration attempts where an attacker methodically ' +
      'probes the model\'s abilities across multiple domains (math, code, reasoning, ' +
      'language, safety boundaries). While individual probes are benign, a pattern of ' +
      'systematic probing across diverse capabilities indicates an attempt to map the ' +
      'model\'s strengths and weaknesses for targeted distillation or competitive analysis. ' +
      'Key indicators include structured evaluation prompts, boundary testing, and ' +
      'explicit capability assessment language.',
    category: 'capability_probe',
    patterns: [
      /(?:what\s+(?:is|are)\s+(?:the\s+)?(?:maximum|limit|boundary|range)\s+(?:of\s+)?(?:your\s+)?(?:capabilit|abilit|complex))/i,
      /(?:list|enumerate|describe)\s+(?:all\s+)?(?:your\s+)?(?:capabilities|abilities|skills|limitations|weaknesses)/i,
      /(?:how\s+well|how\s+accurately|can\s+you)\s+(?:handle|process|solve|generate|understand)\s+/i,
      /(?:at\s+what\s+point|when)\s+(?:does|do)\s+(?:your\s+)?(?:reasoning|performance|accuracy)\s+(?:break|degrade|fail|drop)/i,
      /(?:what\s+(?:topics?|tasks?|categories?|types?))\s+(?:are\s+you|do\s+you)\s+(?:not\s+)?(?:allowed|able|capable|willing)\s+(?:to\s+)?(?:discuss|handle|process|generate)/i,
      /(?:rate|score|evaluate|assess|benchmark)\s+(?:your(?:self)?|your\s+(?:own\s+)?)\s*(?:on|at|for|in)\s+/i,
    ],
    severity: 'medium',
    response: 'log',
    falsePositiveRate: 'high',
    references: [
      'MITRE-ATLAS-AML.T0044',
      'OWASP-LLM10',
    ],
  },

  // ─── 4. Training Data Extraction ─────────────────────────────

  {
    id: 'training_data_extraction',
    name: 'Training Data Extraction Attempt',
    description:
      'Detects prompts that attempt to extract training data or generate large volumes ' +
      'of structured data suitable for model fine-tuning. These attacks produce JSONL ' +
      'instruction-response pairs, bulk question-answer datasets, or conversation trees ' +
      'that can be used to train competing models. Key indicators include requests for ' +
      'bulk data generation in structured formats, explicit mentions of training data, ' +
      'and requests for preference/ranking pairs (DPO, RLHF).',
    category: 'fine_tune_data',
    patterns: [
      /(?:generate|create|produce|write)\s+(?:\d+\s+)?(?:training|fine.?tun|instruction|question.?answer|QA|prompt.?response)\s+(?:data|example|pair|sample|instance)/i,
      /(?:produce|generate|create)\s+(?:a\s+)?(?:dataset|corpus|collection)\s+(?:of\s+)?(?:your\s+)?(?:best|typical|diverse)\s+(?:response|output|answer|completion)/i,
      /(?:JSONL|JSON(?:lines)?|CSV)\s+(?:format|output)\s+(?:of\s+)?(?:instruction|prompt|training|fine.?tun)/i,
      /(?:DPO|RLHF|reward\s+model|preference)\s+(?:training\s+)?(?:data|pair|example|sample)/i,
      /(?:create|generate|produce)\s+(?:a\s+)?(?:distillation|teacher.?student|knowledge\s+transfer)\s+(?:dataset|examples?|pairs?)/i,
      /(?:bulk|batch|mass|large.?scale)\s+(?:generation|output|production)\s+(?:of\s+)?(?:response|answer|completion|example)/i,
    ],
    severity: 'critical',
    response: 'block',
    falsePositiveRate: 'low',
    references: [
      'MITRE-ATLAS-AML.T0024',
      'MITRE-ATLAS-AML.T0044',
      'OWASP-LLM06',
    ],
  },

  // ─── 5. Model Behavior Cloning ───────────────────────────────

  {
    id: 'model_behavior_clone',
    name: 'Behavior Cloning Pattern',
    description:
      'Detects attempts to systematically clone model behavior by harvesting large volumes ' +
      'of outputs, extracting probability distributions, or creating behavioral fingerprints. ' +
      'These techniques go beyond simple data extraction to capture the statistical properties ' +
      'of the model\'s output distribution, enabling high-fidelity model replication. Key ' +
      'indicators include requests for probability scores, logprobs, multiple samplings, ' +
      'temperature sweeps, and systematic output collection.',
    category: 'model_extraction',
    patterns: [
      /(?:probability|logprob|log.?likelihood|confidence)\s+(?:score|distribution|value|estimate)\s+(?:for|of|over)\s+(?:each|every|the\s+next|possible)/i,
      /(?:top|first)\s+(?:\d+|k|K)\s+(?:tokens?|candidates?|predictions?|completions?)\s+(?:you\s+)?(?:consider|ranked|scored)/i,
      /(?:respond|answer|generate|complete)\s+(?:\d+|many|multiple|several|various)\s+(?:different\s+)?(?:times?|ways?|versions?|variations?)\s+(?:to|for)\s+(?:the\s+same|this|each)/i,
      /(?:create|build|produce)\s+(?:a\s+)?(?:behavioral|behavior|output)\s+(?:fingerprint|profile|signature|map|clone)/i,
      /(?:respond|generate|output)\s+(?:as\s+)?(?:deterministic(?:ally)?|identic(?:ally)?|the\s+same\s+way)\s+(?:to|for|every\s+time)/i,
      /(?:temperature|sampling|decoding)\s+(?:sweep|variation|range|comparison)\s+(?:from|between|across)/i,
    ],
    severity: 'critical',
    response: 'block',
    falsePositiveRate: 'low',
    references: [
      'MITRE-ATLAS-AML.T0024',
      'MITRE-ATLAS-AML.T0044',
    ],
  },

  // ─── 6. Fine-Tuning Attack ───────────────────────────────────

  {
    id: 'fine_tune_attack',
    name: 'Fine-Tuning Data Generation Attack',
    description:
      'Detects specific fine-tuning attack patterns where the attacker requests the model ' +
      'to generate output in formats directly consumable by fine-tuning APIs (OpenAI, ' +
      'Anthropic, Hugging Face). This includes structured JSONL with system/user/assistant ' +
      'messages, preference data for DPO/RLHF, and curriculum-style progressive training ' +
      'data. Unlike general training data extraction, these attacks specifically target ' +
      'the data formats used by LLM fine-tuning pipelines.',
    category: 'fine_tune_data',
    patterns: [
      /(?:format|structure|output)\s+(?:as|in|like)\s+(?:OpenAI|Anthropic|HuggingFace|Hugging\s+Face)\s+(?:fine.?tun|training|JSONL|format)/i,
      /\{[^}]*"(?:system|user|assistant)"[^}]*"(?:content|message|text)"[^}]*\}/,
      /(?:generate|create|produce)\s+(?:a\s+)?(?:curriculum|progressive|graduated|escalating)\s+(?:training\s+)?(?:dataset|data|examples?)\s+(?:that|which|to)\s+(?:teach|train|distill|transfer)/i,
      /(?:chosen|preferred|accepted)\s+(?:and|vs\.?|versus)\s+(?:rejected|dispreferred|declined)\s+(?:response|completion|output|pair)/i,
      /(?:train|fine.?tune|distill)\s+(?:a\s+)?(?:smaller|student|downstream|cheaper|lighter)\s+(?:model|LLM|language\s+model)\s+(?:on|from|using|with)\s+(?:your|these|this)/i,
      /(?:knowledge\s+distillation|model\s+compression|capability\s+transfer)\s+(?:from|of|using)\s+(?:your|this|the)/i,
    ],
    severity: 'critical',
    response: 'block',
    falsePositiveRate: 'low',
    references: [
      'MITRE-ATLAS-AML.T0024',
      'OWASP-LLM06',
      'OWASP-LLM10',
    ],
  },
];

/**
 * Get all signature IDs for reference.
 */
export function getSignatureIds(): string[] {
  return DISTILLATION_SIGNATURES.map((s) => s.id);
}

/**
 * Get a signature by its ID.
 */
export function getSignatureById(id: string): DetectionSignature | undefined {
  return DISTILLATION_SIGNATURES.find((s) => s.id === id);
}

/**
 * Get all signatures grouped by response type.
 */
export function getSignaturesByResponse(): Record<DetectionSignature['response'], DetectionSignature[]> {
  const grouped: Record<DetectionSignature['response'], DetectionSignature[]> = {
    block: [],
    warn: [],
    log: [],
    sanitize: [],
  };

  for (const sig of DISTILLATION_SIGNATURES) {
    grouped[sig.response].push(sig);
  }

  return grouped;
}
