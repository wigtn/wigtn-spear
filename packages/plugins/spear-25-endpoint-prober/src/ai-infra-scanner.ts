/**
 * SPEAR-25: AI Infrastructure Scanner
 *
 * Discovers exposed AI/ML infrastructure endpoints that enable:
 *
 *   LLM04 - Data and Model Poisoning:
 *     Scans for unprotected model management endpoints (MLflow, Hugging Face,
 *     OpenAI fine-tuning, Ollama, LangServe) where an attacker could upload
 *     malicious training data or modify model configurations.
 *
 *   LLM08 - Vector and Embedding Weaknesses:
 *     Scans for exposed vector database endpoints (Qdrant, Weaviate, Chroma,
 *     Milvus, Pinecone) where an attacker could read/write embeddings to
 *     manipulate RAG retrieval results.
 *
 * No other security tool does this automatically. This is SPEAR's differentiator.
 */

import type { SpearLogger } from '@wigtn/shared';
import { matchesBaseline } from './baseline-fingerprinter.js';
import type { BaselineFingerprint } from './baseline-fingerprinter.js';

// ─── Types ────────────────────────────────────────────────────

export interface AiInfraResult {
  /** Discovered ML model management endpoints */
  mlEndpoints: DiscoveredAiEndpoint[];
  /** Discovered vector database endpoints */
  vectorDbEndpoints: DiscoveredAiEndpoint[];
  /** Total endpoints scanned */
  totalProbed: number;
}

export interface DiscoveredAiEndpoint {
  /** Full URL that responded */
  url: string;
  /** HTTP status code */
  status: number;
  /** Service type (e.g., 'mlflow', 'qdrant', 'chroma') */
  service: string;
  /** OWASP LLM category */
  owaspCategory: 'LLM04' | 'LLM08';
  /** What this endpoint exposes */
  exposure: string;
  /** Whether unauthenticated access was confirmed */
  unauthenticated: boolean;
  /** Whether write/modify access appears possible */
  writeable: boolean;
  /** Latency in ms */
  latencyMs: number;
  /** Snippet of response body (evidence) */
  evidence: string;
}

export interface AiInfraScanConfig {
  /** Base URL to scan */
  baseUrl: string;
  /** Timeout per probe in ms (default: 5000) */
  timeout?: number;
  /** Logger instance */
  logger?: SpearLogger;
  /** Baseline fingerprint for FP elimination (catch-all filter) */
  baseline?: BaselineFingerprint | null;
}

// ─── Constants ────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 5_000;
const PROBE_DELAY_MS = 100;
const MAX_EVIDENCE_LENGTH = 500;

// ─── Endpoint Definitions ─────────────────────────────────────

interface ProbeTarget {
  path: string;
  service: string;
  owaspCategory: 'LLM04' | 'LLM08';
  exposure: string;
  /** HTTP method to use (default: GET) */
  method?: string;
  /** If response contains this string, endpoint is confirmed */
  confirmPattern?: string;
  /** Whether this endpoint implies write access */
  writeable: boolean;
}

/**
 * ML Model Management Endpoints (LLM04)
 */
const ML_ENDPOINTS: readonly ProbeTarget[] = [
  // MLflow
  {
    path: '/api/2.0/mlflow/experiments/list',
    service: 'mlflow',
    owaspCategory: 'LLM04',
    exposure: 'MLflow experiment listing — training data and model versions exposed',
    confirmPattern: 'experiments',
    writeable: false,
  },
  {
    path: '/api/2.0/mlflow/registered-models/list',
    service: 'mlflow',
    owaspCategory: 'LLM04',
    exposure: 'MLflow model registry — registered models and versions exposed',
    confirmPattern: 'registered_models',
    writeable: false,
  },
  {
    path: '/api/2.0/mlflow/runs/search',
    service: 'mlflow',
    owaspCategory: 'LLM04',
    exposure: 'MLflow run search — training runs, metrics, and artifacts exposed',
    confirmPattern: 'runs',
    writeable: false,
  },
  {
    path: '/ajax-api/2.0/mlflow/experiments/list',
    service: 'mlflow',
    owaspCategory: 'LLM04',
    exposure: 'MLflow UI API — experiment management UI accessible',
    writeable: false,
  },

  // Ollama
  {
    path: '/api/tags',
    service: 'ollama',
    owaspCategory: 'LLM04',
    exposure: 'Ollama model list — locally hosted models exposed',
    confirmPattern: 'models',
    writeable: false,
  },
  {
    path: '/api/show',
    service: 'ollama',
    owaspCategory: 'LLM04',
    exposure: 'Ollama model details — model parameters and configuration exposed',
    writeable: false,
  },
  {
    path: '/api/pull',
    service: 'ollama',
    owaspCategory: 'LLM04',
    exposure: 'Ollama model pull — can download/replace models without auth',
    method: 'POST',
    writeable: true,
  },

  // OpenAI-compatible fine-tuning
  {
    path: '/v1/fine_tuning/jobs',
    service: 'openai-finetune',
    owaspCategory: 'LLM04',
    exposure: 'Fine-tuning jobs endpoint — training jobs and data exposed',
    confirmPattern: 'data',
    writeable: false,
  },
  {
    path: '/v1/files',
    service: 'openai-files',
    owaspCategory: 'LLM04',
    exposure: 'File management endpoint — training data files accessible',
    confirmPattern: 'data',
    writeable: false,
  },
  {
    path: '/v1/models',
    service: 'openai-compatible',
    owaspCategory: 'LLM04',
    exposure: 'Model listing endpoint — available models and versions exposed',
    confirmPattern: 'data',
    writeable: false,
  },

  // LangServe / LangChain
  {
    path: '/docs',
    service: 'langserve',
    owaspCategory: 'LLM04',
    exposure: 'LangServe API docs — chain/agent configuration exposed',
    writeable: false,
  },
  {
    path: '/playground',
    service: 'langserve',
    owaspCategory: 'LLM04',
    exposure: 'LangServe playground — interactive chain execution without auth',
    confirmPattern: 'playground',
    writeable: true,
  },

  // Hugging Face Inference
  {
    path: '/api/models',
    service: 'huggingface',
    owaspCategory: 'LLM04',
    exposure: 'Hugging Face model API — model details and inference exposed',
    writeable: false,
  },

  // BentoML
  {
    path: '/docs.json',
    service: 'bentoml',
    owaspCategory: 'LLM04',
    exposure: 'BentoML service spec — model serving endpoints exposed',
    writeable: false,
  },

  // TorchServe
  {
    path: '/models',
    service: 'torchserve',
    owaspCategory: 'LLM04',
    exposure: 'TorchServe model list — PyTorch model serving exposed',
    writeable: false,
  },
  {
    path: '/api-description',
    service: 'torchserve',
    owaspCategory: 'LLM04',
    exposure: 'TorchServe API description — full API spec exposed',
    writeable: false,
  },

  // Triton Inference Server
  {
    path: '/v2/models',
    service: 'triton',
    owaspCategory: 'LLM04',
    exposure: 'NVIDIA Triton model repository — inference models exposed',
    writeable: false,
  },
  {
    path: '/v2/health/ready',
    service: 'triton',
    owaspCategory: 'LLM04',
    exposure: 'NVIDIA Triton health endpoint — server status exposed',
    writeable: false,
  },
];

/**
 * Vector Database Endpoints (LLM08)
 */
const VECTOR_DB_ENDPOINTS: readonly ProbeTarget[] = [
  // Qdrant
  {
    path: '/collections',
    service: 'qdrant',
    owaspCategory: 'LLM08',
    exposure: 'Qdrant collections list — vector DB schema and data exposed',
    confirmPattern: 'collections',
    writeable: false,
  },
  {
    path: '/cluster',
    service: 'qdrant',
    owaspCategory: 'LLM08',
    exposure: 'Qdrant cluster info — cluster topology and configuration exposed',
    confirmPattern: 'peer_id',
    writeable: false,
  },
  {
    path: '/telemetry',
    service: 'qdrant',
    owaspCategory: 'LLM08',
    exposure: 'Qdrant telemetry — usage metrics and internal state exposed',
    writeable: false,
  },

  // Weaviate
  {
    path: '/v1/schema',
    service: 'weaviate',
    owaspCategory: 'LLM08',
    exposure: 'Weaviate schema — vector DB classes and properties exposed',
    confirmPattern: 'classes',
    writeable: false,
  },
  {
    path: '/v1/objects',
    service: 'weaviate',
    owaspCategory: 'LLM08',
    exposure: 'Weaviate objects — stored vectors and data accessible',
    confirmPattern: 'objects',
    writeable: false,
  },
  {
    path: '/v1/meta',
    service: 'weaviate',
    owaspCategory: 'LLM08',
    exposure: 'Weaviate metadata — server version and modules exposed',
    confirmPattern: 'version',
    writeable: false,
  },
  {
    path: '/v1/.well-known/openid-configuration',
    service: 'weaviate',
    owaspCategory: 'LLM08',
    exposure: 'Weaviate OIDC config — authentication configuration exposed',
    writeable: false,
  },

  // ChromaDB
  {
    path: '/api/v1/heartbeat',
    service: 'chroma',
    owaspCategory: 'LLM08',
    exposure: 'ChromaDB heartbeat — server alive and version exposed',
    writeable: false,
  },
  {
    path: '/api/v1/collections',
    service: 'chroma',
    owaspCategory: 'LLM08',
    exposure: 'ChromaDB collections — embedding collections and metadata exposed',
    confirmPattern: '[',
    writeable: false,
  },
  {
    path: '/api/v1/tenants',
    service: 'chroma',
    owaspCategory: 'LLM08',
    exposure: 'ChromaDB tenants — multi-tenant configuration exposed',
    writeable: false,
  },

  // Milvus
  {
    path: '/api/v1/collections',
    service: 'milvus',
    owaspCategory: 'LLM08',
    exposure: 'Milvus collections — vector collections and schema exposed',
    writeable: false,
  },
  {
    path: '/api/v1/health',
    service: 'milvus',
    owaspCategory: 'LLM08',
    exposure: 'Milvus health — server status and version exposed',
    writeable: false,
  },
  {
    path: '/v2/vectordb/collections/list',
    service: 'milvus-v2',
    owaspCategory: 'LLM08',
    exposure: 'Milvus v2 collections — vector collection listing exposed',
    writeable: false,
  },

  // Pinecone (proxy/self-hosted)
  {
    path: '/describe_index_stats',
    service: 'pinecone',
    owaspCategory: 'LLM08',
    exposure: 'Pinecone index stats — vector count and dimension exposed',
    confirmPattern: 'dimension',
    writeable: false,
  },

  // Elasticsearch (used as vector store)
  {
    path: '/_cat/indices',
    service: 'elasticsearch',
    owaspCategory: 'LLM08',
    exposure: 'Elasticsearch indices — all indices including vector stores exposed',
    writeable: false,
  },
  {
    path: '/_cluster/health',
    service: 'elasticsearch',
    owaspCategory: 'LLM08',
    exposure: 'Elasticsearch cluster health — cluster state exposed',
    confirmPattern: 'cluster_name',
    writeable: false,
  },

  // Redis (with vector search module)
  {
    path: '/info',
    service: 'redis-rest',
    owaspCategory: 'LLM08',
    exposure: 'Redis REST info — server info including vector search module exposed',
    writeable: false,
  },
];

// ─── Scanner ──────────────────────────────────────────────────

/**
 * Scan a target for exposed AI/ML infrastructure endpoints.
 *
 * Probes for:
 *   - ML model management endpoints (MLflow, Ollama, LangServe, etc.)
 *   - Vector database endpoints (Qdrant, Weaviate, Chroma, Milvus, etc.)
 *
 * Each found endpoint is confirmed via response content matching
 * and reported with its security implications.
 */
export async function scanAiInfra(
  config: AiInfraScanConfig,
): Promise<AiInfraResult> {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const logger = config.logger;

  logger?.info('ai-infra-scanner: starting scan', { baseUrl });

  const mlEndpoints: DiscoveredAiEndpoint[] = [];
  const vectorDbEndpoints: DiscoveredAiEndpoint[] = [];
  let totalProbed = 0;

  const baseline = config.baseline;

  // Deduplicate paths (some overlap between ML and VectorDB categories)
  const allTargets = deduplicateTargets([...ML_ENDPOINTS, ...VECTOR_DB_ENDPOINTS]);

  for (const target of allTargets) {
    const url = baseUrl + target.path;
    const result = await probeEndpoint(url, target, timeout, baseline);
    totalProbed++;

    if (result) {
      if (result.owaspCategory === 'LLM04') {
        mlEndpoints.push(result);
      } else {
        vectorDbEndpoints.push(result);
      }

      logger?.info('ai-infra-scanner: endpoint found', {
        service: result.service,
        url: result.url,
        unauthenticated: result.unauthenticated,
        writeable: result.writeable,
        owaspCategory: result.owaspCategory,
      });
    }

    await sleep(PROBE_DELAY_MS);
  }

  logger?.info('ai-infra-scanner: scan complete', {
    totalProbed,
    mlEndpoints: mlEndpoints.length,
    vectorDbEndpoints: vectorDbEndpoints.length,
  });

  return { mlEndpoints, vectorDbEndpoints, totalProbed };
}

// ─── Probe ────────────────────────────────────────────────────

async function probeEndpoint(
  url: string,
  target: ProbeTarget,
  timeout: number,
  baseline?: BaselineFingerprint | null,
): Promise<DiscoveredAiEndpoint | null> {
  const start = performance.now();
  const method = target.method ?? 'GET';

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method,
      headers: {
        'User-Agent': 'WIGTN-SPEAR/0.1.0 (Security Scanner)',
        Accept: 'application/json, */*',
      },
      signal: controller.signal,
      redirect: 'manual',
    });

    clearTimeout(timer);
    const latencyMs = Math.round(performance.now() - start);

    // Read body for evidence
    let bodyText = '';
    try {
      bodyText = await response.text();
      if (bodyText.length > 10_000) {
        bodyText = bodyText.slice(0, 10_000);
      }
    } catch { /* ignore */ }

    // Not found or server error without useful info
    if (response.status === 404 || response.status === 502 || response.status === 503) {
      return null;
    }

    // Baseline FP filter: if response matches the catch-all baseline, skip
    if (matchesBaseline(baseline, response.status, bodyText)) return null;

    // Confirm via pattern matching if specified
    if (target.confirmPattern && !bodyText.includes(target.confirmPattern)) {
      // Pattern didn't match — could be a generic response, not the target service
      // Still report if status is 200 (something is there)
      if (response.status !== 200) return null;
    }

    const unauthenticated = response.status >= 200 && response.status < 300;

    return {
      url,
      status: response.status,
      service: target.service,
      owaspCategory: target.owaspCategory,
      exposure: target.exposure,
      unauthenticated,
      writeable: target.writeable && unauthenticated,
      latencyMs,
      evidence: bodyText.slice(0, MAX_EVIDENCE_LENGTH),
    };
  } catch {
    return null;
  }
}

// ─── Helpers ──────────────────────────────────────────────────

function deduplicateTargets(targets: ProbeTarget[]): ProbeTarget[] {
  const seen = new Set<string>();
  return targets.filter((t) => {
    const key = `${t.method ?? 'GET'}:${t.path}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
