/**
 * @wigtn/core - Core Engine for WIGTN-SPEAR
 *
 * This package provides the core scanning engine used by all SPEAR modules.
 * It implements a multi-stage pipeline that processes files through:
 *
 *   1. Aho-Corasick keyword pre-filtering (O(n) multi-pattern matching)
 *   2. Regex pattern matching with ReDoS protection
 *   3. Shannon entropy analysis for secret detection
 *   4. Worker thread parallelism for large codebases
 *
 * All exports use ES module syntax with .js extensions for Node16 resolution.
 */

// --- Engine: Aho-Corasick Multi-Pattern Matcher ---
export {
  AhoCorasick,
  AhoCorasickCaseInsensitive,
  type AhoCorasickMatch,
} from './engine/aho-corasick.js';

// --- Engine: Regex Pattern Matcher ---
export {
  RegexMatcher,
  type RegexMatch,
} from './engine/regex-matcher.js';

// --- Engine: Shannon Entropy Analysis ---
export {
  shannonEntropy,
  isHighEntropy,
  classifyEntropy,
} from './engine/entropy.js';

// --- Engine: Worker Thread Pool ---
export {
  WorkerPool,
} from './engine/worker-pool.js';

// --- Engine: Scan Pipeline ---
export {
  scanPipeline,
  discoverFiles,
  readFileContent,
  type PipelineOptions,
} from './engine/pipeline.js';

// --- Spearignore ---
export {
  loadSpearignore,
  getDefaultIgnores,
  createSpearignore,
} from './spearignore.js';

// --- Rate Limiter ---
export {
  RateLimiter,
} from './rate-limiter.js';
export type { RateLimiterConfig } from './rate-limiter.js';

// --- Verification Cache ---
export {
  VerificationCache,
} from './verification-cache.js';
export type { CacheEntry } from './verification-cache.js';
