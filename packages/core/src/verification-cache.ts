/**
 * Verification Cache -- LRU cache for API verification results.
 *
 * Used in aggressive mode to avoid redundant live verification calls
 * for secrets that have already been checked. The cache key is a hash
 * of the masked secret value (never the raw secret).
 *
 * Features:
 *   - LRU eviction when maxSize is reached (default: 1000 entries)
 *   - TTL-based expiry (default: 1 hour)
 *   - Hit/miss statistics for monitoring cache effectiveness
 *   - Single-threaded safe (Node.js event loop), future-proof for
 *     worker thread scenarios via copy-on-read semantics
 *
 * Usage:
 *   const cache = new VerificationCache({ maxSize: 500, ttlMs: 30 * 60 * 1000 });
 *
 *   const cached = cache.get(maskedKey);
 *   if (cached) {
 *     // Use cached result
 *   } else {
 *     const result = await verifySecret(secret);
 *     cache.set(maskedKey, {
 *       verified: result.verified,
 *       active: result.active,
 *       service: result.service,
 *       permissions: result.permissions,
 *       cachedAt: Date.now(),
 *     });
 *   }
 */

// ─── Types ───────────────────────────────────────────────────

export interface CacheEntry {
  /** Whether the secret was successfully verified against the API */
  verified: boolean;
  /** Whether the secret is currently active (valid credentials) */
  active: boolean;
  /** Service name that was verified (e.g. 'github', 'aws', 'slack') */
  service?: string;
  /** Permissions/scopes associated with the credential */
  permissions?: string[];
  /** Timestamp when this entry was cached (epoch ms) */
  cachedAt: number;
}

export interface VerificationCacheOptions {
  /** Maximum number of entries before LRU eviction. Default: 1000 */
  maxSize?: number;
  /** Time-to-live in milliseconds. Entries older than this are expired. Default: 3600000 (1 hour) */
  ttlMs?: number;
}

// ─── Constants ───────────────────────────────────────────────

/** Default maximum cache size */
const DEFAULT_MAX_SIZE = 1000;

/** Default TTL: 1 hour in milliseconds */
const DEFAULT_TTL_MS = 60 * 60 * 1000;

// ─── Internal Node ───────────────────────────────────────────

/**
 * Doubly-linked list node for LRU ordering.
 *
 * We maintain a Map for O(1) lookup and a doubly-linked list for O(1)
 * promotion/eviction. This gives us O(1) get/set/has operations.
 */
interface CacheNode {
  key: string;
  entry: CacheEntry;
  prev: CacheNode | null;
  next: CacheNode | null;
}

// ─── VerificationCache ───────────────────────────────────────

export class VerificationCache {
  private readonly maxSize: number;
  private readonly ttlMs: number;

  /** Key -> CacheNode for O(1) lookup */
  private readonly map: Map<string, CacheNode> = new Map();

  /** Most recently used node (front of the list) */
  private head: CacheNode | null = null;

  /** Least recently used node (back of the list) */
  private tail: CacheNode | null = null;

  /** Cache hit counter */
  private hitCount = 0;

  /** Cache miss counter */
  private missCount = 0;

  constructor(options?: VerificationCacheOptions) {
    this.maxSize = options?.maxSize ?? DEFAULT_MAX_SIZE;
    this.ttlMs = options?.ttlMs ?? DEFAULT_TTL_MS;
  }

  /**
   * Get a cached verification result by key.
   *
   * Returns undefined if:
   *   - The key is not in the cache
   *   - The entry has expired (TTL exceeded)
   *
   * On a hit, the entry is promoted to the front of the LRU list.
   *
   * @param key - Cache key (should be hash of masked secret)
   * @returns The cached entry, or undefined on miss/expiry
   */
  get(key: string): CacheEntry | undefined {
    const node = this.map.get(key);

    if (!node) {
      this.missCount++;
      return undefined;
    }

    // Check TTL expiry
    if (this.isExpired(node.entry)) {
      // Remove expired entry
      this.removeNode(node);
      this.map.delete(key);
      this.missCount++;
      return undefined;
    }

    // Promote to front (most recently used)
    this.moveToFront(node);
    this.hitCount++;

    // Return a shallow copy to prevent external mutation
    return { ...node.entry };
  }

  /**
   * Store a verification result in the cache.
   *
   * If the key already exists, the entry is updated and promoted.
   * If the cache is full, the least recently used entry is evicted.
   *
   * @param key   - Cache key (should be hash of masked secret)
   * @param entry - The verification result to cache
   */
  set(key: string, entry: CacheEntry): void {
    const existing = this.map.get(key);

    if (existing) {
      // Update existing entry and promote
      existing.entry = { ...entry };
      this.moveToFront(existing);
      return;
    }

    // Evict LRU entries if at capacity
    while (this.map.size >= this.maxSize && this.tail) {
      const evicted = this.tail;
      this.removeNode(evicted);
      this.map.delete(evicted.key);
    }

    // Create new node and add to front
    const node: CacheNode = {
      key,
      entry: { ...entry },
      prev: null,
      next: null,
    };

    this.addToFront(node);
    this.map.set(key, node);
  }

  /**
   * Check if a key exists in the cache and has not expired.
   *
   * Does NOT count as a hit/miss and does NOT promote the entry.
   * Use this for existence checks without affecting LRU ordering.
   *
   * @param key - Cache key
   * @returns true if key exists and is not expired
   */
  has(key: string): boolean {
    const node = this.map.get(key);
    if (!node) return false;

    if (this.isExpired(node.entry)) {
      // Clean up expired entry
      this.removeNode(node);
      this.map.delete(key);
      return false;
    }

    return true;
  }

  /**
   * Clear all entries from the cache and reset statistics.
   */
  clear(): void {
    this.map.clear();
    this.head = null;
    this.tail = null;
    this.hitCount = 0;
    this.missCount = 0;
  }

  /**
   * Get cache statistics.
   *
   * @returns Object with current size, hit/miss counts, and hit rate
   */
  stats(): { size: number; hits: number; misses: number; hitRate: number } {
    const total = this.hitCount + this.missCount;
    return {
      size: this.map.size,
      hits: this.hitCount,
      misses: this.missCount,
      hitRate: total > 0 ? this.hitCount / total : 0,
    };
  }

  // ─── Private: Linked List Operations ───────────────────────

  /**
   * Check whether a cache entry has exceeded its TTL.
   */
  private isExpired(entry: CacheEntry): boolean {
    return Date.now() - entry.cachedAt > this.ttlMs;
  }

  /**
   * Add a node to the front of the doubly-linked list.
   */
  private addToFront(node: CacheNode): void {
    node.prev = null;
    node.next = this.head;

    if (this.head) {
      this.head.prev = node;
    }

    this.head = node;

    if (!this.tail) {
      this.tail = node;
    }
  }

  /**
   * Remove a node from the doubly-linked list.
   */
  private removeNode(node: CacheNode): void {
    if (node.prev) {
      node.prev.next = node.next;
    } else {
      // Node is the head
      this.head = node.next;
    }

    if (node.next) {
      node.next.prev = node.prev;
    } else {
      // Node is the tail
      this.tail = node.prev;
    }

    node.prev = null;
    node.next = null;
  }

  /**
   * Move an existing node to the front of the list (most recently used).
   */
  private moveToFront(node: CacheNode): void {
    if (node === this.head) return; // Already at front
    this.removeNode(node);
    this.addToFront(node);
  }
}
