/**
 * Rate Limiter -- Per-service rate limiting for API verification requests.
 *
 * Implements a sliding-window token bucket algorithm with concurrent request
 * limiting. Designed for the aggressive mode secret verification pipeline
 * where SPEAR makes live API calls to validate discovered credentials.
 *
 * Features:
 *   - Per-service rate limits (different APIs have different thresholds)
 *   - Sliding window RPM enforcement (requests per minute)
 *   - Concurrent request capping (prevents connection exhaustion)
 *   - Queuing with backpressure (acquire() returns a promise that resolves
 *     when a slot becomes available)
 *   - Default config: { rpm: 60, concurrent: 5 }
 *
 * Usage:
 *   const limiter = new RateLimiter();
 *   limiter.setServiceLimit('github', { rpm: 30, concurrent: 3 });
 *
 *   await limiter.acquire('github');
 *   try {
 *     await verifyGitHubToken(token);
 *   } finally {
 *     limiter.release('github');
 *   }
 */

// ─── Types ───────────────────────────────────────────────────

export interface RateLimiterConfig {
  /** Requests per minute per service */
  rpm: number;
  /** Maximum concurrent requests per service */
  concurrent: number;
}

/** Internal queued waiter -- resolved when a slot becomes available */
interface QueuedWaiter {
  resolve: () => void;
}

// ─── Constants ───────────────────────────────────────────────

/** Default rate limit applied to services with no explicit configuration. */
const DEFAULT_CONFIG: RateLimiterConfig = {
  rpm: 60,
  concurrent: 5,
};

/** Sliding window duration in milliseconds (1 minute). */
const WINDOW_MS = 60_000;

/** Polling interval when waiting for a rate limit slot (ms). */
const POLL_INTERVAL_MS = 100;

// ─── RateLimiter ─────────────────────────────────────────────

export class RateLimiter {
  /** Per-service rate limit configuration */
  private readonly configs: Map<string, RateLimiterConfig> = new Map();

  /** Per-service sliding window of request timestamps (epoch ms) */
  private readonly windows: Map<string, number[]> = new Map();

  /** Per-service count of currently active (in-flight) requests */
  private readonly active: Map<string, number> = new Map();

  /** Per-service FIFO queue of waiters blocked on acquire() */
  private readonly queues: Map<string, QueuedWaiter[]> = new Map();

  /** Fallback config used when no service-specific config is set */
  private readonly defaultConfig: RateLimiterConfig;

  constructor(defaults?: RateLimiterConfig) {
    this.defaultConfig = defaults ?? { ...DEFAULT_CONFIG };
  }

  /**
   * Set or update the rate limit configuration for a specific service.
   *
   * @param service - Service identifier (e.g. 'github', 'aws', 'slack')
   * @param config  - Rate limit parameters for this service
   */
  setServiceLimit(service: string, config: RateLimiterConfig): void {
    this.configs.set(service, { ...config });
  }

  /**
   * Acquire permission to make a request to a service.
   *
   * If the service has available capacity (both RPM and concurrent slots),
   * resolves immediately. Otherwise, the returned promise blocks until a
   * slot becomes available.
   *
   * Callers MUST call release() when the request completes (use try/finally).
   *
   * @param service - Service identifier
   * @returns Promise that resolves when a slot is available
   */
  async acquire(service: string): Promise<void> {
    const config = this.getConfig(service);

    // Fast path: check if we can proceed immediately
    if (this.canProceed(service, config)) {
      this.recordRequest(service);
      return;
    }

    // Slow path: queue and wait
    return new Promise<void>((resolve) => {
      const waiter: QueuedWaiter = { resolve };
      let queue = this.queues.get(service);
      if (!queue) {
        queue = [];
        this.queues.set(service, queue);
      }
      queue.push(waiter);

      // Start a polling loop to check when a slot opens.
      // We use polling rather than event-driven notification because
      // RPM windows expire based on time, not just on release() calls.
      const interval = setInterval(() => {
        // Prune expired timestamps from the window
        this.pruneWindow(service);

        if (this.canProceed(service, config)) {
          clearInterval(interval);

          // Remove this waiter from the queue
          const q = this.queues.get(service);
          if (q) {
            const idx = q.indexOf(waiter);
            if (idx !== -1) {
              q.splice(idx, 1);
            }
          }

          this.recordRequest(service);
          resolve();
        }
      }, POLL_INTERVAL_MS);
    });
  }

  /**
   * Release a request slot after completion.
   *
   * Decrements the active count for the service. If there are queued
   * waiters, the next one will be unblocked on the next poll cycle.
   *
   * @param service - Service identifier
   */
  release(service: string): void {
    const current = this.active.get(service) ?? 0;
    if (current > 0) {
      this.active.set(service, current - 1);
    }
  }

  /**
   * Get current rate limiter stats for a service.
   *
   * @param service - Service identifier
   * @returns Object with current RPM usage, active count, and queue depth
   */
  getStats(service: string): { rpm: number; active: number; queued: number } {
    this.pruneWindow(service);

    const window = this.windows.get(service) ?? [];
    const active = this.active.get(service) ?? 0;
    const queue = this.queues.get(service) ?? [];

    return {
      rpm: window.length,
      active,
      queued: queue.length,
    };
  }

  // ─── Private Helpers ───────────────────────────────────────

  /**
   * Get the effective config for a service (service-specific or default).
   */
  private getConfig(service: string): RateLimiterConfig {
    return this.configs.get(service) ?? this.defaultConfig;
  }

  /**
   * Check whether a new request can proceed without violating limits.
   */
  private canProceed(service: string, config: RateLimiterConfig): boolean {
    // Check concurrent limit
    const active = this.active.get(service) ?? 0;
    if (active >= config.concurrent) {
      return false;
    }

    // Check RPM limit (sliding window)
    this.pruneWindow(service);
    const window = this.windows.get(service) ?? [];
    if (window.length >= config.rpm) {
      return false;
    }

    return true;
  }

  /**
   * Record a new request: add timestamp to window and increment active count.
   */
  private recordRequest(service: string): void {
    // Add to sliding window
    let window = this.windows.get(service);
    if (!window) {
      window = [];
      this.windows.set(service, window);
    }
    window.push(Date.now());

    // Increment active count
    const active = this.active.get(service) ?? 0;
    this.active.set(service, active + 1);
  }

  /**
   * Remove timestamps older than the sliding window duration.
   */
  private pruneWindow(service: string): void {
    const window = this.windows.get(service);
    if (!window || window.length === 0) return;

    const cutoff = Date.now() - WINDOW_MS;
    // Since timestamps are appended in order, find the first valid index
    let firstValid = 0;
    while (firstValid < window.length && window[firstValid]! < cutoff) {
      firstValid++;
    }

    if (firstValid > 0) {
      window.splice(0, firstValid);
    }
  }
}
