/**
 * SecureSecret: Safe handling of secret values
 *
 * Principles:
 * 1. Raw secret exists only in memory, never written to disk
 * 2. Masking is irreversible (cannot recover original from masked value)
 * 3. Memory zeroed before GC (best-effort)
 */
export class SecureSecret {
  private buffer: Buffer;
  private disposed = false;

  constructor(raw: string) {
    this.buffer = Buffer.from(raw, 'utf-8');
  }

  /**
   * Masking algorithm:
   * - length >= 8: first 4 chars + '****' + last 4 chars
   *   e.g. "AKIAIOSFODNN7EXAMPLE" → "AKIA****MPLE"
   * - 4 <= length < 8: first 2 chars + '****'
   *   e.g. "abc123" → "ab****"
   * - length < 4: '****' (full mask)
   *   e.g. "key" → "****"
   */
  mask(): string {
    this.assertNotDisposed();
    const str = this.buffer.toString('utf-8');
    const len = str.length;
    if (len >= 8) return str.slice(0, 4) + '****' + str.slice(-4);
    if (len >= 4) return str.slice(0, 2) + '****';
    return '****';
  }

  /**
   * Only use raw value for live API verification (in memory).
   * Call dispose() immediately after verification completes.
   */
  unsafeRawForVerification(): string {
    this.assertNotDisposed();
    return this.buffer.toString('utf-8');
  }

  /**
   * Zero out memory (best-effort).
   * Buffer.fill(0) overwrites original data.
   * V8 GC doesn't guarantee 100% erasure, but minimizes memory scan attack surface.
   */
  dispose(): void {
    if (!this.disposed) {
      this.buffer.fill(0);
      this.disposed = true;
    }
  }

  get isDisposed(): boolean {
    return this.disposed;
  }

  private assertNotDisposed(): void {
    if (this.disposed) {
      throw new Error('SecureSecret has been disposed');
    }
  }

  toString(): string {
    return this.mask();
  }

  toJSON(): string {
    return this.mask();
  }

  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `SecureSecret(${this.disposed ? 'DISPOSED' : this.mask()})`;
  }
}
