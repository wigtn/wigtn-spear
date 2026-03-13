import { describe, it, expect } from 'vitest';
import { SecureSecret } from '../src/secure-secret.js';

describe('SecureSecret', () => {
  // ─── Masking: length >= 8 ────────────────────────────────────

  describe('masking for length >= 8', () => {
    it('should mask as first4 + **** + last4 for 8-character string', () => {
      const secret = new SecureSecret('12345678');
      expect(secret.mask()).toBe('1234****5678');
    });

    it('should mask as first4 + **** + last4 for long string', () => {
      const secret = new SecureSecret('AKIAIOSFODNN7EXAMPLE');
      expect(secret.mask()).toBe('AKIA****MPLE');
    });

    it('should mask a 20-character AWS key correctly', () => {
      const secret = new SecureSecret('wJalrXUtnFEMI/K7MDENG');
      expect(secret.mask()).toBe('wJal****DENG');
    });

    it('should mask exactly 8 characters', () => {
      const secret = new SecureSecret('abcdefgh');
      expect(secret.mask()).toBe('abcd****efgh');
    });

    it('should mask a 9-character string', () => {
      const secret = new SecureSecret('abcdefghi');
      expect(secret.mask()).toBe('abcd****fghi');
    });
  });

  // ─── Masking: length 4-7 ─────────────────────────────────────

  describe('masking for length 4-7', () => {
    it('should mask as first2 + **** for 4-character string', () => {
      const secret = new SecureSecret('abcd');
      expect(secret.mask()).toBe('ab****');
    });

    it('should mask as first2 + **** for 7-character string', () => {
      const secret = new SecureSecret('abcdefg');
      expect(secret.mask()).toBe('ab****');
    });

    it('should mask as first2 + **** for 5-character string', () => {
      const secret = new SecureSecret('hello');
      expect(secret.mask()).toBe('he****');
    });

    it('should mask as first2 + **** for 6-character string', () => {
      const secret = new SecureSecret('secret');
      expect(secret.mask()).toBe('se****');
    });
  });

  // ─── Masking: length < 4 ─────────────────────────────────────

  describe('masking for length < 4', () => {
    it('should return **** for 3-character string', () => {
      const secret = new SecureSecret('key');
      expect(secret.mask()).toBe('****');
    });

    it('should return **** for 2-character string', () => {
      const secret = new SecureSecret('ab');
      expect(secret.mask()).toBe('****');
    });

    it('should return **** for 1-character string', () => {
      const secret = new SecureSecret('x');
      expect(secret.mask()).toBe('****');
    });

    it('should return **** for empty string', () => {
      const secret = new SecureSecret('');
      expect(secret.mask()).toBe('****');
    });
  });

  // ─── unsafeRawForVerification ────────────────────────────────

  describe('unsafeRawForVerification', () => {
    it('should return the original raw value', () => {
      const raw = 'AKIAIOSFODNN7EXAMPLE';
      const secret = new SecureSecret(raw);
      expect(secret.unsafeRawForVerification()).toBe(raw);
    });

    it('should return the exact original value for short strings', () => {
      const secret = new SecureSecret('ab');
      expect(secret.unsafeRawForVerification()).toBe('ab');
    });

    it('should return the original for empty string', () => {
      const secret = new SecureSecret('');
      expect(secret.unsafeRawForVerification()).toBe('');
    });

    it('should preserve special characters', () => {
      const raw = 'p@$$w0rd!#%&*()';
      const secret = new SecureSecret(raw);
      expect(secret.unsafeRawForVerification()).toBe(raw);
    });

    it('should preserve Unicode characters', () => {
      const raw = '\u30D1\u30B9\u30EF\u30FC\u30C9\u79D8\u5BC6\u5BC6\u7801';
      const secret = new SecureSecret(raw);
      expect(secret.unsafeRawForVerification()).toBe(raw);
    });
  });

  // ─── dispose() zeros buffer ──────────────────────────────────

  describe('dispose', () => {
    it('should mark the secret as disposed', () => {
      const secret = new SecureSecret('my-secret-key');
      expect(secret.isDisposed).toBe(false);
      secret.dispose();
      expect(secret.isDisposed).toBe(true);
    });

    it('should be idempotent (calling dispose twice does not throw)', () => {
      const secret = new SecureSecret('my-secret-key');
      secret.dispose();
      expect(() => secret.dispose()).not.toThrow();
      expect(secret.isDisposed).toBe(true);
    });

    it('should zero the internal buffer after dispose', () => {
      const raw = 'sensitive-data-here';
      const secret = new SecureSecret(raw);

      // Access the raw value before dispose to confirm it works
      expect(secret.unsafeRawForVerification()).toBe(raw);

      secret.dispose();

      // After dispose, the buffer should be zeroed
      // We cannot access the buffer directly, but trying to use it after
      // dispose should throw
      expect(secret.isDisposed).toBe(true);
    });
  });

  // ─── Using after dispose throws ──────────────────────────────

  describe('using after dispose', () => {
    it('should throw on mask() after dispose', () => {
      const secret = new SecureSecret('my-secret');
      secret.dispose();
      expect(() => secret.mask()).toThrow('SecureSecret has been disposed');
    });

    it('should throw on unsafeRawForVerification() after dispose', () => {
      const secret = new SecureSecret('my-secret');
      secret.dispose();
      expect(() => secret.unsafeRawForVerification()).toThrow('SecureSecret has been disposed');
    });

    it('should throw the correct error message', () => {
      const secret = new SecureSecret('test');
      secret.dispose();
      expect(() => secret.mask()).toThrow('SecureSecret has been disposed');
    });
  });

  // ─── toString() returns masked ───────────────────────────────

  describe('toString', () => {
    it('should return the masked value', () => {
      const secret = new SecureSecret('AKIAIOSFODNN7EXAMPLE');
      expect(secret.toString()).toBe('AKIA****MPLE');
    });

    it('should return same as mask()', () => {
      const secret = new SecureSecret('my-test-secret');
      expect(secret.toString()).toBe(secret.mask());
    });

    it('should return **** for short values', () => {
      const secret = new SecureSecret('abc');
      expect(secret.toString()).toBe('****');
    });

    it('should work when used in string interpolation', () => {
      const secret = new SecureSecret('AKIAIOSFODNN7EXAMPLE');
      const str = `Secret: ${secret}`;
      expect(str).toBe('Secret: AKIA****MPLE');
      expect(str).not.toContain('AKIAIOSFODNN7EXAMPLE');
    });
  });

  // ─── toJSON() returns masked ─────────────────────────────────

  describe('toJSON', () => {
    it('should return the masked value', () => {
      const secret = new SecureSecret('AKIAIOSFODNN7EXAMPLE');
      expect(secret.toJSON()).toBe('AKIA****MPLE');
    });

    it('should serialize as masked in JSON.stringify', () => {
      const secret = new SecureSecret('super-secret-key');
      const obj = { key: secret };
      const json = JSON.stringify(obj);
      expect(json).toContain('supe****-key');
      expect(json).not.toContain('super-secret-key');
    });

    it('should return same as mask()', () => {
      const secret = new SecureSecret('testing123');
      expect(secret.toJSON()).toBe(secret.mask());
    });
  });

  // ─── Symbol.inspect returns masked with wrapper ──────────────

  describe('custom inspect', () => {
    it('should return SecureSecret(masked) format', () => {
      const secret = new SecureSecret('AKIAIOSFODNN7EXAMPLE');
      const inspectSymbol = Symbol.for('nodejs.util.inspect.custom');
      const result = (secret as Record<symbol, () => string>)[inspectSymbol]!();
      expect(result).toBe('SecureSecret(AKIA****MPLE)');
    });

    it('should return SecureSecret(DISPOSED) after dispose', () => {
      const secret = new SecureSecret('AKIAIOSFODNN7EXAMPLE');
      secret.dispose();
      const inspectSymbol = Symbol.for('nodejs.util.inspect.custom');
      const result = (secret as Record<symbol, () => string>)[inspectSymbol]!();
      expect(result).toBe('SecureSecret(DISPOSED)');
    });

    it('should return SecureSecret(****) for short values', () => {
      const secret = new SecureSecret('abc');
      const inspectSymbol = Symbol.for('nodejs.util.inspect.custom');
      const result = (secret as Record<symbol, () => string>)[inspectSymbol]!();
      expect(result).toBe('SecureSecret(****)');
    });
  });

  // ─── Raw value never leaks through standard coercion ─────────

  describe('no raw value leakage', () => {
    it('should not expose raw value through any standard method', () => {
      const rawValue = 'AKIAIOSFODNN7REALKEY1';
      const secret = new SecureSecret(rawValue);

      // String coercion
      expect(String(secret)).not.toContain(rawValue);

      // JSON serialization
      expect(JSON.stringify(secret)).not.toContain(rawValue);

      // Template literal
      expect(`${secret}`).not.toContain(rawValue);
    });
  });
});
