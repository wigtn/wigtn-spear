import assert from 'node:assert/strict';
import test from 'node:test';
import { cookieHeader, parseSetCookie, type StoredCookie } from '../src/http-runner.js';

test('parseSetCookie extracts name, value, path, and secure', () => {
  const parsed = parseSetCookie('session=abc123; Path=/app; Secure; HttpOnly');
  assert.ok(parsed);
  assert.equal(parsed.name, 'session');
  assert.equal(parsed.value, 'abc123');
  assert.equal(parsed.path, '/app');
  assert.equal(parsed.secure, true);
  assert.equal(parsed.expired, false);
});

test('parseSetCookie flags Max-Age<=0 and past Expires as expired deletions', () => {
  assert.equal(parseSetCookie('x=1; Max-Age=0')?.expired, true);
  assert.equal(parseSetCookie('x=1; Max-Age=-5')?.expired, true);
  assert.equal(parseSetCookie('x=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT')?.expired, true);
  assert.equal(parseSetCookie('x=1; Max-Age=3600')?.expired, false);
});

test('parseSetCookie rejects malformed cookies', () => {
  assert.equal(parseSetCookie(''), null);
  assert.equal(parseSetCookie('=novalue'), null);
  assert.equal(parseSetCookie('flag-only'), null);
});

test('cookieHeader applies path scoping and the secure attribute', () => {
  const jar = new Map<string, StoredCookie>([
    ['root', { value: 'r', path: '/', secure: false }],
    ['scoped', { value: 's', path: '/admin', secure: false }],
    ['locked', { value: 'l', path: '/', secure: true }],
  ]);

  // HTTP request under /admin: root + scoped are sent; secure cookie is withheld.
  const adminHttp = cookieHeader(jar, new URL('http://127.0.0.1/admin/panel'));
  assert.ok(adminHttp?.includes('root=r'));
  assert.ok(adminHttp?.includes('scoped=s'));
  assert.ok(!adminHttp?.includes('locked=l'));

  // A path outside /admin drops the scoped cookie.
  const rootHttp = cookieHeader(jar, new URL('http://127.0.0.1/public'));
  assert.ok(rootHttp?.includes('root=r'));
  assert.ok(!rootHttp?.includes('scoped=s'));

  // HTTPS carries the secure cookie.
  const https = cookieHeader(jar, new URL('https://127.0.0.1/public'));
  assert.ok(https?.includes('locked=l'));
});

test('cookieHeader honors RFC 6265 path boundaries (no /admin leak to /administrator)', () => {
  const jar = new Map<string, StoredCookie>([['scoped', { value: 's', path: '/admin', secure: false }]]);
  // Exact and sub-path under a boundary match.
  assert.ok(cookieHeader(jar, new URL('http://127.0.0.1/admin'))?.includes('scoped=s'));
  assert.ok(cookieHeader(jar, new URL('http://127.0.0.1/admin/users'))?.includes('scoped=s'));
  // A sibling path that merely shares the prefix must NOT match.
  assert.equal(cookieHeader(jar, new URL('http://127.0.0.1/administrator')), undefined);
});

test('cookieHeader returns undefined when nothing matches', () => {
  const jar = new Map<string, StoredCookie>([['secure', { value: 'v', path: '/', secure: true }]]);
  assert.equal(cookieHeader(jar, new URL('http://127.0.0.1/')), undefined);
});
