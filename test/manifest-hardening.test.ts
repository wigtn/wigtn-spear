import assert from 'node:assert/strict';
import test from 'node:test';
import { validateAuthorizationManifest } from '../src/validation.js';
import { signedManifest, testKeys } from './helpers.js';

test('manifest validation rejects a relative repository path', () => {
  const { privateKeyPem } = testKeys();
  const base = signedManifest(privateKeyPem);
  const manifest = { ...base, target: { ...base.target, repositoryPath: 'workspace/app' } };
  assert.throws(() => validateAuthorizationManifest(manifest), /absolute path/u);
});

test('manifest validation rejects a non-canonical canary origin', () => {
  const { privateKeyPem } = testKeys();
  const base = signedManifest(privateKeyPem);
  const manifest = {
    ...base,
    safety: { ...base.safety, allowedCanaryOrigins: ['http://127.0.0.1:4399/callback'] },
  };
  assert.throws(() => validateAuthorizationManifest(manifest), /allowedCanaryOrigins/u);
});

test('manifest validation rejects a non-canonical control origin', () => {
  const { privateKeyPem } = testKeys();
  const base = signedManifest(privateKeyPem);
  const manifest = {
    ...base,
    safety: { ...base.safety, allowedControlOrigins: ['http://127.0.0.1:4500/'] },
  };
  // A trailing path segment on the origin is not a canonical exact origin.
  const withPath = {
    ...manifest,
    safety: { ...manifest.safety, allowedControlOrigins: ['http://127.0.0.1:4500/state'] },
  };
  assert.throws(() => validateAuthorizationManifest(withPath), /allowedControlOrigins/u);
});

test('manifest validation accepts canonical IP-literal origins and control channel', () => {
  const { privateKeyPem } = testKeys();
  const base = signedManifest(privateKeyPem);
  const manifest = {
    ...base,
    safety: {
      ...base.safety,
      allowedCanaryOrigins: ['http://127.0.0.1:4399'],
      allowedControlOrigins: ['http://127.0.0.1:4500'],
    },
  };
  assert.doesNotThrow(() => validateAuthorizationManifest(manifest));
});
