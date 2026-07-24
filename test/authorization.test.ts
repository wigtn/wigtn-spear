import assert from 'node:assert/strict';
import test from 'node:test';
import { verifyAuthorization } from '../src/authorization.js';
import { SpearSafetyError } from '../src/errors.js';
import {
  BUILD_DIGEST,
  signedManifest,
  testKeys,
} from './helpers.js';

const NOW = new Date('2026-07-23T00:00:00.000Z');

test('accepts an active signed test authorization with exact capability and build', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const result = verifyAuthorization(signedManifest(privateKeyPem), trustStore, {
    acknowledgeAuthorization: true,
    requiredCapabilities: ['run:project'],
    actualBuildDigest: BUILD_DIGEST,
    now: NOW,
  });
  assert.match(result.manifestDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(result.manifest.target.environment, 'test');
});

test('rejects missing acknowledgement, production, expiry, capability, build, and revoked key', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const manifest = signedManifest(privateKeyPem);
  const base = {
    acknowledgeAuthorization: true,
    requiredCapabilities: ['run:project'],
    actualBuildDigest: BUILD_DIGEST,
    now: NOW,
  };

  assert.throws(
    () => verifyAuthorization(manifest, trustStore, { ...base, acknowledgeAuthorization: false }),
    SpearSafetyError,
  );
  assert.throws(
    () => verifyAuthorization(
      signedManifest(privateKeyPem, {
        target: { ...manifest.target, environment: 'production' },
      }),
      trustStore,
      base,
    ),
    /production-class/u,
  );
  assert.throws(
    () => verifyAuthorization(manifest, trustStore, {
      ...base,
      now: new Date('2026-08-02T00:00:00.000Z'),
    }),
    /expired/u,
  );
  assert.throws(
    () => verifyAuthorization(manifest, trustStore, {
      ...base,
      requiredCapabilities: ['run:compound'],
    }),
    /missing capabilities/u,
  );
  assert.throws(
    () => verifyAuthorization(manifest, trustStore, {
      ...base,
      actualBuildDigest: `sha256:${'b'.repeat(64)}`,
    }),
    /build digest mismatch/u,
  );
  const revoked = structuredClone(trustStore);
  revoked.keys[0]!.status = 'revoked';
  assert.throws(() => verifyAuthorization(manifest, revoked, base), /revoked/u);
  const unknown = structuredClone(trustStore);
  unknown.keys[0]!.keyId = 'different-key';
  assert.throws(() => verifyAuthorization(manifest, unknown, base), /Unknown or duplicate/u);
});

test('detects manifest tampering before an active callback can run', () => {
  const { privateKeyPem, trustStore } = testKeys();
  const tampered = structuredClone(signedManifest(privateKeyPem));
  tampered.safety.maxRequests += 1;
  let targetEvents = 0;
  const activeBoundary = (): void => {
    verifyAuthorization(tampered, trustStore, {
      acknowledgeAuthorization: true,
      requiredCapabilities: ['run:project'],
      actualBuildDigest: BUILD_DIGEST,
      now: NOW,
    });
    targetEvents += 1;
  };
  assert.throws(activeBoundary, /signature is invalid/u);
  assert.equal(targetEvents, 0);
});
