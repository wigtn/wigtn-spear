import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertPinnableActiveOrigins,
  DestinationGuard,
  validateAttackCorpus,
  type AddressResolver,
} from '../src/safety.js';
import { signedManifest, testKeys } from './helpers.js';

test('inert corpus rejects executables, live credentials, real recipients, and external analyzers', () => {
  const { privateKeyPem } = testKeys();
  const manifest = signedManifest(privateKeyPem);
  const valid = {
    schemaVersion: '3.0',
    kind: 'attack-corpus',
    files: [{
      id: 'text-canary',
      filename: 'canary.txt',
      mediaType: 'text/plain',
      contentBase64: Buffer.from('inert marker').toString('base64'),
      inertCanary: true,
    }],
    identities: [{ id: 'user-a', fixture: true, token: 'fixture_user_a' }],
    recipients: ['sink@owned.test'],
    analyzerOrigins: ['http://127.0.0.1:4399'],
  };
  assert.equal(validateAttackCorpus(valid, manifest).files.length, 1);

  const executable = structuredClone(valid);
  executable.files[0]!.contentBase64 = Buffer.from([0x7f, 0x45, 0x4c, 0x46]).toString('base64');
  assert.throws(() => validateAttackCorpus(executable, manifest), /executable content/u);

  const credential = structuredClone(valid);
  credential.identities[0]!.token = 'live-secret-token';
  assert.throws(() => validateAttackCorpus(credential, manifest), /live credential/u);

  const recipient = structuredClone(valid);
  recipient.recipients = ['real@example.com'];
  assert.throws(() => validateAttackCorpus(recipient, manifest), /reserved \.test/u);

  const analyzer = structuredClone(valid);
  analyzer.analyzerOrigins = ['https://analyzer.example.com'];
  assert.throws(() => validateAttackCorpus(analyzer, manifest), /outside owned canary scope/u);
});

test('active runs require IP-literal target origins so the socket can be pinned', () => {
  const { privateKeyPem } = testKeys();
  // IPv4, IPv6, and IP+port literals are pinnable and accepted.
  for (const origin of ['http://127.0.0.1:4310', 'http://203.0.113.10', 'http://[::1]:8080']) {
    const manifest = signedManifest(privateKeyPem, {
      target: {
        name: 'fixture-app',
        repositoryPath: '/workspace/fixture-app',
        buildDigest: `sha256:${'a'.repeat(64)}`,
        origins: [origin],
        environment: 'test',
      },
    });
    assert.doesNotThrow(() => assertPinnableActiveOrigins(manifest));
  }
  // A hostname target would be re-resolved by fetch and is rejected.
  const hostnameManifest = signedManifest(privateKeyPem, {
    target: {
      name: 'fixture-app',
      repositoryPath: '/workspace/fixture-app',
      buildDigest: `sha256:${'a'.repeat(64)}`,
      origins: ['http://fixture.test'],
      environment: 'test',
    },
  });
  assert.throws(() => assertPinnableActiveOrigins(hostnameManifest), /IP-literal host/u);
});

test('destination guard blocks out-of-scope origins, metadata, and DNS rebinding', async () => {
  const { privateKeyPem } = testKeys();
  const manifest = signedManifest(privateKeyPem, {
    target: {
      name: 'fixture-app',
      repositoryPath: '/workspace/fixture-app',
      buildDigest: `sha256:${'a'.repeat(64)}`,
      origins: ['http://fixture.test'],
      environment: 'test',
    },
    safety: {
      allowedHosts: ['fixture.test'],
      allowedCanaryOrigins: [],
      maxRequests: 100,
      maxWallTimeMs: 30_000,
      maxConcurrency: 2,
      maxResponseBytes: 262_144,
      allowMutations: false,
      twinAttested: false,
    },
  });
  let calls = 0;
  const resolver: AddressResolver = {
    async resolve(): Promise<string[]> {
      calls += 1;
      return calls === 1 ? ['203.0.113.10'] : ['203.0.113.11'];
    },
  };
  const guard = new DestinationGuard(manifest, resolver);
  await guard.pin('http://fixture.test', 'target');
  assert.throws(
    () => guard.assertUrl('https://outside.example/path', 'target'),
    /Out-of-scope/u,
  );
  assert.throws(
    () => guard.assertUrl('http://169.254.169.254/latest/meta-data', 'target'),
    /Metadata destination/u,
  );
  await assert.rejects(
    () => guard.revalidate('http://fixture.test/redirected', 'target'),
    /DNS rebinding/u,
  );
});
