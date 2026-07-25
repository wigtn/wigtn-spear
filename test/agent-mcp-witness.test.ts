import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import test from 'node:test';
import { runMcpCausalAttack, startMcpWitnessProxy } from '../src/agent/index.js';

// A fake MCP server: a tools/call for `leak_secret` returns an admin token in its
// result (the exfil); any other tool returns clean content.
function fakeMcpUpstream(): Promise<{ server: Server; url: string }> {
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      let name = '';
      try { name = JSON.parse(Buffer.concat(chunks).toString('utf8')).params?.name ?? ''; } catch { /* empty */ }
      const result = name === 'leak_secret'
        ? { content: [{ type: 'text', text: 'Fetched: {"token":"adm-temp-ssrf-2026","role":"admin"}' }] }
        : { content: [{ type: 'text', text: 'ok, nothing sensitive here' }] };
      res.statusCode = 200;
      res.setHeader('content-type', 'application/json');
      res.setHeader('mcp-session-id', 'sess-1');
      res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp` })));
}

async function toolCall(origin: string, name: string): Promise<void> {
  await fetch(`${origin}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'mcp-session-id': 'sess-1' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: {} } }),
  });
}

test('MCP witness proxy observes a forbidden canary leaking through a tool result', async () => {
  const upstream = await fakeMcpUpstream();
  const proxy = await startMcpWitnessProxy({ upstream: upstream.url, canaries: [/adm-[a-z0-9-]+/iu, /FLAG\{[^}]+\}/u] });
  try {
    // A benign tool call: nothing leaks → no observation.
    await toolCall(proxy.origin, 'status');
    assert.equal(proxy.observedLeak(), false);

    // The exfil tool call: the admin token appears in the RESULT → witnessed.
    await toolCall(proxy.origin, 'leak_secret');
    assert.equal(proxy.observedLeak(), true);
    assert.equal(proxy.observations.at(-1)?.tool, 'leak_secret');
    assert.ok(proxy.observations.at(-1)?.leaked.includes('adm-temp-ssrf-2026'));

    // Reset clears state for the next attempt/phase.
    proxy.reset();
    assert.equal(proxy.observedLeak(), false);
  } finally {
    await proxy.close();
    await new Promise<void>((r) => upstream.server.close(() => r()));
  }
});

test('runMcpCausalAttack proves a leak caused by the attack driver, and rejects a canned always-on exploit', async () => {
  const upstream = await fakeMcpUpstream();
  const proxy = await startMcpWitnessProxy({ upstream: upstream.url, canaries: [/adm-[a-z0-9-]+/iu] });
  try {
    // A driver that leaks ONLY under attack → proven (the malicious input is the cause).
    const proven = await runMcpCausalAttack({
      proxy,
      drive: (phase) => toolCall(proxy.origin, phase === 'attack' ? 'leak_secret' : 'status'),
    });
    assert.equal(proven.disposition, 'proven');
    assert.equal(proven.baselineObserved, false);
    assert.equal(proven.counterfactualObserved, false);
    assert.ok(proven.leaked.some((o) => o.leaked.includes('adm-temp-ssrf-2026')));

    // A "canned exploit" that fires regardless of input → the leak shows in baseline
    // too, so it is NOT proven: the malicious input was not demonstrated as the cause.
    const canned = await runMcpCausalAttack({ proxy, drive: () => toolCall(proxy.origin, 'leak_secret') });
    assert.equal(canned.disposition, 'rejected');
    assert.equal(canned.baselineObserved, true);

    // A driver that never leaks → rejected.
    const clean = await runMcpCausalAttack({ proxy, drive: () => toolCall(proxy.origin, 'status') });
    assert.equal(clean.disposition, 'rejected');
  } finally {
    await proxy.close();
    await new Promise<void>((r) => upstream.server.close(() => r()));
  }
});
