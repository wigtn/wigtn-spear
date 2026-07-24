#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { manifestWithSignature } from './authorization.js';
import { evaluateCoverage } from './coverage.js';
import {
  generateEd25519KeyPair,
  signDocument,
} from './crypto.js';
import { diffCoverage, diffFindings } from './diff.js';
import { discoverSurfacesFrom } from './discovery.js';
import {
  createEvidenceBundle,
  pruneEvidenceBundle,
  renderEvidenceMarkdown,
  replayEvidenceBundle,
  retentionDue,
  verifyEvidenceBundle,
  verifyFix,
} from './evidence.js';
import { buildCampaignReport, renderReportMarkdown } from './report.js';
import { runCausalHttpAttack } from './http-runner.js';
import { minimizeCausalProgram } from './minimizer.js';
import { oracleStatePaths } from './oracle.js';
import { AttackTwin, ConstantStateController, type StateController } from './twin.js';
import { HttpControlStateController } from './control-channel.js';
import {
  computePackDescriptorDigest,
  packDescriptor,
  verifyPackRegistry,
} from './registry.js';
import { prepareRunPreview } from './run.js';
import type {
  AuthorizationManifest,
  CandidateFinding,
  CoverageReport,
  PackManifest,
  PackRegistry,
  TwinDefinition,
  UnsignedPackRegistry,
} from './types.js';
import {
  validateAttackProgram,
  validateAuthorizationManifest,
  validateCausalHttpAttackProgram,
  validatePackManifest,
  validateTrustStore,
} from './validation.js';
import {
  isRecord,
  readJsonFile,
  requireArray,
  requireString,
  writeJsonFile,
} from './utils.js';

interface ParsedArgs {
  positionals: string[];
  options: Map<string, string | true>;
}

function parseArgs(args: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options = new Map<string, string | true>();
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index];
    if (!value) continue;
    if (!value.startsWith('--')) {
      positionals.push(value);
      continue;
    }
    const key = value.slice(2);
    const next = args[index + 1];
    if (next && !next.startsWith('--')) {
      options.set(key, next);
      index += 1;
    } else {
      options.set(key, true);
    }
  }
  return { positionals, options };
}

function requiredOption(parsed: ParsedArgs, name: string): string {
  const value = parsed.options.get(name);
  if (typeof value !== 'string') throw new Error(`Missing required option --${name}`);
  return value;
}

function csvOption(parsed: ParsedArgs, name: string, fallback: string[]): string[] {
  const value = parsed.options.get(name);
  if (typeof value !== 'string') return fallback;
  return value.split(',').map((item) => item.trim()).filter(Boolean);
}

async function emit(value: unknown, parsed: ParsedArgs): Promise<void> {
  const output = parsed.options.get('output');
  if (typeof output === 'string') await writeJsonFile(output, value);
  console.log(JSON.stringify(value, null, 2));
}

function printHelp(): void {
  console.log(`SPEAR 0.3.0 — evidence-driven attack verification foundation

Passive:
  spear discover --profile <file> [--openapi <json>] [--next-routes <json>]
                 [--supabase <json>] [--graphql <json>] [--output <file>]
  spear map --profile <file> [--openapi <json>] [--next-routes <json>]
            [--supabase <json>] [--graphql <json>] [--output <file>]
  spear coverage --inventory <file> --profile <file> --registry <file>
                 --trust-store <file> --policy <file> [--output <file>]
  spear diff --from <coverage.json> --to <coverage.json> [--output <file>]
  spear diff --findings --from <report.json> --to <report.json> [--output <file>]
  spear attack validate --program <file>

Signing and trust:
  spear keygen --key-id <id> --private-key <file> --trust-store <file>
  spear manifest sign --input <unsigned.json> --private-key <file>
                      --key-id <id> --output <file>
  spear registry sign --input <unsigned.json> --private-key <file>
                      --key-id <id> --output <file>
  spear registry verify --registry <file> --trust-store <file>

Run preparation (no target access):
  spear run preview --manifest <file> --trust-store <file> --profile <file>
                    --inventory <file> --registry <file> --policy <file>
                    --acknowledge-authorization
                    [--capabilities run:project,discover] [--output <file>]

Twin preflight (verifies the disposable control channel resets deterministically):
  spear twin prepare --manifest <file> --twin <file> [--output <file>]

Active causal run (emits a signed evidence bundle):
  spear run project --manifest <file> --trust-store <file> --profile <file>
                    --inventory <file> --registry <file> --policy <file>
                    --program <file> --twin <file>
                    --evidence-private-key <file> --evidence-key-id <id>
                    --acknowledge-authorization [--minimize]
                    [--retention-days <n>] [--output <bundle.json>]
    response-only oracles (response-contains, differential-access) run with a
    constant Twin; state-observing oracles (state-path-increased/-decreased/
    -changed/-delta-exceeds, partial-effect, canary-egress) require twin.control
    (resetUrl/snapshotUrl) on an owned IP-literal origin.
    --minimize drops attack steps that are not required for the proven predicate.

Evidence (signed causal bundles):
  spear evidence verify --bundle <file> --trust-store <file> [--output <file>]
  spear evidence render --bundle <file> --trust-store <file> [--output <file>]
  spear evidence prune --bundle <file> --trust-store <file>
                       --evidence-private-key <file> --evidence-key-id <id>
                       [--if-expired] [--output <file>]
    --if-expired only prunes once the retention window has elapsed (and is a
    no-op on an already-pruned bundle), so it is safe to run on a schedule.
  spear replay --bundle <file> --trust-store <file> [--output <file>]
  spear verify-fix --original <bundle> --fixed <bundle> --trust-store <file>
                   [--benign-utility-passed] [--output <file>]
  spear report --coverage <file> --trust-store <file> [--bundles <f1,f2>]
               [--candidates <file>] [--format json|md] [--output <file>]

Exit codes:
  0  success (validation/output ok, coverage met, or verify-fix verdict=fixed)
  1  a proven finding is present (run project / evidence verify / replay)
  2  input, signature, safety, or execution error
  3  coverage policy failure, independent of finding count`);
}

async function keygen(parsed: ParsedArgs): Promise<void> {
  const keyId = requiredOption(parsed, 'key-id');
  const privatePath = resolve(requiredOption(parsed, 'private-key'));
  const trustPath = resolve(requiredOption(parsed, 'trust-store'));
  const pair = generateEd25519KeyPair();
  await writeFile(privatePath, pair.privateKeyPem, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  await writeFile(
    trustPath,
    `${JSON.stringify({
      schemaVersion: '3.0',
      keys: [{
        keyId,
        algorithm: 'Ed25519',
        publicKeyPem: pair.publicKeyPem,
        status: 'active',
      }],
    }, null, 2)}\n`,
    { encoding: 'utf8', flag: 'wx', mode: 0o600 },
  );
  console.log(`Created private key ${privatePath} and trust store ${trustPath}`);
}

async function signManifest(parsed: ParsedArgs): Promise<void> {
  const input = await readJsonFile<unknown>(requiredOption(parsed, 'input'));
  if (!isRecord(input)) throw new Error('Unsigned manifest must be an object');
  if ('signature' in input) throw new Error('Input manifest must not already contain signature');
  const privateKeyPem = await readFile(resolve(requiredOption(parsed, 'private-key')), 'utf8');
  const signature = signDocument(input, privateKeyPem, requiredOption(parsed, 'key-id'));
  const signed = manifestWithSignature(
    input as unknown as Omit<AuthorizationManifest, 'signature'>,
    signature,
  );
  await emit(signed, parsed);
}

async function signRegistry(parsed: ParsedArgs): Promise<void> {
  const input = await readJsonFile<unknown>(requiredOption(parsed, 'input'));
  if (!isRecord(input)) throw new Error('Unsigned registry must be an object');
  if ('signature' in input) throw new Error('Input registry must not already contain signature');
  const rawPacks = requireArray(input, 'packs', 'registry');
  const packs: PackManifest[] = rawPacks.map((raw, index) => {
    if (!isRecord(raw)) throw new Error(`registry.packs[${index}] must be an object`);
    const seed = {
      ...raw,
      integrity: {
        algorithm: 'sha256',
        descriptorDigest: `sha256:${'0'.repeat(64)}`,
      },
    };
    const validated = validatePackManifest(seed, `registry.packs[${index}]`);
    return {
      ...packDescriptor(validated),
      integrity: {
        algorithm: 'sha256',
        descriptorDigest: computePackDescriptorDigest(packDescriptor(validated)),
      },
    };
  });
  const unsigned = { ...input, packs } as unknown as UnsignedPackRegistry;
  const privateKeyPem = await readFile(resolve(requiredOption(parsed, 'private-key')), 'utf8');
  const signature = signDocument(
    unsigned as unknown as Record<string, unknown>,
    privateKeyPem,
    requiredOption(parsed, 'key-id'),
  );
  const signed = { ...unsigned, signature } as PackRegistry;
  await emit(signed, parsed);
}

async function optionalJson(parsed: ParsedArgs, name: string): Promise<unknown> {
  const path = parsed.options.get(name);
  return typeof path === 'string' ? readJsonFile<unknown>(path) : undefined;
}

async function commandDiscover(parsed: ParsedArgs): Promise<void> {
  const profile = await readJsonFile<unknown>(requiredOption(parsed, 'profile'));
  const [openApi, nextRoutes, supabase, graphql] = await Promise.all([
    optionalJson(parsed, 'openapi'),
    optionalJson(parsed, 'next-routes'),
    optionalJson(parsed, 'supabase'),
    optionalJson(parsed, 'graphql'),
  ]);
  await emit(
    discoverSurfacesFrom(profile, {
      ...(openApi !== undefined ? { openApi } : {}),
      ...(nextRoutes !== undefined ? { nextRoutes } : {}),
      ...(supabase !== undefined ? { supabase } : {}),
      ...(graphql !== undefined ? { graphql } : {}),
    }),
    parsed,
  );
}

async function commandCoverage(parsed: ParsedArgs): Promise<number> {
  const [inventory, profile, registry, trustStore, policy] = await Promise.all([
    readJsonFile<unknown>(requiredOption(parsed, 'inventory')),
    readJsonFile<unknown>(requiredOption(parsed, 'profile')),
    readJsonFile<unknown>(requiredOption(parsed, 'registry')),
    readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
    readJsonFile<unknown>(requiredOption(parsed, 'policy')),
  ]);
  const report = evaluateCoverage(inventory, profile, registry, trustStore, policy);
  await emit(report, parsed);
  return report.verdict === 'coverage-complete' ? 0 : 3;
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const parsed = parseArgs(argv);
  const [topic, action] = parsed.positionals;
  if (!topic || topic === 'help' || parsed.options.has('help')) {
    printHelp();
    return 0;
  }
  if (topic === 'version' || parsed.options.has('version')) {
    console.log('0.3.0');
    return 0;
  }
  if (topic === 'keygen') {
    await keygen(parsed);
    return 0;
  }
  if (topic === 'manifest' && action === 'sign') {
    await signManifest(parsed);
    return 0;
  }
  if (topic === 'registry' && action === 'sign') {
    await signRegistry(parsed);
    return 0;
  }
  if (topic === 'registry' && action === 'verify') {
    const [registry, trustStore] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'registry')),
      readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
    ]);
    validateTrustStore(trustStore);
    await emit(verifyPackRegistry(registry, trustStore), parsed);
    return 0;
  }
  if (topic === 'discover' || topic === 'map') {
    await commandDiscover(parsed);
    return 0;
  }
  if (topic === 'coverage') return commandCoverage(parsed);
  if (topic === 'attack' && action === 'validate') {
    const program = await readJsonFile<unknown>(requiredOption(parsed, 'program'));
    await emit(validateAttackProgram(program), parsed);
    return 0;
  }
  if (topic === 'run' && action === 'preview') {
    const [manifest, trustStore, profile, inventory, registry, policy] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'manifest')),
      readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
      readJsonFile<unknown>(requiredOption(parsed, 'profile')),
      readJsonFile<unknown>(requiredOption(parsed, 'inventory')),
      readJsonFile<unknown>(requiredOption(parsed, 'registry')),
      readJsonFile<unknown>(requiredOption(parsed, 'policy')),
    ]);
    const preview = prepareRunPreview(
      manifest,
      trustStore,
      profile,
      inventory,
      registry,
      policy,
      {
        acknowledgeAuthorization: parsed.options.get('acknowledge-authorization') === true,
        requiredCapabilities: csvOption(parsed, 'capabilities', ['run:project']),
      },
    );
    await emit(preview, parsed);
    return preview.coverageVerdict === 'coverage-complete' ? 0 : 3;
  }
  if (topic === 'twin' && action === 'prepare') {
    const [manifestInput, twinInput] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'manifest')),
      readJsonFile<unknown>(requiredOption(parsed, 'twin')),
    ]);
    const manifest = validateAuthorizationManifest(manifestInput);
    const twinDefinition = twinInput as TwinDefinition;
    const controller: StateController = twinDefinition.control
      ? new HttpControlStateController(twinDefinition.control, manifest)
      : new ConstantStateController();
    const twin = new AttackTwin(twinDefinition, controller);
    // Drive the control channel end-to-end: reset, baseline snapshot, and a
    // second reset that must reproduce the baseline digest before any attack.
    const baseline = await twin.prepare();
    await twin.resetAndVerify();
    await emit(
      {
        schemaVersion: '3.0',
        kind: 'twin-preflight',
        twinId: twinDefinition.twinId,
        controlChannel: twinDefinition.control ? 'http' : 'constant',
        snapshotId: baseline.snapshotId,
        baselineDigest: baseline.digest,
        resetVerified: true,
      },
      parsed,
    );
    return 0;
  }
  if (topic === 'run' && action === 'project') {
    const [manifest, trustStore, profile, inventory, registry, policy, programInput, twinInput] =
      await Promise.all([
        readJsonFile<unknown>(requiredOption(parsed, 'manifest')),
        readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
        readJsonFile<unknown>(requiredOption(parsed, 'profile')),
        readJsonFile<unknown>(requiredOption(parsed, 'inventory')),
        readJsonFile<unknown>(requiredOption(parsed, 'registry')),
        readJsonFile<unknown>(requiredOption(parsed, 'policy')),
        readJsonFile<unknown>(requiredOption(parsed, 'program')),
        readJsonFile<unknown>(requiredOption(parsed, 'twin')),
      ]);
    const program = validateCausalHttpAttackProgram(programInput);
    const twinDefinition = twinInput as TwinDefinition;
    let controller: StateController;
    // An oracle needs the owned control channel iff it observes state paths;
    // response-only oracles (response-contains, differential-access) run against
    // a constant Twin.
    if (oracleStatePaths(program.oracle).length === 0) {
      controller = new ConstantStateController();
    } else {
      const control = twinDefinition.control;
      if (!control) {
        throw new Error(
          'state-observing oracle requires an owned Twin control channel; add twin.control '
          + '(resetUrl/snapshotUrl) and verify it first with `spear twin prepare`',
        );
      }
      controller = new HttpControlStateController(control, validateAuthorizationManifest(manifest));
    }
    const evidenceKeyPem = await readFile(
      resolve(requiredOption(parsed, 'evidence-private-key')),
      'utf8',
    );
    const twin = new AttackTwin(twinDefinition, controller);
    const acknowledge = parsed.options.get('acknowledge-authorization') === true;
    const runInputs = { manifest, trustStore, profile, inventory, registry, policy, twin };
    const run = await runCausalHttpAttack(
      { ...runInputs, program },
      { acknowledgeAuthorization: acknowledge },
    );
    let minimizedGraphPath: string[] | undefined;
    if (parsed.options.get('minimize') === true && run.disposition === 'proven') {
      const minimized = await minimizeCausalProgram(
        program,
        (candidate) => runCausalHttpAttack(
          { ...runInputs, program: candidate },
          { acknowledgeAuthorization: acknowledge },
        ),
      );
      minimizedGraphPath = minimized.graphPath;
    }
    const retentionDaysOption = parsed.options.get('retention-days');
    const retentionDays = typeof retentionDaysOption === 'string'
      ? Number(retentionDaysOption)
      : undefined;
    if (retentionDays !== undefined && (!Number.isFinite(retentionDays) || retentionDays <= 0)) {
      throw new Error('--retention-days must be a positive number');
    }
    const bundle = createEvidenceBundle(
      run,
      program,
      { privateKeyPem: evidenceKeyPem, keyId: requiredOption(parsed, 'evidence-key-id') },
      new Date(),
      minimizedGraphPath,
      retentionDays,
    );
    await emit(bundle, parsed);
    if (run.disposition === 'proven') return 1;
    if (run.disposition === 'error') return 2;
    return 0;
  }
  if (topic === 'diff') {
    if (parsed.options.get('findings') === true) {
      const [from, to] = await Promise.all([
        readJsonFile<unknown>(requiredOption(parsed, 'from')),
        readJsonFile<unknown>(requiredOption(parsed, 'to')),
      ]);
      await emit(diffFindings(from, to), parsed);
      return 0;
    }
    const [from, to] = await Promise.all([
      readJsonFile<CoverageReport>(requiredOption(parsed, 'from')),
      readJsonFile<CoverageReport>(requiredOption(parsed, 'to')),
    ]);
    await emit(diffCoverage(from, to), parsed);
    return 0;
  }
  if (topic === 'evidence' && action === 'prune') {
    const [bundle, trustStore] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'bundle')),
      readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
    ]);
    // --if-expired makes prune a safe cron/CI no-op until the retention window
    // elapses (and on an already-pruned bundle), so it needs no signing key to run.
    const verified = verifyEvidenceBundle(bundle, trustStore);
    if (verified.retention.grade === 'redacted-only') {
      process.stderr.write('Bundle is already redacted-only; no changes.\n');
      await emit(verified, parsed);
      return 0;
    }
    if (parsed.options.get('if-expired') === true && !retentionDue(verified)) {
      process.stderr.write(
        `Retention window not elapsed (raw expires ${verified.retention.rawExpiresAt}); no changes.\n`,
      );
      await emit(verified, parsed);
      return 0;
    }
    const evidenceKeyPem = await readFile(
      resolve(requiredOption(parsed, 'evidence-private-key')),
      'utf8',
    );
    const pruned = pruneEvidenceBundle(bundle, trustStore, {
      privateKeyPem: evidenceKeyPem,
      keyId: requiredOption(parsed, 'evidence-key-id'),
    });
    await emit(pruned, parsed);
    return 0;
  }
  if (topic === 'evidence' && (action === 'verify' || action === 'render')) {
    const [bundle, trustStore] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'bundle')),
      readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
    ]);
    if (action === 'render') {
      const markdown = renderEvidenceMarkdown(bundle, trustStore);
      const output = parsed.options.get('output');
      if (typeof output === 'string') await writeFile(resolve(output), markdown, 'utf8');
      console.log(markdown);
      return 0;
    }
    const verified = verifyEvidenceBundle(bundle, trustStore);
    await emit(
      {
        schemaVersion: '3.0',
        kind: 'evidence-verification',
        bundleId: verified.bundleId,
        bundleDigest: verified.bundleDigest,
        signatureKeyId: verified.signature.keyId,
        disposition: verified.run.disposition,
        verified: true,
      },
      parsed,
    );
    return verified.run.disposition === 'proven' ? 1 : 0;
  }
  if (topic === 'replay') {
    const [bundle, trustStore] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'bundle')),
      readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
    ]);
    const replay = replayEvidenceBundle(bundle, trustStore);
    await emit(replay, parsed);
    return replay.replayedDisposition === 'proven' ? 1 : 0;
  }
  if (topic === 'verify-fix') {
    const [originalBundle, fixedBundle, trustStore] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'original')),
      readJsonFile<unknown>(requiredOption(parsed, 'fixed')),
      readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
    ]);
    const original = verifyEvidenceBundle(originalBundle, trustStore);
    const fixed = verifyEvidenceBundle(fixedBundle, trustStore);
    const result = verifyFix(
      original.run,
      fixed.run,
      parsed.options.get('benign-utility-passed') === true,
    );
    await emit(result, parsed);
    return result.verdict === 'fixed' ? 0 : 1;
  }
  if (topic === 'report') {
    const [coverage, trustStore] = await Promise.all([
      readJsonFile<unknown>(requiredOption(parsed, 'coverage')),
      readJsonFile<unknown>(requiredOption(parsed, 'trust-store')),
    ]);
    const bundlePaths = csvOption(parsed, 'bundles', []);
    const bundles = await Promise.all(bundlePaths.map((path) => readJsonFile<unknown>(path)));
    const candidatesInput = await optionalJson(parsed, 'candidates');
    const candidates = Array.isArray(candidatesInput)
      ? (candidatesInput as CandidateFinding[])
      : [];
    const report = buildCampaignReport(coverage, bundles, candidates, trustStore);
    if (parsed.options.get('format') === 'md') {
      const markdown = renderReportMarkdown(report);
      const output = parsed.options.get('output');
      if (typeof output === 'string') await writeFile(resolve(output), markdown, 'utf8');
      console.log(markdown);
    } else {
      await emit(report, parsed);
    }
    if (report.coverage.verdict !== 'coverage-complete') return 3;
    return report.findings.proven.length > 0 ? 1 : 0;
  }
  throw new Error(`Unknown command: ${parsed.positionals.join(' ')}`);
}

const isEntryPoint = process.argv[1] !== undefined
  && fileURLToPath(import.meta.url) === resolve(process.argv[1]);

if (isEntryPoint) {
  main()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((error: unknown) => {
      console.error(`SPEAR error: ${error instanceof Error ? error.message : String(error)}`);
      process.exitCode = 2;
    });
}
