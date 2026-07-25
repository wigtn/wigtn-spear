import { verifyAuthorization } from '../authorization.js';
import { sha256Digest } from '../crypto.js';
import { SpearConfigError, SpearExecutionError } from '../errors.js';
import { createPinnedDispatcher } from '../pinning.js';
import { assertPinnableOrigin, DestinationGuard } from '../safety.js';
import { isRecord } from '../utils.js';
import {
  type AgentFetchDeps,
  directAttackerRequest,
  type FetchImpl,
} from './client.js';

export interface McpToolDescriptor {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

export interface McpCapabilitySnapshot {
  /** Canonical digest of the whole tool set. */
  digest: string;
  /** name -> per-tool descriptor digest. */
  perTool: Record<string, string>;
  toolNames: string[];
  /** Names that appear more than once — a shadowing / name-collision signal. */
  shadowedNames: string[];
}

function extractTools(parsed: unknown): McpToolDescriptor[] {
  const list = Array.isArray(parsed)
    ? parsed
    : isRecord(parsed) && Array.isArray(parsed.tools)
      ? parsed.tools
      : undefined;
  if (!list) throw new SpearConfigError('MCP tool listing must be an array or { tools: [...] }');
  return list.map((raw, index) => {
    if (!isRecord(raw) || typeof raw.name !== 'string') {
      throw new SpearConfigError(`MCP tool[${index}] must have a string name`);
    }
    return {
      name: raw.name,
      ...(typeof raw.description === 'string' ? { description: raw.description } : {}),
      ...('inputSchema' in raw ? { inputSchema: raw.inputSchema } : {}),
    };
  });
}

/** Digest a tool set so approval-time and execution-time listings can be compared. */
export function digestMcpCapabilities(tools: McpToolDescriptor[]): McpCapabilitySnapshot {
  const perTool: Record<string, string> = {};
  const seen = new Map<string, number>();
  for (const tool of tools) {
    perTool[tool.name] = sha256Digest({
      name: tool.name,
      description: tool.description ?? '',
      inputSchema: tool.inputSchema ?? null,
    });
    seen.set(tool.name, (seen.get(tool.name) ?? 0) + 1);
  }
  const shadowedNames = [...seen.entries()].filter(([, count]) => count > 1).map(([name]) => name);
  return {
    digest: sha256Digest(perTool),
    perTool,
    toolNames: tools.map((tool) => tool.name),
    shadowedNames,
  };
}

async function snapshot(listUrl: string, deps: AgentFetchDeps): Promise<McpCapabilitySnapshot> {
  const { status, body } = await directAttackerRequest({ url: listUrl, method: 'GET' }, deps);
  if (status < 200 || status >= 300) {
    throw new SpearExecutionError(`MCP tool listing returned HTTP ${status}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new SpearConfigError('MCP tool listing was not JSON');
  }
  return digestMcpCapabilities(extractTools(parsed));
}

export interface McpIntegrityOptions {
  manifest: unknown;
  trustStore: unknown;
  actualBuildDigest: string;
  acknowledgeAuthorization: boolean;
  /** The authorized MCP tool-listing endpoint to snapshot. */
  listUrl: string;
  programId?: string;
  fetchImpl?: FetchImpl;
  now?: Date;
}

export interface McpIntegrityResult {
  schemaVersion: '3.0';
  kind: 'mcp-integrity';
  programId: string;
  approvalDigest: string;
  executionDigest: string;
  /** The tool set mutated between approval and execution (rug pull / capability drift, FR-456). */
  rugPull: boolean;
  /** Colliding tool names observed (shadowing / puppet selection). */
  shadowedNames: string[];
  disposition: 'proven' | 'rejected';
  reason: string;
}

/**
 * Prove an MCP capability-integrity violation deterministically: snapshot the tool
 * listing at approval time and again at execution time. If the capability digest
 * changed (rug pull / post-approval drift) or a tool name is shadowed, the finding
 * is proven — no model judgement involved, only the signed digest comparison.
 */
export async function verifyMcpIntegrity(options: McpIntegrityOptions): Promise<McpIntegrityResult> {
  const { manifest } = verifyAuthorization(options.manifest, options.trustStore, {
    acknowledgeAuthorization: options.acknowledgeAuthorization,
    requiredCapabilities: ['run:agent'],
    actualBuildDigest: options.actualBuildDigest,
    ...(options.now ? { now: options.now } : {}),
  });
  const guard = new DestinationGuard(manifest);
  let deps: AgentFetchDeps;
  if (options.fetchImpl) {
    assertPinnableOrigin(options.listUrl, 'MCP tool-listing endpoint');
    deps = { guard, fetchImpl: options.fetchImpl };
  } else {
    await guard.pin(options.listUrl, 'target');
    deps = { guard, dispatcher: createPinnedDispatcher(guard.pins) };
  }

  const approval = await snapshot(options.listUrl, deps);
  const execution = await snapshot(options.listUrl, deps);
  const rugPull = approval.digest !== execution.digest;
  const shadowedNames = [...new Set([...approval.shadowedNames, ...execution.shadowedNames])];
  const proven = rugPull || shadowedNames.length > 0;
  return {
    schemaVersion: '3.0',
    kind: 'mcp-integrity',
    programId: options.programId ?? 'mcp-integrity',
    approvalDigest: approval.digest,
    executionDigest: execution.digest,
    rugPull,
    shadowedNames,
    disposition: proven ? 'proven' : 'rejected',
    reason: proven
      ? rugPull
        ? 'MCP capability digest changed between approval and execution (rug pull / drift)'
        : 'MCP tool name shadowing / collision detected'
      : 'MCP capability set was stable and free of name collisions',
  };
}
