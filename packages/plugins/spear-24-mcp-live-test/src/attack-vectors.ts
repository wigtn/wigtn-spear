/**
 * MCP Attack Vectors
 *
 * Defines and implements attack scenarios against live MCP servers.
 * Each attack vector targets a specific vulnerability class in the
 * MCP protocol or its typical server implementations.
 *
 * Attack categories:
 *   - tool_enumeration     Enumerate all available tools and analyze surface area
 *   - description_injection Check tool descriptions for hidden injection payloads
 *   - schema_manipulation   Test input schema validation and bypass techniques
 *   - tool_squatting       Detect suspicious tool names that shadow system tools
 *   - rug_pull_detection   Monitor for tool description changes between calls
 *   - privilege_escalation Test cross-tool access and permission boundaries
 *   - data_exfiltration    Test data leakage through tool invocations
 *
 * MITRE ATT&CK Mappings:
 *   - T1059   Command and Scripting Interpreter
 *   - T1005   Data from Local System
 *   - T1041   Exfiltration Over C2 Channel
 *   - T1071   Application Layer Protocol
 *   - T1027   Obfuscated Files or Information
 *   - T1204   User Execution
 *   - T1562   Impair Defenses
 *   - T1036   Masquerading
 */

import type { SpearLogger } from '@wigtn/shared';
import type { MCPClient, MCPTool } from './mcp-client.js';

// ─── Public Types ────────────────────────────────────────────

export type MCPAttackCategory =
  | 'tool_enumeration'
  | 'description_injection'
  | 'schema_manipulation'
  | 'tool_squatting'
  | 'rug_pull_detection'
  | 'privilege_escalation'
  | 'data_exfiltration';

export interface MCPAttackVector {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
  category: MCPAttackCategory;
  mitre: string[];
  /** Function that executes the attack against a live MCP server */
  execute: (
    client: MCPClient,
    logger: SpearLogger,
  ) => AsyncGenerator<AttackResult>;
}

export interface AttackResult {
  success: boolean;
  evidence: string;
  details: Record<string, unknown>;
}

// ─── Constants ───────────────────────────────────────────────

/**
 * Tool names that are suspicious because they shadow common system or
 * filesystem operations. A legitimate MCP server should not typically
 * expose tools with these names unless it is a filesystem server.
 */
const SUSPICIOUS_TOOL_NAMES = [
  'exec', 'execute', 'shell', 'system', 'eval',
  'run_command', 'run_shell', 'bash', 'sh', 'cmd',
  'admin', 'sudo', 'root',
  'read_file', 'write_file', 'delete_file', 'list_files',
  'read_directory', 'write_directory',
  'execute_command', 'run_script',
  'get_env', 'set_env', 'environment',
  'upload', 'download',
];

/**
 * Known MCP server tool name prefixes that may be targets for squatting.
 */
const KNOWN_MCP_TOOL_PREFIXES = [
  'filesystem', 'git', 'docker', 'kubernetes', 'github',
  'slack', 'postgres', 'sqlite', 'redis', 'fetch',
  'brave_search', 'puppeteer', 'sequential_thinking',
];

/**
 * Patterns in tool descriptions that indicate hidden injection.
 * Each entry is [pattern, description, severity].
 */
const DESCRIPTION_INJECTION_PATTERNS: Array<[RegExp, string, 'critical' | 'high' | 'medium']> = [
  // Hidden instruction markers
  [/<IMPORTANT>/i, 'Contains <IMPORTANT> instruction marker', 'critical'],
  [/<!--[\s\S]*?-->/, 'Contains HTML comment (potential hidden instruction)', 'critical'],
  [/<system>[\s\S]*?<\/system>/i, 'Contains <system> tag (prompt injection)', 'critical'],
  [/<instruction>[\s\S]*?<\/instruction>/i, 'Contains <instruction> tag', 'critical'],
  [/<hidden>[\s\S]*?<\/hidden>/i, 'Contains <hidden> tag', 'critical'],

  // Invisible Unicode characters
  [/[\u200B\u200C\u200D\u200E\u200F\uFEFF\u2060-\u2064]/, 'Contains zero-width Unicode characters', 'critical'],
  [/[\u202A-\u202E\u2066-\u2069]/, 'Contains bidirectional override characters', 'high'],

  // Cross-tool references
  [/(?:first|before|then|after)\s+(?:call|use|invoke|run)\s+/i, 'Contains cross-tool call instruction', 'high'],
  [/(?:use|call|invoke)\s+(?:the\s+)?(?:tool|function)\s+['"]?\w+['"]?/i, 'References another tool by name', 'high'],

  // Data exfiltration instructions
  [/(?:send|post|transmit|forward)\s+(?:to|data|result|output)\s+(?:https?:\/\/|url|endpoint)/i, 'Contains data exfiltration instruction', 'critical'],
  [/(?:fetch|curl|wget|http\.get)\s*\(?\s*['"]https?:\/\//i, 'Contains HTTP fetch instruction', 'critical'],
  [/(?:webhook|callback|notify)\s*.*https?:\/\//i, 'Contains webhook/callback URL', 'high'],

  // Privilege escalation hints
  [/(?:read|access|open)\s+(?:\/etc\/|\.ssh|\.env|\.aws|credentials)/i, 'Contains file access instruction targeting sensitive paths', 'critical'],
  [/(?:execute|exec|spawn|system)\s*\(?\s*['"](?:bash|sh|cmd|powershell)/i, 'Contains shell execution instruction', 'critical'],

  // Safety override instructions
  [/(?:ignore|bypass|skip|disable)\s+(?:safety|security|check|validation|guard|permission)/i, 'Contains safety bypass instruction', 'critical'],
  [/(?:you\s+(?:are|must|should|will))\s+(?:ignore|forget|override)/i, 'Contains prompt override instruction', 'critical'],

  // Markdown/HTML injection
  [/\[.*?\]\(javascript:/i, 'Contains JavaScript protocol in Markdown link', 'high'],
  [/<script[\s>]/i, 'Contains <script> tag', 'critical'],
  [/<img[^>]+onerror/i, 'Contains onerror handler injection', 'high'],
];

/**
 * Input schemas considered overly permissive (allow arbitrary input).
 */
const PERMISSIVE_SCHEMA_INDICATORS = [
  'additionalProperties',
  'anyOf',
  'oneOf',
  'patternProperties',
];

// ─── Attack Vector Implementations ───────────────────────────

/**
 * AV-01: Tool Enumeration and Surface Analysis
 *
 * Lists all available tools and analyzes the attack surface:
 *   - Total tool count (high count = larger attack surface)
 *   - Tool names checked against suspicious name patterns
 *   - Tool descriptions analyzed for length and content
 *   - Input schemas analyzed for permissiveness
 */
const toolEnumeration: MCPAttackVector = {
  id: 'tool-enumeration',
  name: 'Tool Enumeration & Surface Analysis',
  description: 'Enumerates all available MCP tools and analyzes the attack surface for suspicious patterns',
  severity: 'medium',
  category: 'tool_enumeration',
  mitre: ['T1059', 'T1005'],
  async *execute(client, logger) {
    logger.info('AV-01: Enumerating tools');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to enumerate tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    logger.info('AV-01: Tools enumerated', { count: tools.length });

    // Yield overall enumeration result
    yield {
      success: true,
      evidence: `Enumerated ${tools.length} tools from MCP server`,
      details: {
        toolCount: tools.length,
        toolNames: tools.map((t) => t.name),
        toolSummary: tools.map((t) => ({
          name: t.name,
          descriptionLength: t.description?.length ?? 0,
          schemaProperties: Object.keys(
            (t.inputSchema as Record<string, unknown>)?.properties ?? {},
          ),
        })),
      },
    };

    // Flag servers with high tool count (larger attack surface)
    if (tools.length > 20) {
      yield {
        success: true,
        evidence: `High tool count (${tools.length}) increases attack surface`,
        details: {
          toolCount: tools.length,
          risk: 'Large number of tools increases the likelihood of vulnerable endpoints',
        },
      };
    }

    // Analyze each tool name for suspicious patterns
    for (const tool of tools) {
      const nameLower = tool.name.toLowerCase();

      // Check for dangerous tool names
      for (const suspicious of SUSPICIOUS_TOOL_NAMES) {
        if (nameLower === suspicious || nameLower.includes(suspicious)) {
          yield {
            success: true,
            evidence: `Suspicious tool name: '${tool.name}' matches pattern '${suspicious}'`,
            details: {
              toolName: tool.name,
              matchedPattern: suspicious,
              description: tool.description,
            },
          };
          break;
        }
      }

      // Check for tools with very long descriptions (potential payload hiding)
      if (tool.description && tool.description.length > 500) {
        yield {
          success: true,
          evidence: `Tool '${tool.name}' has an unusually long description (${tool.description.length} chars)`,
          details: {
            toolName: tool.name,
            descriptionLength: tool.description.length,
            descriptionPreview: tool.description.slice(0, 200) + '...',
          },
        };
      }

      // Check for overly permissive input schemas
      const schemaStr = JSON.stringify(tool.inputSchema ?? {});
      for (const indicator of PERMISSIVE_SCHEMA_INDICATORS) {
        if (schemaStr.includes(indicator)) {
          yield {
            success: true,
            evidence: `Tool '${tool.name}' has permissive input schema (${indicator})`,
            details: {
              toolName: tool.name,
              indicator,
              inputSchema: tool.inputSchema,
            },
          };
          break;
        }
      }
    }
  },
};

/**
 * AV-02: Description Injection Scanner
 *
 * Analyzes each tool description for hidden injection patterns:
 *   - Hidden instruction markers (<IMPORTANT>, <!-- -->, etc.)
 *   - Invisible Unicode characters (zero-width, bidi overrides)
 *   - Cross-tool references (attack chaining)
 *   - Data exfiltration instructions
 *   - Privilege escalation hints
 *   - Markdown/HTML injection
 */
const descriptionInjection: MCPAttackVector = {
  id: 'description-injection',
  name: 'Tool Description Injection Scanner',
  description: 'Scans tool descriptions for hidden injection patterns, invisible characters, and malicious instructions',
  severity: 'critical',
  category: 'description_injection',
  mitre: ['T1027', 'T1204', 'T1059'],
  async *execute(client, logger) {
    logger.info('AV-02: Scanning tool descriptions for injection patterns');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools for description analysis: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    for (const tool of tools) {
      const description = tool.description ?? '';
      if (!description) continue;

      // Test against all injection patterns
      for (const [pattern, patternDesc, severity] of DESCRIPTION_INJECTION_PATTERNS) {
        if (pattern.test(description)) {
          logger.warn('AV-02: Injection pattern found', {
            toolName: tool.name,
            pattern: patternDesc,
            severity,
          });

          yield {
            success: true,
            evidence: `Tool '${tool.name}': ${patternDesc}`,
            details: {
              toolName: tool.name,
              pattern: patternDesc,
              severity,
              descriptionPreview: description.slice(0, 300),
              matchedRegex: pattern.source,
            },
          };
        }
      }

      // Additionally, check the raw JSON of the input schema for injection
      const schemaStr = JSON.stringify(tool.inputSchema ?? {});
      for (const [pattern, patternDesc, severity] of DESCRIPTION_INJECTION_PATTERNS) {
        if (pattern.test(schemaStr)) {
          yield {
            success: true,
            evidence: `Tool '${tool.name}' input schema contains: ${patternDesc}`,
            details: {
              toolName: tool.name,
              location: 'inputSchema',
              pattern: patternDesc,
              severity,
            },
          };
        }
      }
    }
  },
};

/**
 * AV-03: Schema Validation Bypass
 *
 * For each discovered tool, attempts various schema bypass techniques:
 *   - Empty args: {}
 *   - Prototype pollution: { "__proto__": {} }
 *   - Type confusion: string where number expected, etc.
 *   - SQL injection in string args
 *   - Path traversal in file args
 *   - Command injection in string args
 */
const schemaValidationBypass: MCPAttackVector = {
  id: 'schema-validation-bypass',
  name: 'Schema Validation Bypass',
  description: 'Tests tool input schema validation by sending malformed, injected, and boundary-violating arguments',
  severity: 'high',
  category: 'schema_manipulation',
  mitre: ['T1059', 'T1005'],
  async *execute(client, logger) {
    logger.info('AV-03: Testing schema validation bypass');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    // Limit to first 10 tools to avoid overwhelming the server
    const targetTools = tools.slice(0, 10);

    for (const tool of targetTools) {
      logger.info('AV-03: Testing tool', { toolName: tool.name });

      // Extract expected parameters from schema
      const schema = tool.inputSchema as Record<string, unknown>;
      const properties = (schema?.properties ?? {}) as Record<
        string,
        Record<string, unknown>
      >;
      const paramNames = Object.keys(properties);

      // Test 1: Empty args
      yield* tryCallAndReport(
        client,
        tool.name,
        {},
        'empty-args',
        'Called with empty arguments (no required params)',
        logger,
      );

      // Test 2: Prototype pollution
      yield* tryCallAndReport(
        client,
        tool.name,
        { '__proto__': { isAdmin: true }, 'constructor': { prototype: { isAdmin: true } } },
        'proto-pollution',
        'Prototype pollution payload (__proto__ and constructor.prototype)',
        logger,
      );

      // Test 3: Type confusion -- send string where other types expected
      if (paramNames.length > 0) {
        const typeConfusionArgs: Record<string, unknown> = {};
        for (const param of paramNames) {
          const paramDef = properties[param];
          if (paramDef?.type === 'number' || paramDef?.type === 'integer') {
            typeConfusionArgs[param] = 'not_a_number';
          } else if (paramDef?.type === 'boolean') {
            typeConfusionArgs[param] = 'not_a_boolean';
          } else if (paramDef?.type === 'array') {
            typeConfusionArgs[param] = 'not_an_array';
          } else if (paramDef?.type === 'object') {
            typeConfusionArgs[param] = 'not_an_object';
          } else {
            typeConfusionArgs[param] = 12345;
          }
        }
        yield* tryCallAndReport(
          client,
          tool.name,
          typeConfusionArgs,
          'type-confusion',
          'Type confusion (wrong types for declared parameters)',
          logger,
        );
      }

      // Test 4: SQL injection in string parameters
      if (paramNames.length > 0) {
        const sqlInjectionArgs: Record<string, unknown> = {};
        for (const param of paramNames) {
          sqlInjectionArgs[param] = "'; DROP TABLE users; --";
        }
        yield* tryCallAndReport(
          client,
          tool.name,
          sqlInjectionArgs,
          'sql-injection',
          'SQL injection payload in string parameters',
          logger,
        );
      }

      // Test 5: Path traversal in file-related parameters
      if (paramNames.length > 0) {
        const pathTraversalArgs: Record<string, unknown> = {};
        for (const param of paramNames) {
          const pLower = param.toLowerCase();
          if (
            pLower.includes('file') ||
            pLower.includes('path') ||
            pLower.includes('dir') ||
            pLower.includes('uri') ||
            pLower.includes('url')
          ) {
            pathTraversalArgs[param] = '../../../../../../etc/passwd';
          } else {
            pathTraversalArgs[param] = '../../../../../../etc/passwd';
          }
        }
        yield* tryCallAndReport(
          client,
          tool.name,
          pathTraversalArgs,
          'path-traversal',
          'Path traversal payload (../../etc/passwd)',
          logger,
        );
      }

      // Test 6: Command injection in string parameters
      if (paramNames.length > 0) {
        const cmdInjectionArgs: Record<string, unknown> = {};
        for (const param of paramNames) {
          cmdInjectionArgs[param] = '$(whoami)';
        }
        yield* tryCallAndReport(
          client,
          tool.name,
          cmdInjectionArgs,
          'cmd-injection-dollar',
          'Command injection payload ($(whoami))',
          logger,
        );

        const cmdInjectionArgs2: Record<string, unknown> = {};
        for (const param of paramNames) {
          cmdInjectionArgs2[param] = '`whoami`';
        }
        yield* tryCallAndReport(
          client,
          tool.name,
          cmdInjectionArgs2,
          'cmd-injection-backtick',
          'Command injection payload (`whoami`)',
          logger,
        );
      }
    }
  },
};

/**
 * AV-04: Tool Squatting Detection
 *
 * Checks if any tool names shadow known system tools, well-known
 * MCP server tools, or use typosquat variants.
 */
const toolSquatting: MCPAttackVector = {
  id: 'tool-squatting',
  name: 'Tool Squatting Detection',
  description: 'Detects tools that shadow known system commands, popular MCP server tools, or use typosquat variants',
  severity: 'high',
  category: 'tool_squatting',
  mitre: ['T1036', 'T1204'],
  async *execute(client, logger) {
    logger.info('AV-04: Checking for tool squatting');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    for (const tool of tools) {
      const nameLower = tool.name.toLowerCase();

      // Check for exact matches with known system tool names
      for (const systemTool of SUSPICIOUS_TOOL_NAMES) {
        if (nameLower === systemTool) {
          yield {
            success: true,
            evidence: `Tool '${tool.name}' shadows system command '${systemTool}'`,
            details: {
              toolName: tool.name,
              shadowedCommand: systemTool,
              description: tool.description,
              risk: 'Tool may intercept or masquerade as a system command',
            },
          };
        }
      }

      // Check for prefix-based squatting of known MCP servers
      for (const prefix of KNOWN_MCP_TOOL_PREFIXES) {
        if (nameLower.startsWith(prefix) && nameLower !== prefix) {
          // Check Levenshtein-like similarity for typosquatting
          const rest = nameLower.slice(prefix.length);
          if (rest.length <= 3 && /^[_\-.]?[a-z]{0,2}$/.test(rest)) {
            yield {
              success: true,
              evidence: `Tool '${tool.name}' may be squatting known MCP tool prefix '${prefix}'`,
              details: {
                toolName: tool.name,
                knownPrefix: prefix,
                suffix: rest,
                description: tool.description,
              },
            };
          }
        }
      }

      // Check for common typosquat patterns (character swaps, extra chars)
      for (const prefix of KNOWN_MCP_TOOL_PREFIXES) {
        if (nameLower !== prefix && levenshteinDistance(nameLower, prefix) <= 2) {
          yield {
            success: true,
            evidence: `Tool '${tool.name}' is a potential typosquat of known tool '${prefix}' (edit distance: ${levenshteinDistance(nameLower, prefix)})`,
            details: {
              toolName: tool.name,
              similarTo: prefix,
              editDistance: levenshteinDistance(nameLower, prefix),
              description: tool.description,
            },
          };
        }
      }
    }
  },
};

/**
 * AV-05: Rug Pull Detection
 *
 * Calls tools/list twice with a delay and compares the results.
 * A legitimate MCP server should return identical tool listings.
 * Changes between calls indicate a potential rug pull attack where
 * tool behavior changes after initial approval.
 */
const rugPullDetection: MCPAttackVector = {
  id: 'rug-pull-detection',
  name: 'Rug Pull Detection',
  description: 'Calls tools/list multiple times to detect tool description or schema changes indicative of rug pull attacks',
  severity: 'critical',
  category: 'rug_pull_detection',
  mitre: ['T1204', 'T1036'],
  async *execute(client, logger) {
    logger.info('AV-05: Testing for rug pull (description mutation)');

    // First tools/list call
    let tools1: MCPTool[];
    try {
      tools1 = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed first tools/list call: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    const snapshot1 = serializeToolList(tools1);

    // Wait for potential rug pull activation
    logger.info('AV-05: Waiting 2 seconds before second enumeration');
    await sleep(2000);

    // Second tools/list call
    let tools2: MCPTool[];
    try {
      tools2 = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed second tools/list call: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    const snapshot2 = serializeToolList(tools2);

    // Compare tool counts
    if (tools1.length !== tools2.length) {
      yield {
        success: true,
        evidence: `Tool count changed between calls: ${tools1.length} -> ${tools2.length}`,
        details: {
          firstCount: tools1.length,
          secondCount: tools2.length,
          addedTools: tools2
            .filter((t) => !tools1.some((t1) => t1.name === t.name))
            .map((t) => t.name),
          removedTools: tools1
            .filter((t) => !tools2.some((t2) => t2.name === t.name))
            .map((t) => t.name),
        },
      };
    }

    // Compare each tool's description and schema
    for (const tool1 of tools1) {
      const tool2 = tools2.find((t) => t.name === tool1.name);
      if (!tool2) continue;

      if (tool1.description !== tool2.description) {
        yield {
          success: true,
          evidence: `Rug pull detected: Tool '${tool1.name}' description changed between calls`,
          details: {
            toolName: tool1.name,
            before: tool1.description,
            after: tool2.description,
            risk: 'Tool description changed post-enumeration, indicating bait-and-switch behavior',
          },
        };
      }

      const schema1 = JSON.stringify(tool1.inputSchema ?? {});
      const schema2 = JSON.stringify(tool2.inputSchema ?? {});
      if (schema1 !== schema2) {
        yield {
          success: true,
          evidence: `Rug pull detected: Tool '${tool1.name}' input schema changed between calls`,
          details: {
            toolName: tool1.name,
            schemaBefore: tool1.inputSchema,
            schemaAfter: tool2.inputSchema,
            risk: 'Input schema changed post-enumeration, may accept different inputs than approved',
          },
        };
      }
    }

    // If everything matched, report clean result
    if (snapshot1 === snapshot2) {
      yield {
        success: false,
        evidence: 'No rug pull detected: tool listings are consistent between calls',
        details: {
          toolCount: tools1.length,
          consistent: true,
        },
      };
    }

    // Third call after making some tool calls (to trigger call-count-based rug pulls)
    if (tools1.length > 0) {
      logger.info('AV-05: Making tool calls to trigger call-count-based rug pull');

      const targetTool = tools1[0];
      // Make several no-op calls to potentially trigger a rug pull
      for (let i = 0; i < 3; i++) {
        try {
          await client.callTool(targetTool.name, {});
        } catch {
          // Errors are expected for invalid args -- we're just triggering call count
        }
      }

      // Check tools/list again after calls
      let tools3: MCPTool[];
      try {
        tools3 = await client.listTools();
      } catch {
        return;
      }

      for (const tool1 of tools1) {
        const tool3 = tools3.find((t) => t.name === tool1.name);
        if (!tool3) continue;

        if (tool1.description !== tool3.description) {
          yield {
            success: true,
            evidence: `Call-count rug pull detected: Tool '${tool1.name}' description changed after ${3} calls`,
            details: {
              toolName: tool1.name,
              before: tool1.description,
              after: tool3.description,
              callCount: 3,
              risk: 'Tool description changed after tool invocations, indicating call-count-triggered rug pull',
            },
          };
        }
      }
    }
  },
};

/**
 * AV-06: Cross-Tool Privilege Escalation
 *
 * Tests if tool arguments can reference or trigger other tools,
 * and checks for tool chaining vulnerabilities.
 */
const crossToolPrivEsc: MCPAttackVector = {
  id: 'cross-tool-priv-esc',
  name: 'Cross-Tool Privilege Escalation',
  description: 'Tests if tool arguments can reference or invoke other tools, testing for tool chaining vulnerabilities',
  severity: 'high',
  category: 'privilege_escalation',
  mitre: ['T1059', 'T1562'],
  async *execute(client, logger) {
    logger.info('AV-06: Testing cross-tool privilege escalation');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    if (tools.length < 2) {
      yield {
        success: false,
        evidence: 'Not enough tools for cross-tool testing (need at least 2)',
        details: { toolCount: tools.length },
      };
      return;
    }

    // For each tool, try referencing other tool names in its arguments
    const targetTools = tools.slice(0, 5);
    const otherToolNames = tools.map((t) => t.name);

    for (const tool of targetTools) {
      const schema = tool.inputSchema as Record<string, unknown>;
      const properties = (schema?.properties ?? {}) as Record<
        string,
        Record<string, unknown>
      >;
      const paramNames = Object.keys(properties);

      if (paramNames.length === 0) continue;

      // Try injecting other tool names into each parameter
      for (const otherName of otherToolNames) {
        if (otherName === tool.name) continue;

        const crossRefArgs: Record<string, unknown> = {};
        for (const param of paramNames) {
          crossRefArgs[param] = `{{call:${otherName}}}`;
        }

        yield* tryCallAndReport(
          client,
          tool.name,
          crossRefArgs,
          'cross-tool-ref',
          `Cross-tool reference injection: referencing '${otherName}' in '${tool.name}' args`,
          logger,
        );

        // Only test one cross-reference per target tool to limit requests
        break;
      }

      // Try tool name in SSRF-style format
      const ssrfArgs: Record<string, unknown> = {};
      for (const param of paramNames) {
        ssrfArgs[param] = `mcp://localhost/tools/${otherToolNames[0]}`;
      }

      yield* tryCallAndReport(
        client,
        tool.name,
        ssrfArgs,
        'mcp-ssrf',
        `MCP SSRF: injecting mcp:// protocol URI into '${tool.name}' args`,
        logger,
      );
    }
  },
};

/**
 * AV-07: Input Size Fuzzing
 *
 * Sends oversized inputs to test buffer limits and error handling:
 *   - Very long strings (10KB+)
 *   - Deeply nested JSON objects
 *   - Unicode edge cases (null bytes, BOM, RTL override)
 */
const inputSizeFuzzing: MCPAttackVector = {
  id: 'input-size-fuzzing',
  name: 'Input Size Fuzzing',
  description: 'Tests tool input handling with oversized strings, deep nesting, and Unicode edge cases',
  severity: 'medium',
  category: 'schema_manipulation',
  mitre: ['T1059'],
  async *execute(client, logger) {
    logger.info('AV-07: Fuzzing tool inputs with edge cases');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    // Test against first 5 tools
    const targetTools = tools.slice(0, 5);

    for (const tool of targetTools) {
      const schema = tool.inputSchema as Record<string, unknown>;
      const properties = (schema?.properties ?? {}) as Record<
        string,
        Record<string, unknown>
      >;
      const paramNames = Object.keys(properties);
      if (paramNames.length === 0) continue;

      // Test 1: Very long string (10KB)
      const longString = 'A'.repeat(10240);
      const longArgs: Record<string, unknown> = {};
      for (const param of paramNames) {
        longArgs[param] = longString;
      }
      yield* tryCallAndReport(
        client,
        tool.name,
        longArgs,
        'long-string',
        `Oversized string input (10KB) to '${tool.name}'`,
        logger,
      );

      // Test 2: Deeply nested JSON (50 levels)
      let nested: Record<string, unknown> = { value: 'deep' };
      for (let i = 0; i < 50; i++) {
        nested = { nested };
      }
      const nestedArgs: Record<string, unknown> = {};
      for (const param of paramNames) {
        nestedArgs[param] = nested;
      }
      yield* tryCallAndReport(
        client,
        tool.name,
        nestedArgs,
        'deep-nesting',
        `Deeply nested JSON object (50 levels) to '${tool.name}'`,
        logger,
      );

      // Test 3: Null bytes
      const nullByteArgs: Record<string, unknown> = {};
      for (const param of paramNames) {
        nullByteArgs[param] = 'test\x00injected\x00data';
      }
      yield* tryCallAndReport(
        client,
        tool.name,
        nullByteArgs,
        'null-bytes',
        `Null byte injection to '${tool.name}'`,
        logger,
      );

      // Test 4: BOM and RTL override
      const unicodeArgs: Record<string, unknown> = {};
      for (const param of paramNames) {
        unicodeArgs[param] = '\uFEFF\u202Etest\u202C\u200Bdata';
      }
      yield* tryCallAndReport(
        client,
        tool.name,
        unicodeArgs,
        'unicode-edge',
        `Unicode edge cases (BOM, RTL override, zero-width) to '${tool.name}'`,
        logger,
      );

      // Test 5: Very large number
      const numArgs: Record<string, unknown> = {};
      for (const param of paramNames) {
        numArgs[param] = Number.MAX_SAFE_INTEGER + 1;
      }
      yield* tryCallAndReport(
        client,
        tool.name,
        numArgs,
        'large-number',
        `Large number beyond MAX_SAFE_INTEGER to '${tool.name}'`,
        logger,
      );
    }
  },
};

/**
 * AV-08: Data Exfiltration Probe
 *
 * Tests whether tool responses leak sensitive information
 * by analyzing outputs for patterns that indicate data leakage.
 */
const dataExfiltrationProbe: MCPAttackVector = {
  id: 'data-exfil-probe',
  name: 'Data Exfiltration Probe',
  description: 'Probes tool responses for sensitive data leakage patterns (env vars, paths, credentials)',
  severity: 'high',
  category: 'data_exfiltration',
  mitre: ['T1005', 'T1041'],
  async *execute(client, logger) {
    logger.info('AV-08: Probing for data exfiltration');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    const targetTools = tools.slice(0, 5);

    // Sensitive data patterns to check in responses
    const sensitivePatterns: Array<[RegExp, string]> = [
      [/(?:^|[/\\])\.env(?:\.|$)/i, 'References .env file'],
      [/(?:PRIVATE KEY|RSA PRIVATE|BEGIN CERTIFICATE)/i, 'Contains private key material'],
      [/(?:password|passwd|secret|token)\s*[:=]\s*\S+/i, 'Contains credential assignment'],
      [/(?:aws_access_key|aws_secret|AKIA[0-9A-Z]{16})/i, 'Contains AWS credential'],
      [/(?:\/etc\/passwd|\/etc\/shadow)/i, 'References system password files'],
      [/(?:\/home\/\w+\/\.ssh)/i, 'References SSH directory'],
      [/(?:eyJ[A-Za-z0-9_-]{10,})/i, 'Contains JWT-like token'],
      [/(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}/i, 'Contains GitHub token'],
    ];

    for (const tool of targetTools) {
      const schema = tool.inputSchema as Record<string, unknown>;
      const properties = (schema?.properties ?? {}) as Record<
        string,
        Record<string, unknown>
      >;
      const paramNames = Object.keys(properties);

      // Try calling with minimal/empty args to see default response
      let result;
      try {
        const minArgs: Record<string, unknown> = {};
        for (const param of paramNames) {
          const paramDef = properties[param];
          if (paramDef?.type === 'string') {
            minArgs[param] = 'test';
          } else if (paramDef?.type === 'number' || paramDef?.type === 'integer') {
            minArgs[param] = 1;
          } else if (paramDef?.type === 'boolean') {
            minArgs[param] = true;
          }
        }
        result = await client.callTool(tool.name, minArgs);
      } catch {
        continue;
      }

      // Analyze response content for sensitive data
      const responseText = result.content
        .map((c) => c.text ?? '')
        .join('\n');

      if (!responseText) continue;

      for (const [pattern, description] of sensitivePatterns) {
        if (pattern.test(responseText)) {
          yield {
            success: true,
            evidence: `Tool '${tool.name}' response ${description}`,
            details: {
              toolName: tool.name,
              leakType: description,
              responsePreview: responseText.slice(0, 500),
            },
          };
        }
      }

      // Check if error responses leak stack traces or internal paths
      if (result.isError && responseText.length > 0) {
        if (/(?:at\s+\w+\s+\(|Error:|Traceback|node_modules)/.test(responseText)) {
          yield {
            success: true,
            evidence: `Tool '${tool.name}' leaks stack trace in error response`,
            details: {
              toolName: tool.name,
              leakType: 'stack_trace',
              responsePreview: responseText.slice(0, 500),
            },
          };
        }
      }
    }
  },
};

/**
 * AV-09: Environment Variable Extraction
 *
 * Attempts to extract environment variables through tools by
 * injecting env-referencing payloads into tool arguments.
 */
const envVarExtraction: MCPAttackVector = {
  id: 'env-var-extraction',
  name: 'Environment Variable Extraction',
  description: 'Attempts to extract environment variables through tool arguments using shell expansion and template injection',
  severity: 'critical',
  category: 'data_exfiltration',
  mitre: ['T1005', 'T1041', 'T1059'],
  async *execute(client, logger) {
    logger.info('AV-09: Testing environment variable extraction');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    const targetTools = tools.slice(0, 5);

    // Payloads that may expand environment variables
    const envPayloads: Array<[string, string]> = [
      ['$HOME', 'Shell variable expansion ($HOME)'],
      ['${HOME}', 'Shell variable expansion (${HOME})'],
      ['$PATH', 'Shell variable expansion ($PATH)'],
      ['%USERPROFILE%', 'Windows env expansion (%USERPROFILE%)'],
      ['{{process.env.HOME}}', 'Template injection (process.env)'],
      ['${process.env.API_KEY}', 'Template injection (process.env.API_KEY)'],
    ];

    for (const tool of targetTools) {
      const schema = tool.inputSchema as Record<string, unknown>;
      const properties = (schema?.properties ?? {}) as Record<
        string,
        Record<string, unknown>
      >;
      const paramNames = Object.keys(properties);
      if (paramNames.length === 0) continue;

      for (const [payload, description] of envPayloads) {
        const args: Record<string, unknown> = {};
        for (const param of paramNames) {
          args[param] = payload;
        }

        let result;
        try {
          result = await client.callTool(tool.name, args);
        } catch {
          continue;
        }

        const responseText = result.content
          .map((c) => c.text ?? '')
          .join('\n');

        // Check if the response contains expanded env var values
        // (i.e., the payload was expanded rather than treated as literal)
        if (responseText && responseText !== payload && !result.isError) {
          // Check if the response looks like an expanded path or value
          if (
            responseText.includes('/home/') ||
            responseText.includes('/Users/') ||
            responseText.includes('C:\\Users\\') ||
            responseText.includes('/usr/') ||
            (responseText.length > payload.length * 2 && responseText.includes(':'))
          ) {
            yield {
              success: true,
              evidence: `Tool '${tool.name}' may expand env variables: ${description}`,
              details: {
                toolName: tool.name,
                payload,
                description,
                responsePreview: responseText.slice(0, 300),
              },
            };
          }
        }
      }
    }
  },
};

/**
 * AV-10: Resource Exposure Check
 *
 * If the MCP server supports resources, enumerate and check for
 * exposed sensitive resources.
 */
const resourceExposure: MCPAttackVector = {
  id: 'resource-exposure',
  name: 'Resource Exposure Check',
  description: 'Enumerates MCP server resources and checks for exposed sensitive data (files, credentials, configs)',
  severity: 'high',
  category: 'data_exfiltration',
  mitre: ['T1005', 'T1041'],
  async *execute(client, logger) {
    logger.info('AV-10: Checking for resource exposure');

    // Check if the client supports resource operations
    if (!client.listResources || !client.readResource) {
      yield {
        success: false,
        evidence: 'MCP client does not support resource operations',
        details: { supported: false },
      };
      return;
    }

    let resources;
    try {
      resources = await client.listResources();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      // Server may not support resources -- this is not an error
      yield {
        success: false,
        evidence: `Server does not support resource listing: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    if (resources.length === 0) {
      yield {
        success: false,
        evidence: 'No resources exposed by MCP server',
        details: { resourceCount: 0 },
      };
      return;
    }

    yield {
      success: true,
      evidence: `MCP server exposes ${resources.length} resources`,
      details: {
        resourceCount: resources.length,
        resources: resources.map((r) => ({
          uri: r.uri,
          name: r.name,
          mimeType: r.mimeType,
        })),
      },
    };

    // Check for sensitive resource URIs
    const sensitivePatterns: Array<[RegExp, string]> = [
      [/\.env($|\.)/i, 'Environment file'],
      [/\.ssh\//i, 'SSH directory'],
      [/credentials/i, 'Credentials file'],
      [/\.aws\//i, 'AWS config'],
      [/private.?key/i, 'Private key'],
      [/secret/i, 'Secret file'],
      [/token/i, 'Token file'],
      [/password/i, 'Password file'],
      [/\/etc\/(passwd|shadow|sudoers)/i, 'System file'],
    ];

    for (const resource of resources) {
      for (const [pattern, description] of sensitivePatterns) {
        if (pattern.test(resource.uri) || pattern.test(resource.name)) {
          yield {
            success: true,
            evidence: `Sensitive resource exposed: '${resource.name}' (${description})`,
            details: {
              uri: resource.uri,
              name: resource.name,
              type: description,
              mimeType: resource.mimeType,
            },
          };
        }
      }
    }
  },
};

/**
 * AV-11: Server Error Information Disclosure
 *
 * Deliberately sends malformed requests to see if the server
 * leaks internal implementation details in error responses.
 */
const errorInfoDisclosure: MCPAttackVector = {
  id: 'error-info-disclosure',
  name: 'Server Error Information Disclosure',
  description: 'Sends malformed requests to check if the server leaks internal details (stack traces, paths, versions) in errors',
  severity: 'medium',
  category: 'tool_enumeration',
  mitre: ['T1005'],
  async *execute(client, logger) {
    logger.info('AV-11: Testing error information disclosure');

    let tools: MCPTool[];
    try {
      tools = await client.listTools();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      yield {
        success: false,
        evidence: `Failed to list tools: ${msg}`,
        details: { error: msg },
      };
      return;
    }

    if (tools.length === 0) return;

    const tool = tools[0];

    // Malformed payloads designed to trigger verbose errors
    const longKey = 'a'.repeat(10000);
    const malformedPayloads: Array<[Record<string, unknown>, string]> = [
      [{ '\x00': null }, 'Null byte in key'],
      [{ '': '' }, 'Empty key-value pair'],
      [{ [longKey]: 'test' }, 'Extremely long key name'],
      [{ test: undefined }, 'Undefined value'],
      [{ test: Symbol('test') as unknown }, 'Symbol value'],
      [{ test: NaN }, 'NaN value'],
      [{ test: Infinity }, 'Infinity value'],
    ];

    for (const [payload, description] of malformedPayloads) {
      try {
        const result = await client.callTool(tool.name, payload);
        const responseText = result.content
          .map((c) => c.text ?? '')
          .join('\n');

        if (result.isError && responseText) {
          // Check for information disclosure in error
          const disclosurePatterns: Array<[RegExp, string]> = [
            [/at\s+\w+\s+\([\w/\\.:]+:\d+:\d+\)/, 'Stack trace with file paths'],
            [/node_modules\//, 'Node modules path disclosure'],
            [/\/home\/\w+|\/Users\/\w+|C:\\Users\\\w+/, 'User home directory'],
            [/version\s*[:=]\s*[\d.]+/, 'Version information'],
            [/(?:MongoDB|PostgreSQL|MySQL|Redis|SQLite)/i, 'Database technology disclosure'],
          ];

          for (const [pattern, disclosureType] of disclosurePatterns) {
            if (pattern.test(responseText)) {
              yield {
                success: true,
                evidence: `Error response from '${tool.name}' discloses: ${disclosureType} (triggered by: ${description})`,
                details: {
                  toolName: tool.name,
                  trigger: description,
                  disclosureType,
                  responsePreview: responseText.slice(0, 500),
                },
              };
            }
          }
        }
      } catch {
        // Expected -- some payloads may crash the call
        continue;
      }
    }
  },
};

// ─── All Attack Vectors ──────────────────────────────────────

/**
 * Complete registry of all MCP attack vectors.
 * These are executed sequentially during a live attack scan.
 */
export const ATTACK_VECTORS: readonly MCPAttackVector[] = [
  toolEnumeration,           // AV-01
  descriptionInjection,      // AV-02
  schemaValidationBypass,    // AV-03
  toolSquatting,             // AV-04
  rugPullDetection,          // AV-05
  crossToolPrivEsc,          // AV-06
  inputSizeFuzzing,          // AV-07
  dataExfiltrationProbe,     // AV-08
  envVarExtraction,          // AV-09
  resourceExposure,          // AV-10
  errorInfoDisclosure,       // AV-11
];

// ─── Utility Functions ───────────────────────────────────────

/**
 * Try to call a tool and yield a result describing the outcome.
 * This is used by attack vectors that need to test tool responses.
 */
async function* tryCallAndReport(
  client: MCPClient,
  toolName: string,
  args: Record<string, unknown>,
  testId: string,
  description: string,
  logger: SpearLogger,
): AsyncGenerator<AttackResult> {
  try {
    const result = await client.callTool(toolName, args);
    const responseText = result.content
      .map((c) => c.text ?? '')
      .join('\n');

    const accepted = !result.isError;

    yield {
      success: accepted,
      evidence: accepted
        ? `Tool '${toolName}' accepted ${testId} payload: ${description}`
        : `Tool '${toolName}' rejected ${testId} payload: ${description}`,
      details: {
        toolName,
        testId,
        description,
        accepted,
        isError: result.isError ?? false,
        responsePreview: responseText.slice(0, 500),
        payloadKeys: Object.keys(args),
      },
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.debug(`Tool call failed for ${testId}`, {
      toolName,
      error: msg,
    });

    yield {
      success: false,
      evidence: `Tool '${toolName}' errored on ${testId} payload: ${msg}`,
      details: {
        toolName,
        testId,
        description,
        error: msg,
      },
    };
  }
}

/**
 * Serialize a tool list for comparison.
 */
function serializeToolList(tools: MCPTool[]): string {
  const sorted = [...tools].sort((a, b) => a.name.localeCompare(b.name));
  return JSON.stringify(
    sorted.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema,
    })),
  );
}

/**
 * Simple Levenshtein distance for typosquat detection.
 */
function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  if (m === 0) return n;
  if (n === 0) return m;

  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    Array.from({ length: n + 1 }, () => 0),
  );

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }

  return dp[m][n];
}

/**
 * Sleep for a specified duration.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
