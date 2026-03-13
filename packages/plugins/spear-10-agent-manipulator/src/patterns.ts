/**
 * SPEAR-10: AI Agent Manipulation -- Pattern Definitions
 *
 * Defines 50+ injection patterns across five categories:
 *
 *   - exfiltration          -- Instructions to send data to external URLs
 *   - privilege_escalation  -- Instructions to bypass security controls
 *   - cot_hijack            -- Chain-of-Thought extraction/redirect attacks
 *   - config_override       -- Override safety settings or allowlists
 *   - stealth_injection     -- Hidden unicode, invisible characters, obfuscated instructions
 *
 * Each pattern includes a MITRE ATT&CK mapping for enterprise threat classification.
 *
 * MITRE references used:
 *   T1059     -- Command and Scripting Interpreter
 *   T1071     -- Application Layer Protocol
 *   T1132     -- Data Encoding
 *   T1190     -- Exploit Public-Facing Application
 *   T1204     -- User Execution
 *   T1505.003 -- Server Software Component: Web Shell
 *   T1547     -- Boot or Logon Autostart Execution
 *   T1562     -- Impair Defenses
 *   T1565     -- Data Manipulation
 *   T1567     -- Exfiltration Over Web Service
 *   T1574     -- Hijack Execution Flow
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type InjectionCategory =
  | 'exfiltration'
  | 'privilege_escalation'
  | 'cot_hijack'
  | 'config_override'
  | 'stealth_injection';

export interface InjectionPattern {
  id: string;
  name: string;
  description: string;
  category: InjectionCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── Exfiltration Patterns ─────────────────────────────────────

const exfiltrationPatterns: InjectionPattern[] = [
  {
    id: 'agent-exfil-url-fetch',
    name: 'URL Fetch Exfiltration',
    description: 'Instruction to fetch or send data to an external URL',
    category: 'exfiltration',
    pattern: /(?:fetch|curl|wget|http\.get|axios|request)\s*\(?['"`]https?:\/\/[^'"`\s]+/i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Remove any instructions that direct the AI agent to make external HTTP requests. AI agent config files should never contain fetch/curl/request instructions.',
  },
  {
    id: 'agent-exfil-send-data',
    name: 'Data Send Instruction',
    description: 'Instruction to send, post, or transmit data externally',
    category: 'exfiltration',
    pattern: /(?:send|post|transmit|upload|exfiltrate|forward)\s+(?:the\s+)?(?:data|content|code|source|file|secret|token|key|password|credential|env)/i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Remove instructions that direct the AI agent to transmit sensitive data. AI config files should not contain data exfiltration commands.',
  },
  {
    id: 'agent-exfil-webhook',
    name: 'Webhook Exfiltration',
    description: 'Reference to webhook URL for data exfiltration',
    category: 'exfiltration',
    pattern: /(?:webhook|callback|notify|ping)\s*(?:url|endpoint|to)?\s*[:=]?\s*['"`]?https?:\/\//i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Remove webhook URL references from AI agent configuration. Agent configs should not contain outbound webhook endpoints.',
  },
  {
    id: 'agent-exfil-base64-encode',
    name: 'Base64 Encode Exfiltration',
    description: 'Instruction to base64 encode data before sending',
    category: 'exfiltration',
    pattern: /(?:base64|btoa|encode)\s*(?:the\s+)?(?:content|data|code|source|file|output|response).*(?:send|post|fetch|url|http)/i,
    severity: 'high',
    mitre: ['T1132', 'T1567'],
    remediation: 'Remove instructions that encode data for exfiltration. Base64 encoding of content combined with sending instructions is a common exfiltration technique.',
  },
  {
    id: 'agent-exfil-dns-tunnel',
    name: 'DNS Tunneling Exfiltration',
    description: 'Instruction to encode data in DNS queries for exfiltration',
    category: 'exfiltration',
    pattern: /(?:dns|subdomain|nslookup|dig)\s*(?:query|lookup|resolve)?.*(?:encode|embed|append|prepend)\s*(?:data|content|secret)/i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Remove DNS tunneling instructions. This is a sophisticated exfiltration technique that encodes data in DNS query hostnames.',
  },
  {
    id: 'agent-exfil-img-tag',
    name: 'Image Tag Exfiltration',
    description: 'Markdown/HTML image tag used to exfiltrate data via URL parameters',
    category: 'exfiltration',
    pattern: /!\[.*?\]\(https?:\/\/[^)]*\$\{|<img[^>]+src\s*=\s*['"`]https?:\/\/[^'"`]*\$\{/i,
    severity: 'critical',
    mitre: ['T1567', 'T1071'],
    remediation: 'Remove image tags that embed dynamic variables in URLs. This technique exfiltrates data by appending it to image request URLs.',
  },
  {
    id: 'agent-exfil-url-param',
    name: 'URL Parameter Data Leak',
    description: 'Instruction to append sensitive data as URL query parameters',
    category: 'exfiltration',
    pattern: /(?:append|add|include|embed)\s+(?:the\s+)?(?:api.?key|token|secret|password|credential|env).*(?:url|query|param|endpoint)/i,
    severity: 'critical',
    mitre: ['T1567'],
    remediation: 'Remove instructions that leak sensitive values through URL parameters. Secrets should never be embedded in URLs.',
  },
  {
    id: 'agent-exfil-clipboard',
    name: 'Clipboard Exfiltration',
    description: 'Instruction to copy sensitive data to clipboard for exfiltration',
    category: 'exfiltration',
    pattern: /(?:copy|clipboard|pbcopy|xclip|xsel).*(?:secret|token|key|password|credential|env|api.?key)/i,
    severity: 'medium',
    mitre: ['T1567'],
    remediation: 'Remove clipboard copy instructions for sensitive data from agent configuration.',
  },

  // ─── Privilege Escalation Patterns ───────────────────────────

  {
    id: 'agent-priv-ignore-security',
    name: 'Ignore Security Warnings',
    description: 'Instruction to ignore security warnings or bypass checks',
    category: 'privilege_escalation',
    pattern: /(?:ignore|skip|bypass|disable|suppress|silence|turn\s+off|don'?t\s+(?:show|display|report|flag))\s+(?:all\s+)?(?:security|safety|warning|error|check|validation|verification|lint|audit)/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Remove instructions that direct the agent to ignore security warnings. Agent configs must not suppress security controls.',
  },
  {
    id: 'agent-priv-sudo-exec',
    name: 'Sudo/Root Execution',
    description: 'Instruction to execute commands with elevated privileges',
    category: 'privilege_escalation',
    pattern: /(?:run|exec|execute)\s+(?:with\s+)?(?:sudo|root|admin|elevated|privileged)|sudo\s+/i,
    severity: 'critical',
    mitre: ['T1059', 'T1547'],
    remediation: 'Remove sudo/root execution instructions from agent configuration. AI agents should never be directed to run with elevated privileges.',
  },
  {
    id: 'agent-priv-modify-dotfile',
    name: 'Dotfile Modification',
    description: 'Instruction to modify shell dotfiles or system configuration',
    category: 'privilege_escalation',
    pattern: /(?:modify|edit|change|write|append|add)\s+(?:to\s+)?(?:~\/)?\.(?:bashrc|zshrc|profile|bash_profile|ssh\/|gitconfig|npmrc|netrc)/i,
    severity: 'high',
    mitre: ['T1547', 'T1574'],
    remediation: 'Remove instructions that modify user dotfiles or system configuration. Agent configs should not direct changes to shell profiles or credentials files.',
  },
  {
    id: 'agent-priv-file-write',
    name: 'Arbitrary File Write',
    description: 'Instruction to write files outside the project directory',
    category: 'privilege_escalation',
    pattern: /(?:write|create|save|overwrite)\s+(?:a\s+)?(?:file\s+)?(?:to|at|in)\s+(?:\/(?:etc|usr|var|tmp|home|root)|~\/|\.\.\/\.\.|%(?:APPDATA|USERPROFILE)%)/i,
    severity: 'critical',
    mitre: ['T1565', '1059'],
    remediation: 'Remove file write instructions targeting paths outside the project directory. AI agents should only modify files within the workspace.',
  },
  {
    id: 'agent-priv-env-read',
    name: 'Environment Variable Harvesting',
    description: 'Instruction to read and expose environment variables',
    category: 'privilege_escalation',
    pattern: /(?:read|print|show|display|output|list|dump|log|echo)\s+(?:all\s+)?(?:env(?:ironment)?(?:\s+var(?:iable)?s?)?|process\.env|os\.environ|\$\{?\w*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)\w*\}?)/i,
    severity: 'high',
    mitre: ['T1059', '1567'],
    remediation: 'Remove instructions that harvest environment variables. Sensitive env vars should never be printed or logged by AI agents.',
  },
  {
    id: 'agent-priv-package-install',
    name: 'Unauthorized Package Installation',
    description: 'Instruction to install packages from untrusted sources',
    category: 'privilege_escalation',
    pattern: /(?:npm\s+install|pip\s+install|gem\s+install|cargo\s+install)\s+(?:--registry\s+https?:\/\/(?!registry\.npmjs\.org|pypi\.org)|\S+@https?:\/\/)/i,
    severity: 'high',
    mitre: ['T1195.002', 'T1059'],
    remediation: 'Remove package install instructions from untrusted registries. Only official registries should be used.',
  },
  {
    id: 'agent-priv-chmod-exec',
    name: 'Chmod Executable Permission',
    description: 'Instruction to make files executable',
    category: 'privilege_escalation',
    pattern: /chmod\s+(?:\+x|[0-7]{3,4})\s+/i,
    severity: 'medium',
    mitre: ['T1059'],
    remediation: 'Remove chmod instructions from agent configuration. AI agents should not change file permissions.',
  },
  {
    id: 'agent-priv-shell-exec',
    name: 'Shell Command Execution',
    description: 'Instruction to execute arbitrary shell commands',
    category: 'privilege_escalation',
    pattern: /(?:run|exec(?:ute)?)\s+(?:the\s+following\s+)?(?:shell\s+)?(?:command|script)\s*[:;]\s*[`'"]/i,
    severity: 'high',
    mitre: ['T1059'],
    remediation: 'Remove shell command execution instructions from agent configuration. AI configs should not contain arbitrary command execution directives.',
  },

  // ─── Chain-of-Thought Hijack Patterns ────────────────────────

  {
    id: 'agent-cot-extract-thinking',
    name: 'CoT Extraction',
    description: 'Instruction to extract and expose chain-of-thought or internal reasoning',
    category: 'cot_hijack',
    pattern: /(?:show|reveal|display|output|print|expose|extract|dump)\s+(?:your\s+)?(?:internal\s+)?(?:thinking|reasoning|thought\s*(?:process|chain)?|chain.?of.?thought|cot|hidden\s+(?:prompt|instruction|context)|system\s+(?:prompt|message|instruction))/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Remove CoT extraction instructions. AI agent configs should not attempt to extract internal reasoning or system prompts.',
  },
  {
    id: 'agent-cot-redirect-output',
    name: 'CoT Output Redirect',
    description: 'Instruction to redirect internal reasoning to a file or external endpoint',
    category: 'cot_hijack',
    pattern: /(?:redirect|pipe|save|write|log|store)\s+(?:your\s+)?(?:thinking|reasoning|thought|cot|internal)\s+(?:to|into|in)\s+(?:a\s+)?(?:file|log|endpoint|url|server)/i,
    severity: 'critical',
    mitre: ['T1567', 'T1190'],
    remediation: 'Remove CoT redirect instructions. Internal reasoning must not be redirected to files or external endpoints.',
  },
  {
    id: 'agent-cot-override-system',
    name: 'System Prompt Override',
    description: 'Attempt to override or ignore the system prompt',
    category: 'cot_hijack',
    pattern: /(?:ignore|forget|disregard|override|replace)\s+(?:all\s+)?(?:your\s+)?(?:previous|prior|above|original|initial|system|default)\s+(?:instructions?|prompts?|rules?|guidelines?|constraints?|context)/i,
    severity: 'critical',
    mitre: ['T1190', 'T1562'],
    remediation: 'Remove system prompt override attempts. Agent config files must not contain instructions that override safety guidelines.',
  },
  {
    id: 'agent-cot-new-persona',
    name: 'Persona Injection',
    description: 'Instruction to adopt a different persona or bypass restrictions',
    category: 'cot_hijack',
    pattern: /(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|role.?play\s+as|assume\s+the\s+(?:role|identity)\s+of)\s+(?:a\s+)?(?:hacker|attacker|malicious|unrestricted|jailbroken|DAN|uncensored)/i,
    severity: 'critical',
    mitre: ['T1190'],
    remediation: 'Remove persona injection attempts. Agent configs must not instruct the AI to adopt malicious or unrestricted personas.',
  },
  {
    id: 'agent-cot-thinking-tags',
    name: 'Thinking Tag Injection',
    description: 'Injection of XML-style thinking/reasoning tags to manipulate CoT',
    category: 'cot_hijack',
    pattern: /<\/?(?:thinking|reasoning|scratchpad|internal|hidden|system)[^>]*>/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Remove XML-style thinking/reasoning tags from agent configuration. These tags can be used to inject or extract chain-of-thought reasoning.',
  },
  {
    id: 'agent-cot-prompt-leak',
    name: 'Prompt Leak Instruction',
    description: 'Instruction to repeat or reveal the full system prompt',
    category: 'cot_hijack',
    pattern: /(?:repeat|recite|echo|verbatim|word.?for.?word|exactly)\s+(?:the\s+)?(?:entire|full|complete|whole)?\s*(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?)/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Remove prompt leak instructions. Agent configs should not attempt to extract the full system prompt.',
  },
  {
    id: 'agent-cot-delimiter-escape',
    name: 'Delimiter Escape Attack',
    description: 'Use of special delimiters or separators to escape prompt context',
    category: 'cot_hijack',
    pattern: /(?:---+\s*(?:END|BEGIN|NEW|SYSTEM)\s*(?:OF\s+)?(?:PROMPT|INSTRUCTION|CONTEXT|SYSTEM)?\s*---+|={3,}\s*(?:SYSTEM|ADMIN|ROOT)\s*={3,}|#{3,}\s*(?:NEW|OVERRIDE)\s*(?:INSTRUCTIONS?|PROMPT)\s*#{3,})/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Remove delimiter escape sequences from agent configuration. These patterns attempt to break out of the prompt context.',
  },

  // ─── Config Override Patterns ────────────────────────────────

  {
    id: 'agent-cfg-wildcard-allow',
    name: 'Wildcard Permission Allow',
    description: 'Overly permissive wildcard in allowed tools or permissions',
    category: 'config_override',
    pattern: /(?:allow(?:ed)?(?:Tools|Commands|Operations|Permissions)?|permissions?)\s*[:=]\s*\[?\s*['"`]?\*['"`]?/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Replace wildcard (*) permissions with explicit, minimal tool allowlists. Use the principle of least privilege.',
  },
  {
    id: 'agent-cfg-disable-confirm',
    name: 'Confirmation Bypass',
    description: 'Configuration to skip user confirmation for dangerous operations',
    category: 'config_override',
    pattern: /(?:skip|disable|bypass|no).?(?:confirm(?:ation)?|prompt|approval|review|ask)\s*[:=]\s*(?:true|1|yes)/i,
    severity: 'high',
    mitre: ['T1562'],
    remediation: 'Re-enable confirmation prompts for dangerous operations. Users should always confirm destructive or sensitive actions.',
  },
  {
    id: 'agent-cfg-trust-all',
    name: 'Trust All Sources',
    description: 'Configuration to trust all MCP servers or external sources',
    category: 'config_override',
    pattern: /(?:trust(?:All|External|Unknown|Unverified)?|verify|validate)\s*[:=]\s*(?:false|0|no|none|disabled?)|(?:trust(?:Level|Mode)?)\s*[:=]\s*['"`]?(?:all|any|none|disabled?)['"`]?/i,
    severity: 'critical',
    mitre: ['T1562', 'T1195.002'],
    remediation: 'Enable source verification and do not trust all external MCP servers blindly. Validate server certificates and signatures.',
  },
  {
    id: 'agent-cfg-sandbox-disable',
    name: 'Sandbox Disable',
    description: 'Configuration to disable sandboxing or isolation',
    category: 'config_override',
    pattern: /(?:sandbox|isolation|container|restrict(?:ed)?(?:Mode)?|safe(?:Mode)?)\s*[:=]\s*(?:false|0|no|none|disabled?|off)/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Do not disable sandbox or isolation settings. AI agents should operate within restricted environments.',
  },
  {
    id: 'agent-cfg-allow-exec',
    name: 'Allow Command Execution',
    description: 'Configuration allowing arbitrary command execution',
    category: 'config_override',
    pattern: /(?:allow(?:ed)?(?:Commands?|Exec(?:ution)?|Shell|Process))\s*[:=]\s*\[?\s*['"`]?\*['"`]?/i,
    severity: 'critical',
    mitre: ['T1059', 'T1562'],
    remediation: 'Restrict command execution to a specific allowlist. Never allow wildcard command execution for AI agents.',
  },
  {
    id: 'agent-cfg-allow-network',
    name: 'Unrestricted Network Access',
    description: 'Configuration allowing unrestricted network access',
    category: 'config_override',
    pattern: /(?:network(?:Access)?|internet|outbound|egress)\s*[:=]\s*(?:true|1|yes|allow|unrestricted|all)/i,
    severity: 'high',
    mitre: ['T1071', 'T1562'],
    remediation: 'Restrict network access to specific, trusted endpoints. AI agents should not have unrestricted outbound network access.',
  },
  {
    id: 'agent-cfg-auto-approve',
    name: 'Auto-Approve All Actions',
    description: 'Configuration to auto-approve all agent actions without review',
    category: 'config_override',
    pattern: /(?:auto(?:Approve|Accept|Confirm|Execute|Run)|yolo(?:Mode)?)\s*[:=]\s*(?:true|1|yes|all)/i,
    severity: 'critical',
    mitre: ['T1562'],
    remediation: 'Disable auto-approve settings. All potentially dangerous agent actions should require human confirmation.',
  },
  {
    id: 'agent-cfg-max-tokens-abuse',
    name: 'Token Limit Override',
    description: 'Unreasonably high token limit to enable long injection payloads',
    category: 'config_override',
    pattern: /(?:max(?:Tokens?|Length|Output)|token(?:Limit|Budget))\s*[:=]\s*(?:[1-9]\d{6,}|Infinity|unlimited)/i,
    severity: 'medium',
    mitre: ['T1190'],
    remediation: 'Set reasonable token limits. Extremely high token limits can enable injection payload delivery.',
  },

  // ─── Stealth Injection Patterns ──────────────────────────────

  {
    id: 'agent-stealth-invisible-chars',
    name: 'Invisible Character Injection',
    description: 'Use of zero-width or invisible Unicode characters to hide instructions',
    category: 'stealth_injection',
    // Zero-width space (U+200B), zero-width non-joiner (U+200C), zero-width joiner (U+200D),
    // left-to-right/right-to-left marks, word joiner, invisible separator
    pattern: /[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD]{2,}/,
    severity: 'critical',
    mitre: ['T1027', 'T1564'],
    remediation: 'Remove invisible Unicode characters. Sequences of zero-width characters are often used to hide injected instructions.',
  },
  {
    id: 'agent-stealth-homoglyph',
    name: 'Homoglyph Attack',
    description: 'Use of visually similar Unicode characters to disguise instructions',
    category: 'stealth_injection',
    // Cyrillic characters that look identical to Latin: a(0x430), e(0x435), o(0x43E), p(0x440), c(0x441), x(0x445)
    pattern: /[\u0430\u0435\u043E\u0440\u0441\u0445\u0410\u0415\u041E\u0420\u0421\u0425]{3,}/,
    severity: 'high',
    mitre: ['T1036'],
    remediation: 'Replace Cyrillic homoglyphs with their ASCII equivalents. Homoglyph substitution can disguise malicious instructions.',
  },
  {
    id: 'agent-stealth-html-comment',
    name: 'HTML Comment Injection',
    description: 'Malicious instructions hidden inside HTML or XML comments',
    category: 'stealth_injection',
    pattern: /<!--[\s\S]*?(?:ignore|override|bypass|execute|fetch|send|exfiltrate|sudo|rm\s+-rf|curl|wget)[\s\S]*?-->/i,
    severity: 'high',
    mitre: ['T1564', 'T1027'],
    remediation: 'Remove hidden instructions from HTML/XML comments. Comments should not contain executable directives.',
  },
  {
    id: 'agent-stealth-markdown-hidden',
    name: 'Markdown Hidden Content',
    description: 'Instructions hidden in markdown that renders as invisible or tiny text',
    category: 'stealth_injection',
    pattern: /(?:<(?:span|div|p)[^>]*(?:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|opacity\s*:\s*0|height\s*:\s*0|width\s*:\s*0)[^>]*>)/i,
    severity: 'high',
    mitre: ['T1564', 'T1027'],
    remediation: 'Remove hidden HTML elements from markdown files. CSS-hidden content in agent configs is a stealth injection technique.',
  },
  {
    id: 'agent-stealth-encoded-payload',
    name: 'Encoded Payload',
    description: 'Base64 or hex encoded instructions to evade detection',
    category: 'stealth_injection',
    pattern: /(?:eval|decode|execute|run)\s*\(\s*(?:atob|Buffer\.from|base64_decode|hex_decode)\s*\(\s*['"`]/i,
    severity: 'critical',
    mitre: ['T1140', 'T1027'],
    remediation: 'Remove encoded execution payloads. Instructions should be in plaintext; encoded payloads indicate attempted evasion.',
  },
  {
    id: 'agent-stealth-whitespace-stego',
    name: 'Whitespace Steganography',
    description: 'Information hidden using trailing whitespace patterns',
    category: 'stealth_injection',
    // Detect lines with excessive trailing whitespace (8+ spaces/tabs at end)
    pattern: /[ \t]{8,}$/m,
    severity: 'low',
    mitre: ['T1564', 'T1027'],
    remediation: 'Remove excessive trailing whitespace. While often benign, patterns of trailing whitespace can encode hidden data via steganography.',
  },
  {
    id: 'agent-stealth-bidi-override',
    name: 'Bidirectional Text Override',
    description: 'Unicode bidirectional override characters to disguise text direction',
    category: 'stealth_injection',
    // RLO (U+202E), LRO (U+202D), RLE (U+202B), LRE (U+202A), PDF (U+202C)
    pattern: /[\u202A\u202B\u202C\u202D\u202E]/,
    severity: 'high',
    mitre: ['T1036'],
    remediation: 'Remove Unicode bidirectional override characters. These can make text appear differently than its actual content.',
  },
  {
    id: 'agent-stealth-backslash-newline',
    name: 'Backslash Newline Obfuscation',
    description: 'Split malicious keywords across lines using backslash-newline continuation',
    category: 'stealth_injection',
    pattern: /(?:ig\\n?ore|by\\n?pass|ex\\n?ec|fe\\n?tch|cu\\n?rl|su\\n?do|se\\n?nd)/i,
    severity: 'medium',
    mitre: ['T1027'],
    remediation: 'Remove backslash-newline obfuscation. Splitting keywords across lines is an evasion technique.',
  },
  {
    id: 'agent-stealth-tag-injection',
    name: 'Hidden Tag Injection',
    description: 'Injected instructions using custom XML/HTML tags that blend with legitimate content',
    category: 'stealth_injection',
    pattern: /<(?:system_override|admin_instruction|hidden_prompt|secret_instruction|override_rules|new_instructions?|injected?)[^>]*>/i,
    severity: 'critical',
    mitre: ['T1190', 'T1027'],
    remediation: 'Remove injected custom tags. Tags like <system_override> or <hidden_prompt> are prompt injection markers.',
  },

  // ─── Additional Exfiltration Patterns ────────────────────────

  {
    id: 'agent-exfil-markdown-link',
    name: 'Markdown Link Exfiltration',
    description: 'Dynamic markdown link constructed with project data for exfiltration',
    category: 'exfiltration',
    pattern: /\[.*?\]\(https?:\/\/(?!(?:github\.com|docs\.|www\.))[^)]*(?:\$\{|{{|%7B)/i,
    severity: 'high',
    mitre: ['T1567'],
    remediation: 'Remove markdown links that embed dynamic variables. These can exfiltrate data through URL parameters.',
  },

  // ─── Additional CoT Patterns ─────────────────────────────────

  {
    id: 'agent-cot-multi-step-inject',
    name: 'Multi-Step Injection',
    description: 'Multi-step instruction sequence designed to gradually escalate permissions',
    category: 'cot_hijack',
    pattern: /(?:step\s*1\s*[:.].*(?:read|access|find)[\s\S]{1,200}step\s*2\s*[:.].*(?:send|post|fetch|write|execute))/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Remove multi-step injection sequences. Gradual permission escalation through numbered steps is a social engineering technique.',
  },
  {
    id: 'agent-cot-instruction-boundary',
    name: 'Instruction Boundary Manipulation',
    description: 'Attempt to redefine where user vs system instructions begin',
    category: 'cot_hijack',
    pattern: /(?:the\s+(?:above|previous)\s+(?:was|were|is)\s+(?:just\s+)?(?:a\s+)?(?:test|example|sample)|(?:actual|real|true)\s+instructions?\s+(?:start|begin)\s+(?:here|below|now))/i,
    severity: 'high',
    mitre: ['T1190'],
    remediation: 'Remove instruction boundary manipulation. These phrases attempt to redefine the context boundary between system and user instructions.',
  },

  // ─── Additional Privilege Escalation Patterns ────────────────

  {
    id: 'agent-priv-git-push-force',
    name: 'Git Force Push',
    description: 'Instruction to force push to git repository',
    category: 'privilege_escalation',
    pattern: /git\s+push\s+(?:--force|-f)\b/i,
    severity: 'high',
    mitre: ['T1565'],
    remediation: 'Remove git force push instructions from agent configuration. Force pushes can destroy repository history.',
  },
  {
    id: 'agent-priv-rm-recursive',
    name: 'Recursive Delete',
    description: 'Instruction to recursively delete files or directories',
    category: 'privilege_escalation',
    pattern: /rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r|--recursive)\s+/i,
    severity: 'critical',
    mitre: ['T1485'],
    remediation: 'Remove recursive delete commands from agent configuration. AI agents should not perform bulk file deletion.',
  },
  {
    id: 'agent-priv-process-kill',
    name: 'Process Kill',
    description: 'Instruction to kill or terminate processes',
    category: 'privilege_escalation',
    pattern: /(?:kill(?:all)?|pkill|taskkill)\s+(?:-9\s+)?/i,
    severity: 'medium',
    mitre: ['T1489'],
    remediation: 'Remove process kill instructions from agent configuration. AI agents should not terminate system processes.',
  },

  // ─── Additional Config Override Patterns ─────────────────────

  {
    id: 'agent-cfg-log-disable',
    name: 'Logging Disabled',
    description: 'Configuration to disable audit logging or monitoring',
    category: 'config_override',
    pattern: /(?:log(?:ging)?|audit(?:ing)?|monitor(?:ing)?|trace|telemetry)\s*[:=]\s*(?:false|0|no|none|disabled?|off)/i,
    severity: 'high',
    mitre: ['T1562'],
    remediation: 'Re-enable logging and audit trails. Disabling logging conceals malicious agent activity.',
  },
  {
    id: 'agent-cfg-rate-limit-disable',
    name: 'Rate Limit Disabled',
    description: 'Configuration to disable rate limiting',
    category: 'config_override',
    pattern: /(?:rate(?:Limit(?:ing)?)?|throttl(?:e|ing)|cooldown)\s*[:=]\s*(?:false|0|none|disabled?|off|unlimited)/i,
    severity: 'medium',
    mitre: ['T1562'],
    remediation: 'Re-enable rate limiting. Unrestricted request rates can enable abuse and resource exhaustion.',
  },

  // ─── Additional Stealth Patterns ─────────────────────────────

  {
    id: 'agent-stealth-unicode-tag',
    name: 'Unicode Tag Character Injection',
    description: 'Use of Unicode Tag characters (U+E0001 to U+E007F) to hide ASCII text',
    category: 'stealth_injection',
    // These are in the supplementary plane, so we need surrogate pair detection
    pattern: /[\uDB40][\uDC01-\uDC7F]/,
    severity: 'critical',
    mitre: ['T1564', 'T1027'],
    remediation: 'Remove Unicode Tag characters. The Unicode Tags block (U+E0001-E007F) can encode hidden ASCII text invisible to users.',
  },
  {
    id: 'agent-stealth-data-uri',
    name: 'Data URI Payload',
    description: 'Embedded data URI containing encoded executable content',
    category: 'stealth_injection',
    pattern: /data:(?:text\/(?:html|javascript)|application\/(?:javascript|x-javascript|ecmascript));base64,/i,
    severity: 'critical',
    mitre: ['T1027', 'T1059'],
    remediation: 'Remove data URIs containing executable content. Base64-encoded scripts in data URIs are a common payload delivery mechanism.',
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 50+ AI agent manipulation injection patterns.
 *
 * Patterns are grouped by category for scanning. Each scanner module
 * filters patterns relevant to its target file types.
 */
export const ALL_PATTERNS: readonly InjectionPattern[] = exfiltrationPatterns;

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: InjectionCategory): InjectionPattern[] {
  return ALL_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns filtered by minimum severity.
 */
export function getPatternsBySeverity(minSeverity: Severity): InjectionPattern[] {
  const severityOrder: Record<Severity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };

  const minLevel = severityOrder[minSeverity];
  return ALL_PATTERNS.filter((p) => severityOrder[p.severity] <= minLevel);
}

/**
 * Pattern count by category (for logging/reporting).
 */
export function getPatternCounts(): Record<InjectionCategory, number> {
  const counts: Record<InjectionCategory, number> = {
    exfiltration: 0,
    privilege_escalation: 0,
    cot_hijack: 0,
    config_override: 0,
    stealth_injection: 0,
  };

  for (const p of ALL_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}
