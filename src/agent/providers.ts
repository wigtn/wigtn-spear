import type { AgentTarget } from './types.js';

/**
 * Preset `AgentTarget` builders for common LLM chat APIs. Use these when the
 * target under test IS a raw provider endpoint; when the customer exposes their
 * own agent app, describe that endpoint with a plain `AgentTarget` instead.
 *
 * SECURITY: the auth header you pass here is redacted from every stored evidence
 * bundle (`SECRET_HEADERS`), but you should still source it from an environment
 * variable at run time rather than committing it into a program file.
 */

export interface OpenAiTargetOptions {
  /** Bearer API key (from env, e.g. process.env.OPENAI_API_KEY). */
  apiKey: string;
  model: string;
  /** Override for Azure/proxy deployments; defaults to the public API. */
  endpoint?: string;
  /** Optional system prompt sent before the attack message. */
  system?: string;
}

/** OpenAI Chat Completions (`POST /v1/chat/completions`). */
export function openAiChatTarget(options: OpenAiTargetOptions): AgentTarget {
  const messages = options.system
    ? `{"role":"system","content":${JSON.stringify(options.system)}},{"role":"user","content":"{{message}}"}`
    : `{"role":"user","content":"{{message}}"}`;
  return {
    endpoint: options.endpoint ?? 'https://api.openai.com/v1/chat/completions',
    method: 'POST',
    headers: { authorization: `Bearer ${options.apiKey}` },
    bodyTemplate: `{"model":${JSON.stringify(options.model)},"messages":[${messages}]}`,
    replyJsonPath: 'choices.0.message.content',
  };
}

export interface AnthropicTargetOptions {
  /** Anthropic API key (from env, e.g. process.env.ANTHROPIC_API_KEY). */
  apiKey: string;
  model: string;
  maxTokens?: number;
  endpoint?: string;
  system?: string;
}

/** Anthropic Messages (`POST /v1/messages`). */
export function anthropicMessagesTarget(options: AnthropicTargetOptions): AgentTarget {
  const system = options.system ? `"system":${JSON.stringify(options.system)},` : '';
  return {
    endpoint: options.endpoint ?? 'https://api.anthropic.com/v1/messages',
    method: 'POST',
    headers: { 'x-api-key': options.apiKey, 'anthropic-version': '2023-06-01' },
    bodyTemplate:
      `{"model":${JSON.stringify(options.model)},"max_tokens":${options.maxTokens ?? 1024},`
      + `${system}"messages":[{"role":"user","content":"{{message}}"}]}`,
    replyJsonPath: 'content.0.text',
  };
}
