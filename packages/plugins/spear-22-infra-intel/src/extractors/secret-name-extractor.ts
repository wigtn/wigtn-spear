/**
 * SPEAR-22: Secret Name Extractor
 *
 * Extracts secret NAMES (not values) to build a secret inventory:
 *   - .env.example / .env.sample variable names
 *   - CI/CD ${{ secrets.* }} references
 *   - process.env.* references in source code
 *   - Cloud secret manager references (--set-secrets, etc.)
 *   - Dockerfile ARG/ENV declarations
 *
 * This is an intelligence module -- it inventories what secrets a project
 * requires without exposing their values.
 */

import type { Finding } from '@wigtn/shared';

// ─── Helper ─────────────────────────────────────────────────────

function findLineNumber(content: string, matchIndex: number): number {
  if (matchIndex < 0 || matchIndex >= content.length) return 1;
  let line = 1;
  for (let i = 0; i < matchIndex && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

function makeFinding(
  ruleIdSuffix: string,
  message: string,
  file: string,
  line: number,
  pluginId: string,
  type: string,
  value: string,
  extra?: Record<string, unknown>,
): Finding {
  return {
    ruleId: `spear-22/${ruleIdSuffix}`,
    severity: 'info',
    message,
    file,
    line,
    metadata: {
      plugin: pluginId,
      category: 'secret_inventory',
      type,
      value,
      ...extra,
    },
  };
}

// ─── .env.example / .env.sample Extraction ──────────────────────

/**
 * Extract variable names from .env.example, .env.sample, and similar files.
 *
 * These files declare what environment variables the project requires
 * without containing actual secret values.
 */
function* extractEnvExample(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    // Skip empty lines and comments
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    // Match KEY=value or KEY= (empty)
    const match = trimmed.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (match) {
      const name = match[1]!;
      const placeholder = match[2]!.trim();
      const key = `env-var:${name}`;
      if (seen.has(key)) continue;
      seen.add(key);

      // Determine if it looks like a secret based on name
      const isLikelySecret = /(?:SECRET|KEY|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY|SIGNING)/i.test(name);

      yield makeFinding(
        'env-example-var',
        `Environment Variable: ${name}${isLikelySecret ? ' (likely secret)' : ''}`,
        filePath,
        i + 1,
        pluginId,
        'env_variable',
        name,
        {
          isLikelySecret,
          hasPlaceholder: placeholder.length > 0,
          source: 'env_example',
        },
      );
    }
  }
}

// ─── CI/CD Secret References ────────────────────────────────────

/**
 * Extract GitHub Actions ${{ secrets.* }} references.
 * Also extracts ${{ vars.* }} for non-secret CI/CD variables.
 */
const GITHUB_SECRETS_PATTERN = /\$\{\{\s*secrets\.([a-zA-Z0-9_]+)\s*\}\}/g;
const GITHUB_VARS_PATTERN = /\$\{\{\s*vars\.([a-zA-Z0-9_]+)\s*\}\}/g;

/** GitLab CI/CD variable references: $CI_*, $VARIABLE_NAME */
const GITLAB_VARIABLE_PATTERN = /\$\{?([A-Z][A-Z0-9_]*)\}?/g;

/** Azure Pipelines variable references: $(variableName) */
const AZURE_PIPELINE_VARS_PATTERN = /\$\(([a-zA-Z][a-zA-Z0-9_.]+)\)/g;

function* extractCicdSecrets(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();

  // GitHub Actions secrets
  GITHUB_SECRETS_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = GITHUB_SECRETS_PATTERN.exec(content)) !== null) {
    const name = match[1]!;
    const key = `gh-secret:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'github-actions-secret',
      `GitHub Actions Secret: ${name}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'github_actions_secret',
      name,
      { source: 'github_actions' },
    );
  }

  // GitHub Actions vars
  GITHUB_VARS_PATTERN.lastIndex = 0;
  while ((match = GITHUB_VARS_PATTERN.exec(content)) !== null) {
    const name = match[1]!;
    const key = `gh-var:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'github-actions-var',
      `GitHub Actions Variable: ${name}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'github_actions_var',
      name,
      { source: 'github_actions' },
    );
  }

  // Azure Pipeline variables (only in azure-pipelines files)
  if (normalizedPath.includes('azure-pipelines') || normalizedPath.includes('pipelines')) {
    AZURE_PIPELINE_VARS_PATTERN.lastIndex = 0;
    while ((match = AZURE_PIPELINE_VARS_PATTERN.exec(content)) !== null) {
      const name = match[1]!;
      const key = `azure-var:${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'azure-pipeline-var',
        `Azure Pipeline Variable: ${name}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'azure_pipeline_var',
        name,
        { source: 'azure_pipelines' },
      );
    }
  }

  // GitLab CI variables (only in gitlab-ci files)
  if (normalizedPath.includes('gitlab-ci')) {
    // Look for variables: section
    const variablesBlockPattern = /variables:\s*\n((?:\s+\w+:.+\n?)+)/g;
    while ((match = variablesBlockPattern.exec(content)) !== null) {
      const block = match[1]!;
      const varLinePattern = /\s+([A-Z_][A-Z0-9_]*):\s*/g;
      let varMatch: RegExpExecArray | null;
      while ((varMatch = varLinePattern.exec(block)) !== null) {
        const name = varMatch[1]!;
        const key = `gitlab-var:${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        yield makeFinding(
          'gitlab-ci-var',
          `GitLab CI Variable: ${name}`,
          filePath,
          findLineNumber(content, match.index + varMatch.index),
          pluginId,
          'gitlab_ci_var',
          name,
          { source: 'gitlab_ci' },
        );
      }
    }
  }
}

// ─── process.env.* References ───────────────────────────────────

/** Match process.env.VARIABLE_NAME or process.env['VARIABLE_NAME'] */
const PROCESS_ENV_PATTERNS: RegExp[] = [
  /process\.env\.([A-Z_][A-Z0-9_]*)/g,
  /process\.env\[["']([A-Z_][A-Z0-9_]*)["']\]/g,
  // Deno: Deno.env.get('VARIABLE_NAME')
  /Deno\.env\.get\(\s*["']([A-Z_][A-Z0-9_]*)["']\s*\)/g,
  // import.meta.env.VARIABLE_NAME (Vite)
  /import\.meta\.env\.([A-Z_][A-Z0-9_]*)/g,
  // os.environ.get('VARIABLE_NAME') or os.getenv('VARIABLE_NAME') (Python -- sometimes in polyglot repos)
  /os\.(?:environ\.get|getenv)\(\s*["']([A-Z_][A-Z0-9_]*)["']\s*\)/g,
];

function* extractProcessEnv(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const pattern of PROCESS_ENV_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const name = match[1]!;
      // Skip very common non-secret env vars
      if (name === 'NODE_ENV' || name === 'HOME' || name === 'PATH' || name === 'PWD' || name === 'USER' || name === 'SHELL') {
        continue;
      }
      const key = `process-env:${name}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const isLikelySecret = /(?:SECRET|KEY|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY|SIGNING)/i.test(name);

      yield makeFinding(
        'process-env-ref',
        `Environment Variable Reference: ${name}${isLikelySecret ? ' (likely secret)' : ''}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'process_env_reference',
        name,
        {
          isLikelySecret,
          source: 'source_code',
        },
      );
    }
  }
}

// ─── Cloud Secret Manager References ────────────────────────────

/** GCP Secret Manager references */
const GCP_SECRET_MGR_PATTERNS: RegExp[] = [
  // --set-secrets=KEY=SECRET_NAME:VERSION
  /--(?:set|update)-secrets[=\s]+([^\s]+)/g,
  // secretmanager client: client.accessSecretVersion({ name: 'projects/.../secrets/SECRET' })
  /secrets\/([a-zA-Z0-9_-]+)\/versions/g,
  // gcloud secrets: gcloud secrets versions access
  /gcloud\s+secrets\s+(?:versions\s+access|create|delete)\s+.*?(?:--secret[=\s]+)?["']?([a-zA-Z0-9_-]+)["']?/g,
];

/** AWS Secrets Manager / SSM Parameter Store */
const AWS_SECRET_MGR_PATTERNS: RegExp[] = [
  // AWS SSM: arn:aws:ssm:*:*:parameter/path
  /arn:aws:ssm:[^:]*:[^:]*:parameter\/([^\s"']+)/g,
  // AWS Secrets Manager: SecretId or secretName
  /(?:SecretId|secretName|secret_name)\s*[:=]\s*["']([a-zA-Z0-9/_-]+)["']/g,
  // AWS SSM getParameter: Name: '/path/to/param'
  /Name:\s*["'](\/[a-zA-Z0-9/_-]+)["']/g,
];

/** Azure Key Vault references */
const AZURE_KEYVAULT_PATTERNS: RegExp[] = [
  // https://vault-name.vault.azure.net/secrets/secret-name
  /([a-zA-Z0-9-]+)\.vault\.azure\.net\/secrets\/([a-zA-Z0-9-]+)/g,
  // @Microsoft.KeyVault(SecretUri=https://...)
  /@Microsoft\.KeyVault\(SecretUri=([^)]+)\)/g,
];

function* extractCloudSecretRefs(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  // GCP Secret Manager
  for (const pattern of GCP_SECRET_MGR_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const raw = match[1]!;
      // Parse comma-separated secret mappings from --set-secrets
      const secrets = raw.includes(',') ? raw.split(',') : [raw];
      for (const secret of secrets) {
        const name = secret.includes('=')
          ? secret.split('=')[1]!.split(':')[0]!.trim()
          : secret.split(':')[0]!.trim();
        if (!name || name.length < 2) continue;
        const key = `gcp-secret-mgr:${name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        yield makeFinding(
          'gcp-secret-manager-ref',
          `GCP Secret Manager: ${name}`,
          filePath,
          findLineNumber(content, match.index),
          pluginId,
          'gcp_secret_manager',
          name,
          { source: 'gcp_secret_manager' },
        );
      }
    }
  }

  // AWS Secrets Manager / SSM
  for (const pattern of AWS_SECRET_MGR_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `aws-secret-mgr:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'aws-secret-manager-ref',
        `AWS Secret/Parameter: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'aws_secret_manager',
        value,
        { source: 'aws_secrets_manager' },
      );
    }
  }

  // Azure Key Vault
  for (const pattern of AZURE_KEYVAULT_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const vaultName = match[1] ?? '';
      const secretName = match[2] ?? match[1]!;
      const value = vaultName && match[2] ? `${vaultName}/${secretName}` : secretName;
      const key = `azure-kv:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'azure-keyvault-ref',
        `Azure Key Vault Secret: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'azure_keyvault',
        value,
        { source: 'azure_keyvault', vaultName },
      );
    }
  }
}

// ─── Dockerfile ARG/ENV Declarations ────────────────────────────

/** Dockerfile ARG that looks like a secret/config placeholder */
const DOCKERFILE_ARG_PATTERN = /^\s*ARG\s+([A-Z_][A-Z0-9_]*)/gim;
const DOCKERFILE_ENV_PATTERN = /^\s*ENV\s+([A-Z_][A-Z0-9_]*)/gim;

function* extractDockerfileSecretNames(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  DOCKERFILE_ARG_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = DOCKERFILE_ARG_PATTERN.exec(content)) !== null) {
    const name = match[1]!;
    const key = `docker-arg:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const isLikelySecret = /(?:SECRET|KEY|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY)/i.test(name);
    yield makeFinding(
      'dockerfile-arg-name',
      `Dockerfile ARG: ${name}${isLikelySecret ? ' (likely secret)' : ''}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'dockerfile_arg',
      name,
      { isLikelySecret, source: 'dockerfile' },
    );
  }

  DOCKERFILE_ENV_PATTERN.lastIndex = 0;
  while ((match = DOCKERFILE_ENV_PATTERN.exec(content)) !== null) {
    const name = match[1]!;
    const key = `docker-env:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const isLikelySecret = /(?:SECRET|KEY|TOKEN|PASSWORD|PASS|AUTH|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY)/i.test(name);
    yield makeFinding(
      'dockerfile-env-name',
      `Dockerfile ENV: ${name}${isLikelySecret ? ' (likely secret)' : ''}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'dockerfile_env',
      name,
      { isLikelySecret, source: 'dockerfile' },
    );
  }
}

// ─── Main Export ─────────────────────────────────────────────────

/**
 * Extract secret name intelligence from a file.
 *
 * Dispatches to specific extractors based on file type and content.
 * Yields Finding objects with severity 'info' for each discovered secret name.
 */
export function* extractSecretNames(
  content: string,
  relativePath: string,
  pluginId: string,
): Generator<Finding> {
  const normalizedPath = relativePath.replace(/\\/g, '/').toLowerCase();

  // .env.example / .env.sample / .env.template / .env.local.example
  if (
    normalizedPath.endsWith('.env.example') ||
    normalizedPath.endsWith('.env.sample') ||
    normalizedPath.endsWith('.env.template') ||
    normalizedPath.endsWith('.env.development') ||
    normalizedPath.endsWith('.env.production') ||
    normalizedPath.endsWith('.env.staging') ||
    normalizedPath.endsWith('.env.test') ||
    normalizedPath.endsWith('.env.local.example')
  ) {
    yield* extractEnvExample(content, relativePath, pluginId);
  }

  // CI/CD secret references (GitHub Actions, GitLab CI, Azure Pipelines)
  if (
    normalizedPath.includes('.github/workflows/') ||
    normalizedPath.includes('gitlab-ci') ||
    normalizedPath.includes('azure-pipelines') ||
    normalizedPath.includes('.circleci/') ||
    normalizedPath.includes('bitbucket-pipelines')
  ) {
    yield* extractCicdSecrets(content, relativePath, pluginId);
  }

  // process.env.* references in source code
  if (
    normalizedPath.endsWith('.ts') ||
    normalizedPath.endsWith('.tsx') ||
    normalizedPath.endsWith('.js') ||
    normalizedPath.endsWith('.jsx') ||
    normalizedPath.endsWith('.mjs') ||
    normalizedPath.endsWith('.cjs') ||
    normalizedPath.endsWith('.py') ||
    normalizedPath.endsWith('.vue') ||
    normalizedPath.endsWith('.svelte')
  ) {
    yield* extractProcessEnv(content, relativePath, pluginId);
  }

  // Cloud secret manager references (any file type)
  yield* extractCloudSecretRefs(content, relativePath, pluginId);

  // Dockerfile ARG/ENV declarations
  if (
    normalizedPath.includes('dockerfile') ||
    normalizedPath.endsWith('containerfile')
  ) {
    yield* extractDockerfileSecretNames(content, relativePath, pluginId);
  }
}
