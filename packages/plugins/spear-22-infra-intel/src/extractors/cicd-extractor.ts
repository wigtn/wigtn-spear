/**
 * SPEAR-22: CI/CD & Cloud Infrastructure Extractor
 *
 * Extracts infrastructure intelligence from CI/CD configuration files:
 *   - GCP: project ID, region, service name, registry URL, secret names
 *   - AWS: account ID, region, bucket names, Lambda function names
 *   - Azure: subscription, resource group, service names
 *   - Docker: base images, exposed ports, env vars, volume mounts
 *
 * All findings are severity 'info' -- this is an intelligence module,
 * not a vulnerability scanner.
 */

import type { Finding } from '@wigtn/shared';

// ─── Helper ─────────────────────────────────────────────────────

/**
 * Find the 1-based line number of a regex match within content.
 * Returns 1 if the match position cannot be determined.
 */
function findLineNumber(content: string, matchIndex: number): number {
  if (matchIndex < 0 || matchIndex >= content.length) return 1;
  let line = 1;
  for (let i = 0; i < matchIndex && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

/**
 * Create a standard infrastructure finding.
 */
function makeFinding(
  ruleIdSuffix: string,
  message: string,
  file: string,
  line: number,
  pluginId: string,
  category: string,
  type: string,
  value: string,
): Finding {
  return {
    ruleId: `spear-22/${ruleIdSuffix}`,
    severity: 'info',
    message,
    file,
    line,
    metadata: {
      plugin: pluginId,
      category,
      type,
      value,
    },
  };
}

// ─── GCP Patterns ───────────────────────────────────────────────

/** GCP project ID: --project=xxx or PROJECT_ID: xxx or project: xxx */
const GCP_PROJECT_ID_PATTERNS: RegExp[] = [
  /--project[=\s]+([a-z][a-z0-9-]{4,28}[a-z0-9])/g,
  /(?:PROJECT_ID|project_id|gcp_project|GCLOUD_PROJECT|GCP_PROJECT)[=:\s]+["']?([a-z][a-z0-9-]{4,28}[a-z0-9])["']?/gi,
  /gcloud\s+.*?--project[=\s]+([a-z][a-z0-9-]{4,28}[a-z0-9])/g,
];

/** GCP region */
const GCP_REGION_PATTERNS: RegExp[] = [
  /--region[=\s]+([a-z]+-[a-z]+\d+)/g,
  /(?:REGION|gcp_region|CLOUD_RUN_REGION)[=:\s]+["']?([a-z]+-[a-z]+\d+)["']?/gi,
];

/** GCP service name */
const GCP_SERVICE_PATTERNS: RegExp[] = [
  /--service[=\s]+([a-z][a-z0-9-]+)/g,
  /(?:SERVICE_NAME|service_name|CLOUD_RUN_SERVICE)[=:\s]+["']?([a-z][a-z0-9-]+)["']?/gi,
];

/** GCP registry URL (gcr.io / artifact registry) */
const GCP_REGISTRY_PATTERNS: RegExp[] = [
  /((?:[a-z]+-)?(?:gcr\.io|docker\.pkg\.dev)\/[a-z0-9-]+(?:\/[a-z0-9-_]+)*)/g,
];

/** GCP secret names from --set-secrets or --update-secrets */
const GCP_SECRET_PATTERNS: RegExp[] = [
  /--(?:set|update)-secrets[=\s]+([^\s]+)/g,
  /secretmanager\.googleapis\.com.*?\/secrets\/([a-zA-Z0-9_-]+)/g,
  /gcloud\s+secrets\s+versions\s+access\s+.*?--secret[=\s]+["']?([a-zA-Z0-9_-]+)["']?/g,
];

// ─── AWS Patterns ───────────────────────────────────────────────

/** AWS account ID (12-digit number) */
const AWS_ACCOUNT_PATTERNS: RegExp[] = [
  /(\d{12})\.dkr\.ecr\./g,
  /(?:AWS_ACCOUNT_ID|aws_account_id)[=:\s]+["']?(\d{12})["']?/gi,
  /arn:aws:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):/g,
];

/** AWS region */
const AWS_REGION_PATTERNS: RegExp[] = [
  /(?:AWS_REGION|AWS_DEFAULT_REGION|aws_region)[=:\s]+["']?([a-z]+-[a-z]+-\d+)["']?/gi,
  /\.([a-z]+-[a-z]+-\d+)\.amazonaws\.com/g,
];

/** AWS S3 bucket names */
const AWS_BUCKET_PATTERNS: RegExp[] = [
  /s3:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/g,
  /(?:BUCKET_NAME|S3_BUCKET|aws_s3_bucket)[=:\s]+["']?([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])["']?/gi,
  /arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/g,
];

/** AWS Lambda function names */
const AWS_LAMBDA_PATTERNS: RegExp[] = [
  /(?:function_name|FunctionName|LAMBDA_FUNCTION)[=:\s]+["']?([a-zA-Z0-9_-]+)["']?/gi,
  /arn:aws:lambda:[a-z0-9-]+:\d{12}:function:([a-zA-Z0-9_-]+)/g,
  /functions:\s*\n(?:\s+([a-zA-Z0-9_-]+):)/g,
];

// ─── Azure Patterns ─────────────────────────────────────────────

/** Azure subscription ID */
const AZURE_SUBSCRIPTION_PATTERNS: RegExp[] = [
  /(?:AZURE_SUBSCRIPTION_ID|subscription_id|subscriptionId)[=:\s]+["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
];

/** Azure resource group */
const AZURE_RESOURCE_GROUP_PATTERNS: RegExp[] = [
  /(?:RESOURCE_GROUP|resource_group_name|resourceGroupName)[=:\s]+["']?([a-zA-Z0-9_-]+)["']?/gi,
  /\/resourceGroups\/([a-zA-Z0-9_-]+)/g,
];

/** Azure service names (App Service, Container Apps, etc.) */
const AZURE_SERVICE_PATTERNS: RegExp[] = [
  /(?:AZURE_WEBAPP_NAME|webapp_name|CONTAINER_APP_NAME)[=:\s]+["']?([a-zA-Z0-9_-]+)["']?/gi,
  /az\s+webapp\s+deploy.*?--name[=\s]+["']?([a-zA-Z0-9_-]+)["']?/g,
  /az\s+containerapp\s+.*?--name[=\s]+["']?([a-zA-Z0-9_-]+)["']?/g,
];

// ─── Docker Patterns ────────────────────────────────────────────

/** Docker FROM (base images) */
const DOCKER_FROM_PATTERN = /^\s*FROM\s+(?:--platform=[^\s]+\s+)?([^\s]+)/gim;

/** Docker EXPOSE (ports) */
const DOCKER_EXPOSE_PATTERN = /^\s*EXPOSE\s+(.+)/gim;

/** Docker ENV declarations */
const DOCKER_ENV_PATTERN = /^\s*ENV\s+([A-Z_][A-Z0-9_]*)[=\s]+(.+)/gim;

/** Docker ARG declarations */
const DOCKER_ARG_PATTERN = /^\s*ARG\s+([A-Z_][A-Z0-9_]*)(?:=(.+))?/gim;

/** Docker VOLUME mounts */
const DOCKER_VOLUME_PATTERN = /^\s*VOLUME\s+(.+)/gim;

/** docker-compose ports mapping */
const COMPOSE_PORTS_PATTERN = /ports:\s*\n((?:\s+-\s+["']?[\d:]+["']?\s*\n?)+)/gi;

/** docker-compose volumes mapping */
const COMPOSE_VOLUMES_PATTERN = /volumes:\s*\n((?:\s+-\s+.+\n?)+)/gi;

/** docker-compose image references */
const COMPOSE_IMAGE_PATTERN = /image:\s*["']?([^\s"']+)["']?/gi;

/** docker-compose services list */
const COMPOSE_SERVICE_PATTERN = /^services:\s*\n((?:\s{2}[a-zA-Z0-9_-]+:\s*\n(?:(?:\s{4,}.+\n)*))*)/gm;

// ─── Extract Functions ──────────────────────────────────────────

/**
 * Extract GCP infrastructure details.
 */
function* extractGcp(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const pattern of GCP_PROJECT_ID_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `gcp-project:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'gcp-project-id',
        `GCP Project ID: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'gcp_project_id',
        value,
      );
    }
  }

  for (const pattern of GCP_REGION_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `gcp-region:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'gcp-region',
        `GCP Region: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'gcp_region',
        value,
      );
    }
  }

  for (const pattern of GCP_SERVICE_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `gcp-service:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'gcp-service-name',
        `GCP Service Name: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'gcp_service_name',
        value,
      );
    }
  }

  for (const pattern of GCP_REGISTRY_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `gcp-registry:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'gcp-registry-url',
        `GCP Registry URL: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'gcp_registry_url',
        value,
      );
    }
  }

  for (const pattern of GCP_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      // --set-secrets may have multiple KEY=SECRET:VERSION pairs
      const secretPairs = value.split(',');
      for (const pair of secretPairs) {
        const secretName = pair.includes('=')
          ? pair.split('=')[1]!.split(':')[0]!.trim()
          : pair.split(':')[0]!.trim();
        if (!secretName || secretName.length < 2) continue;
        const key = `gcp-secret:${secretName}`;
        if (seen.has(key)) continue;
        seen.add(key);
        yield makeFinding(
          'gcp-secret-name',
          `GCP Secret Manager reference: ${secretName}`,
          filePath,
          findLineNumber(content, match.index),
          pluginId,
          'cloud_infrastructure',
          'gcp_secret_reference',
          secretName,
        );
      }
    }
  }
}

/**
 * Extract AWS infrastructure details.
 */
function* extractAws(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const pattern of AWS_ACCOUNT_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `aws-account:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'aws-account-id',
        `AWS Account ID: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'aws_account_id',
        value,
      );
    }
  }

  for (const pattern of AWS_REGION_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `aws-region:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'aws-region',
        `AWS Region: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'aws_region',
        value,
      );
    }
  }

  for (const pattern of AWS_BUCKET_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `aws-bucket:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'aws-s3-bucket',
        `AWS S3 Bucket: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'aws_s3_bucket',
        value,
      );
    }
  }

  for (const pattern of AWS_LAMBDA_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `aws-lambda:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'aws-lambda-function',
        `AWS Lambda Function: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'aws_lambda_function',
        value,
      );
    }
  }
}

/**
 * Extract Azure infrastructure details.
 */
function* extractAzure(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const pattern of AZURE_SUBSCRIPTION_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `azure-sub:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'azure-subscription-id',
        `Azure Subscription ID: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'azure_subscription_id',
        value,
      );
    }
  }

  for (const pattern of AZURE_RESOURCE_GROUP_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `azure-rg:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'azure-resource-group',
        `Azure Resource Group: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'azure_resource_group',
        value,
      );
    }
  }

  for (const pattern of AZURE_SERVICE_PATTERNS) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1]!;
      const key = `azure-svc:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'azure-service-name',
        `Azure Service Name: ${value}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'azure_service_name',
        value,
      );
    }
  }
}

/**
 * Extract Docker infrastructure details from Dockerfiles.
 */
function* extractDockerfile(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  // Base images
  DOCKER_FROM_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = DOCKER_FROM_PATTERN.exec(content)) !== null) {
    const value = match[1]!;
    if (value.startsWith('$') || value === 'scratch') continue;
    const key = `docker-image:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'docker-base-image',
      `Docker Base Image: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'docker_base_image',
      value,
    );
  }

  // Exposed ports
  DOCKER_EXPOSE_PATTERN.lastIndex = 0;
  while ((match = DOCKER_EXPOSE_PATTERN.exec(content)) !== null) {
    const portsStr = match[1]!.trim();
    const ports = portsStr.split(/\s+/);
    for (const port of ports) {
      const cleanPort = port.replace(/\/(tcp|udp)/i, '');
      const key = `docker-port:${cleanPort}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'docker-exposed-port',
        `Docker Exposed Port: ${cleanPort}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'cloud_infrastructure',
        'docker_exposed_port',
        cleanPort,
      );
    }
  }

  // ENV vars
  DOCKER_ENV_PATTERN.lastIndex = 0;
  while ((match = DOCKER_ENV_PATTERN.exec(content)) !== null) {
    const name = match[1]!;
    const value = match[2]!.trim();
    const key = `docker-env:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'docker-env-var',
      `Docker ENV: ${name}=${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'docker_env_var',
      `${name}=${value}`,
    );
  }

  // ARG declarations
  DOCKER_ARG_PATTERN.lastIndex = 0;
  while ((match = DOCKER_ARG_PATTERN.exec(content)) !== null) {
    const name = match[1]!;
    const defaultVal = match[2]?.trim() ?? '';
    const key = `docker-arg:${name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const display = defaultVal ? `${name}=${defaultVal}` : name;
    yield makeFinding(
      'docker-arg',
      `Docker ARG: ${display}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'docker_arg',
      display,
    );
  }

  // VOLUME mounts
  DOCKER_VOLUME_PATTERN.lastIndex = 0;
  while ((match = DOCKER_VOLUME_PATTERN.exec(content)) !== null) {
    const value = match[1]!.trim();
    const key = `docker-volume:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'docker-volume-mount',
      `Docker Volume: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'docker_volume',
      value,
    );
  }
}

/**
 * Extract Docker Compose infrastructure details.
 */
function* extractDockerCompose(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  // Services list
  COMPOSE_SERVICE_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = COMPOSE_SERVICE_PATTERN.exec(content)) !== null) {
    const servicesBlock = match[1]!;
    const serviceNamePattern = /^  ([a-zA-Z0-9_-]+):/gm;
    let svcMatch: RegExpExecArray | null;
    while ((svcMatch = serviceNamePattern.exec(servicesBlock)) !== null) {
      const name = svcMatch[1]!;
      const key = `compose-svc:${name}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'compose-service',
        `Docker Compose Service: ${name}`,
        filePath,
        findLineNumber(content, match.index + svcMatch.index),
        pluginId,
        'cloud_infrastructure',
        'compose_service',
        name,
      );
    }
  }

  // Image references
  COMPOSE_IMAGE_PATTERN.lastIndex = 0;
  while ((match = COMPOSE_IMAGE_PATTERN.exec(content)) !== null) {
    const value = match[1]!;
    if (value.startsWith('$')) continue;
    const key = `compose-image:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'compose-image',
      `Docker Compose Image: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'compose_image',
      value,
    );
  }

  // Ports
  COMPOSE_PORTS_PATTERN.lastIndex = 0;
  while ((match = COMPOSE_PORTS_PATTERN.exec(content)) !== null) {
    const portsBlock = match[1]!;
    const portLinePattern = /-\s+["']?([\d:]+)["']?/g;
    let portMatch: RegExpExecArray | null;
    while ((portMatch = portLinePattern.exec(portsBlock)) !== null) {
      const value = portMatch[1]!;
      const key = `compose-port:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'compose-port-mapping',
        `Docker Compose Port Mapping: ${value}`,
        filePath,
        findLineNumber(content, match.index + portMatch.index),
        pluginId,
        'cloud_infrastructure',
        'compose_port_mapping',
        value,
      );
    }
  }

  // Volumes
  COMPOSE_VOLUMES_PATTERN.lastIndex = 0;
  while ((match = COMPOSE_VOLUMES_PATTERN.exec(content)) !== null) {
    const volumesBlock = match[1]!;
    const volumeLinePattern = /-\s+(.+)/g;
    let volMatch: RegExpExecArray | null;
    while ((volMatch = volumeLinePattern.exec(volumesBlock)) !== null) {
      const value = volMatch[1]!.trim();
      if (!value) continue;
      const key = `compose-vol:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'compose-volume',
        `Docker Compose Volume: ${value}`,
        filePath,
        findLineNumber(content, match.index + volMatch.index),
        pluginId,
        'cloud_infrastructure',
        'compose_volume',
        value,
      );
    }
  }
}

/**
 * Extract Terraform infrastructure details.
 */
function* extractTerraform(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  // Terraform provider configurations
  const providerPattern = /provider\s+"([a-zA-Z0-9_-]+)"\s*\{/g;
  let match: RegExpExecArray | null;
  while ((match = providerPattern.exec(content)) !== null) {
    const value = match[1]!;
    const key = `tf-provider:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'terraform-provider',
      `Terraform Provider: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'terraform_provider',
      value,
    );
  }

  // Terraform resource types
  const resourcePattern = /resource\s+"([a-zA-Z0-9_]+)"\s+"([a-zA-Z0-9_-]+)"/g;
  while ((match = resourcePattern.exec(content)) !== null) {
    const resourceType = match[1]!;
    const resourceName = match[2]!;
    const value = `${resourceType}.${resourceName}`;
    const key = `tf-resource:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'terraform-resource',
      `Terraform Resource: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'terraform_resource',
      value,
    );
  }

  // Terraform variables
  const variablePattern = /variable\s+"([a-zA-Z0-9_-]+)"/g;
  while ((match = variablePattern.exec(content)) !== null) {
    const value = match[1]!;
    const key = `tf-var:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'terraform-variable',
      `Terraform Variable: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'terraform_variable',
      value,
    );
  }

  // Terraform backend (state storage)
  const backendPattern = /backend\s+"([a-zA-Z0-9_-]+)"\s*\{/g;
  while ((match = backendPattern.exec(content)) !== null) {
    const value = match[1]!;
    const key = `tf-backend:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'terraform-backend',
      `Terraform Backend: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'terraform_backend',
      value,
    );
  }
}

/**
 * Extract Serverless Framework details.
 */
function* extractServerless(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  // Serverless service name
  const servicePattern = /^service:\s*["']?([a-zA-Z0-9_-]+)["']?/m;
  const serviceMatch = servicePattern.exec(content);
  if (serviceMatch) {
    const value = serviceMatch[1]!;
    yield makeFinding(
      'serverless-service',
      `Serverless Service: ${value}`,
      filePath,
      findLineNumber(content, serviceMatch.index),
      pluginId,
      'cloud_infrastructure',
      'serverless_service',
      value,
    );
  }

  // Serverless provider/runtime
  const runtimePattern = /runtime:\s*["']?([a-zA-Z0-9._-]+)["']?/g;
  let match: RegExpExecArray | null;
  while ((match = runtimePattern.exec(content)) !== null) {
    const value = match[1]!;
    const key = `sls-runtime:${value}`;
    if (seen.has(key)) continue;
    seen.add(key);
    yield makeFinding(
      'serverless-runtime',
      `Serverless Runtime: ${value}`,
      filePath,
      findLineNumber(content, match.index),
      pluginId,
      'cloud_infrastructure',
      'serverless_runtime',
      value,
    );
  }

  // Serverless functions
  const functionBlockPattern = /^functions:\s*$/m;
  const funcBlockMatch = functionBlockPattern.exec(content);
  if (funcBlockMatch) {
    const afterFunctions = content.slice(funcBlockMatch.index + funcBlockMatch[0].length);
    const funcNamePattern = /^\s{2}([a-zA-Z0-9_-]+):/gm;
    let funcMatch: RegExpExecArray | null;
    while ((funcMatch = funcNamePattern.exec(afterFunctions)) !== null) {
      // Stop if we hit a top-level key (no indentation)
      if (/^\S/m.test(afterFunctions.slice(0, funcMatch.index).split('\n').pop() ?? '')) break;
      const value = funcMatch[1]!;
      const key = `sls-function:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'serverless-function',
        `Serverless Function: ${value}`,
        filePath,
        findLineNumber(content, funcBlockMatch.index + funcBlockMatch[0].length + funcMatch.index),
        pluginId,
        'cloud_infrastructure',
        'serverless_function',
        value,
      );
    }
  }
}

// ─── Main Export ─────────────────────────────────────────────────

/**
 * Extract CI/CD and cloud infrastructure intelligence from a file.
 *
 * Dispatches to cloud-specific extractors based on file content and path.
 * Yields Finding objects with severity 'info' for each discovered piece
 * of infrastructure intelligence.
 */
export function* extractCicd(
  content: string,
  relativePath: string,
  pluginId: string,
): Generator<Finding> {
  const normalizedPath = relativePath.replace(/\\/g, '/').toLowerCase();

  // GCP extraction -- run on all CI/CD-related files
  yield* extractGcp(content, relativePath, pluginId);

  // AWS extraction -- run on all CI/CD-related files
  yield* extractAws(content, relativePath, pluginId);

  // Azure extraction -- run on all CI/CD-related files
  yield* extractAzure(content, relativePath, pluginId);

  // Dockerfile extraction
  if (
    normalizedPath.includes('dockerfile') ||
    normalizedPath.endsWith('containerfile')
  ) {
    yield* extractDockerfile(content, relativePath, pluginId);
  }

  // Docker Compose extraction
  if (
    normalizedPath.includes('docker-compose') ||
    normalizedPath.includes('compose.yml') ||
    normalizedPath.includes('compose.yaml')
  ) {
    yield* extractDockerCompose(content, relativePath, pluginId);
  }

  // Terraform extraction
  if (normalizedPath.endsWith('.tf')) {
    yield* extractTerraform(content, relativePath, pluginId);
  }

  // Serverless extraction
  if (
    normalizedPath.includes('serverless.yml') ||
    normalizedPath.includes('serverless.yaml') ||
    normalizedPath.includes('serverless.ts')
  ) {
    yield* extractServerless(content, relativePath, pluginId);
  }
}
