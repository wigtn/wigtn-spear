/**
 * SPEAR-13: Cloud Credential Chain -- Pattern Definitions
 *
 * Defines 60+ regex patterns for detecting cloud credentials, IAM role
 * chains, and metadata service access across three major cloud providers:
 *
 *   - AWS   -- AKIA keys, secret keys, session tokens, assumed role ARNs,
 *              STS credentials, IMDS URLs (169.254.169.254)
 *   - GCP   -- Service account JSON, gcloud auth tokens, Application Default
 *              Credentials (ADC) file paths, Compute metadata URLs
 *   - Azure -- Client secrets, managed identity tokens, connection strings,
 *              SAS tokens, Key Vault references
 *
 * Cross-cloud patterns:
 *   - IMDS / metadata service access (all three providers)
 *   - Environment variable exposure for cloud credentials
 *   - Credential file path references
 *
 * Each pattern includes MITRE ATT&CK mappings:
 *   T1552     -- Unsecured Credentials
 *   T1078     -- Valid Accounts
 *   T1078.004 -- Valid Accounts: Cloud Accounts
 *   T1552.001 -- Unsecured Credentials: Credentials In Files
 *   T1552.004 -- Unsecured Credentials: Private Keys
 *   T1098     -- Account Manipulation
 */

import type { Severity } from '@wigtn/shared';

// ─── Types ──────────────────────────────────────────────────────

export type CloudProvider = 'aws' | 'gcp' | 'azure' | 'generic';

export type CredentialCategory =
  | 'access_key'
  | 'secret_key'
  | 'session_token'
  | 'iam_role'
  | 'service_account'
  | 'auth_token'
  | 'connection_string'
  | 'sas_token'
  | 'client_secret'
  | 'private_key'
  | 'metadata_service'
  | 'credential_file'
  | 'env_exposure';

export interface CredentialPattern {
  id: string;
  name: string;
  description: string;
  provider: CloudProvider;
  category: CredentialCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
}

// ─── AWS Patterns ───────────────────────────────────────────────

const awsPatterns: CredentialPattern[] = [
  // --- Access Keys ---
  {
    id: 'aws-akia-access-key',
    name: 'AWS Access Key ID (AKIA)',
    description: 'Long-term AWS access key ID starting with AKIA',
    provider: 'aws',
    category: 'access_key',
    pattern: /\bAKIA[0-9A-Z]{16}\b/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the hardcoded AWS access key. Use IAM roles, instance profiles, or environment-based credential providers instead.',
  },
  {
    id: 'aws-asia-temp-key',
    name: 'AWS Temporary Access Key (ASIA)',
    description: 'Temporary STS access key starting with ASIA',
    provider: 'aws',
    category: 'access_key',
    pattern: /\bASIA[0-9A-Z]{16}\b/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the hardcoded temporary AWS key. Temporary credentials should never be committed to source control.',
  },
  {
    id: 'aws-aida-iam-key',
    name: 'AWS IAM Unique ID (AIDA)',
    description: 'AWS IAM user unique identifier starting with AIDA',
    provider: 'aws',
    category: 'access_key',
    pattern: /\bAIDA[0-9A-Z]{16}\b/,
    severity: 'high',
    mitre: ['T1078.004'],
    remediation: 'Remove the AWS IAM user identifier. While not a credential itself, it reveals IAM user information useful for targeted attacks.',
  },
  {
    id: 'aws-aroa-role-id',
    name: 'AWS Role ID (AROA)',
    description: 'AWS IAM role unique identifier starting with AROA',
    provider: 'aws',
    category: 'iam_role',
    pattern: /\bAROA[0-9A-Z]{16}\b/,
    severity: 'high',
    mitre: ['T1078.004', 'T1098'],
    remediation: 'Remove the AWS role ID. Role identifiers expose the IAM role structure and can assist in privilege escalation.',
  },

  // --- Secret Keys ---
  {
    id: 'aws-secret-key-assignment',
    name: 'AWS Secret Access Key Assignment',
    description: 'AWS secret access key assigned to a variable or config field',
    provider: 'aws',
    category: 'secret_key',
    pattern: /(?:aws_secret_access_key|aws_secret_key|secret_access_key|secretAccessKey)\s*[:=]\s*['"`]?[A-Za-z0-9/+=]{40}['"`]?/i,
    severity: 'critical',
    mitre: ['T1552', 'T1552.001', 'T1078.004'],
    remediation: 'Remove the hardcoded AWS secret key immediately. Rotate the key and use IAM roles or a secrets manager.',
  },
  {
    id: 'aws-secret-key-pattern',
    name: 'AWS Secret Access Key Pattern',
    description: 'Standalone 40-character base64 string following an AWS access key context',
    provider: 'aws',
    category: 'secret_key',
    pattern: /(?:secret|aws_secret)[^=]*=\s*['"`]?(?:[A-Za-z0-9/+=]{40})['"`]?/i,
    severity: 'critical',
    mitre: ['T1552', 'T1552.001'],
    remediation: 'Remove the hardcoded secret key. Use AWS Secrets Manager or Parameter Store for credential storage.',
  },

  // --- Session Tokens ---
  {
    id: 'aws-session-token',
    name: 'AWS Session Token',
    description: 'AWS STS session token assigned to a variable or config field',
    provider: 'aws',
    category: 'session_token',
    pattern: /(?:aws_session_token|sessionToken|session_token)\s*[:=]\s*['"`]?[A-Za-z0-9/+=]{100,}['"`]?/i,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the STS session token. Temporary credentials must not be stored in source code or config files.',
  },
  {
    id: 'aws-security-token',
    name: 'AWS Security Token',
    description: 'AWS security token in environment or config context',
    provider: 'aws',
    category: 'session_token',
    pattern: /AWS_SECURITY_TOKEN\s*[:=]\s*['"`]?[A-Za-z0-9/+=]{100,}['"`]?/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the hardcoded AWS security token. Use credential provider chains for runtime credential resolution.',
  },

  // --- IAM / STS ---
  {
    id: 'aws-assume-role-arn',
    name: 'AWS Assumed Role ARN',
    description: 'ARN for an AWS IAM assumed role (arn:aws:sts::*:assumed-role)',
    provider: 'aws',
    category: 'iam_role',
    pattern: /arn:aws:sts::[0-9]{12}:assumed-role\/[A-Za-z0-9_+=,.@\/-]+/,
    severity: 'high',
    mitre: ['T1078.004', 'T1098'],
    remediation: 'Remove the assumed role ARN from source code. Role ARNs in code expose the IAM trust chain.',
  },
  {
    id: 'aws-role-arn',
    name: 'AWS IAM Role ARN',
    description: 'ARN for an AWS IAM role (arn:aws:iam::*:role/*)',
    provider: 'aws',
    category: 'iam_role',
    pattern: /arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9_+=,.@\/-]+/,
    severity: 'medium',
    mitre: ['T1078.004', 'T1098'],
    remediation: 'Avoid hardcoding IAM role ARNs in source code. Use configuration or environment variables to reference roles.',
  },
  {
    id: 'aws-user-arn',
    name: 'AWS IAM User ARN',
    description: 'ARN for an AWS IAM user (arn:aws:iam::*:user/*)',
    provider: 'aws',
    category: 'iam_role',
    pattern: /arn:aws:iam::[0-9]{12}:user\/[A-Za-z0-9_+=,.@\/-]+/,
    severity: 'medium',
    mitre: ['T1078.004'],
    remediation: 'Avoid hardcoding IAM user ARNs. These expose account structure and specific user identities.',
  },
  {
    id: 'aws-sts-get-caller-identity',
    name: 'AWS STS GetCallerIdentity Response',
    description: 'STS GetCallerIdentity response data embedded in code or config',
    provider: 'aws',
    category: 'iam_role',
    pattern: /GetCallerIdentity[\s\S]{0,100}(?:Account|Arn|UserId)\s*[:=]/i,
    severity: 'medium',
    mitre: ['T1078.004'],
    remediation: 'Remove STS identity response data from source files. This reveals the AWS account identity chain.',
  },

  // --- IMDS ---
  {
    id: 'aws-imds-v1-url',
    name: 'AWS IMDS v1 URL',
    description: 'HTTP request to the AWS Instance Metadata Service (169.254.169.254)',
    provider: 'aws',
    category: 'metadata_service',
    pattern: /https?:\/\/169\.254\.169\.254\/latest\/(?:meta-data|user-data|dynamic|api\/token)/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove IMDS URL references. If metadata access is needed, use IMDSv2 with token authentication and restrict access via instance roles.',
  },
  {
    id: 'aws-imds-credentials-path',
    name: 'AWS IMDS Credentials Path',
    description: 'Direct access to IAM credentials through the IMDS endpoint',
    provider: 'aws',
    category: 'metadata_service',
    pattern: /169\.254\.169\.254\/latest\/meta-data\/iam\/security-credentials\/?/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004', 'T1098'],
    remediation: 'Remove direct IMDS credential access. Use the AWS SDK credential provider chain which handles IMDS interaction securely.',
  },

  // --- Credential Files ---
  {
    id: 'aws-credentials-file',
    name: 'AWS Credentials File Path',
    description: 'Reference to the AWS credentials file (~/.aws/credentials)',
    provider: 'aws',
    category: 'credential_file',
    pattern: /(?:~|\/home\/\w+|\$HOME|%USERPROFILE%)\/\.aws\/credentials/i,
    severity: 'high',
    mitre: ['T1552.001'],
    remediation: 'Remove direct references to the AWS credentials file. Use environment variables or the AWS SDK default credential chain.',
  },
  {
    id: 'aws-config-file',
    name: 'AWS Config File Path',
    description: 'Reference to the AWS config file (~/.aws/config)',
    provider: 'aws',
    category: 'credential_file',
    pattern: /(?:~|\/home\/\w+|\$HOME|%USERPROFILE%)\/\.aws\/config/i,
    severity: 'medium',
    mitre: ['T1552.001'],
    remediation: 'Avoid hardcoding paths to AWS config files. Use SDK defaults or environment variable overrides.',
  },

  // --- Environment Variables ---
  {
    id: 'aws-env-access-key',
    name: 'AWS Access Key Env Var',
    description: 'AWS_ACCESS_KEY_ID environment variable set with a value',
    provider: 'aws',
    category: 'env_exposure',
    pattern: /AWS_ACCESS_KEY_ID\s*[:=]\s*['"`]?AKIA[0-9A-Z]{16}['"`]?/,
    severity: 'critical',
    mitre: ['T1552', 'T1552.001', 'T1078.004'],
    remediation: 'Remove the hardcoded AWS_ACCESS_KEY_ID. Set it via a secure secrets manager or CI/CD variable injection.',
  },
  {
    id: 'aws-env-secret-key',
    name: 'AWS Secret Key Env Var',
    description: 'AWS_SECRET_ACCESS_KEY environment variable set with a value',
    provider: 'aws',
    category: 'env_exposure',
    pattern: /AWS_SECRET_ACCESS_KEY\s*[:=]\s*['"`]?[A-Za-z0-9/+=]{40}['"`]?/,
    severity: 'critical',
    mitre: ['T1552', 'T1552.001', 'T1078.004'],
    remediation: 'Remove the hardcoded AWS_SECRET_ACCESS_KEY. Use a secrets manager or runtime injection.',
  },
  {
    id: 'aws-env-session-token',
    name: 'AWS Session Token Env Var',
    description: 'AWS_SESSION_TOKEN environment variable set with a value',
    provider: 'aws',
    category: 'env_exposure',
    pattern: /AWS_SESSION_TOKEN\s*[:=]\s*['"`]?[A-Za-z0-9/+=]{100,}['"`]?/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove hardcoded session tokens. Temporary credentials should be resolved at runtime.',
  },
  {
    id: 'aws-env-default-region',
    name: 'AWS Default Region Env Var With Credential Context',
    description: 'AWS_DEFAULT_REGION set alongside credential environment variables',
    provider: 'aws',
    category: 'env_exposure',
    pattern: /AWS_DEFAULT_REGION\s*[:=]\s*['"`]?[a-z]{2}-[a-z]+-\d['"`]?/,
    severity: 'info',
    mitre: ['T1078.004'],
    remediation: 'Verify that the region configuration does not appear alongside hardcoded credentials in the same file.',
  },
];

// ─── GCP Patterns ───────────────────────────────────────────────

const gcpPatterns: CredentialPattern[] = [
  // --- Service Account Keys ---
  {
    id: 'gcp-service-account-json',
    name: 'GCP Service Account JSON Key',
    description: 'Google Cloud service account private key JSON structure',
    provider: 'gcp',
    category: 'service_account',
    pattern: /"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key"/,
    severity: 'critical',
    mitre: ['T1552', 'T1552.004', 'T1078.004'],
    remediation: 'Remove the service account JSON key file from the repository. Use Workload Identity Federation or runtime key injection.',
  },
  {
    id: 'gcp-private-key-id',
    name: 'GCP Private Key ID',
    description: 'Google Cloud service account private key ID field',
    provider: 'gcp',
    category: 'service_account',
    pattern: /"private_key_id"\s*:\s*"[a-f0-9]{40}"/,
    severity: 'critical',
    mitre: ['T1552', 'T1552.004'],
    remediation: 'Remove the private key ID. This identifies a specific service account key that should be managed externally.',
  },
  {
    id: 'gcp-client-email',
    name: 'GCP Service Account Email',
    description: 'Google Cloud service account email address in credential context',
    provider: 'gcp',
    category: 'service_account',
    pattern: /"client_email"\s*:\s*"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com"/,
    severity: 'high',
    mitre: ['T1078.004'],
    remediation: 'Remove service account email references from source code. Use IAM bindings via infrastructure-as-code instead.',
  },
  {
    id: 'gcp-private-key-pem',
    name: 'GCP Private Key (PEM)',
    description: 'RSA private key in PEM format associated with GCP service account',
    provider: 'gcp',
    category: 'private_key',
    pattern: /-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]{100,}-----END (?:RSA )?PRIVATE KEY-----/,
    severity: 'critical',
    mitre: ['T1552.004'],
    remediation: 'Remove the private key from the codebase immediately. Store keys in a secrets manager and rotate the compromised key.',
  },

  // --- Auth Tokens ---
  {
    id: 'gcp-oauth-token',
    name: 'GCP OAuth Access Token',
    description: 'Google OAuth 2.0 access token (ya29.* pattern)',
    provider: 'gcp',
    category: 'auth_token',
    pattern: /\bya29\.[A-Za-z0-9_-]{50,}/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the OAuth access token. Google access tokens are short-lived but must never be committed to source control.',
  },
  {
    id: 'gcp-refresh-token',
    name: 'GCP Refresh Token',
    description: 'Google OAuth refresh token pattern',
    provider: 'gcp',
    category: 'auth_token',
    pattern: /(?:refresh_token|refreshToken)\s*[:=]\s*['"`]?1\/\/[A-Za-z0-9_-]{40,}['"`]?/i,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the refresh token. Refresh tokens provide long-term access and must be stored in a secrets manager.',
  },
  {
    id: 'gcp-api-key',
    name: 'GCP API Key',
    description: 'Google Cloud API key pattern (AIza prefix)',
    provider: 'gcp',
    category: 'access_key',
    pattern: /\bAIza[A-Za-z0-9_-]{35}\b/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the GCP API key. Restrict API keys by referrer/IP and use service accounts for server-side authentication.',
  },

  // --- ADC / Credential Files ---
  {
    id: 'gcp-adc-file-path',
    name: 'GCP Application Default Credentials Path',
    description: 'Reference to the ADC file path (~/.config/gcloud/application_default_credentials.json)',
    provider: 'gcp',
    category: 'credential_file',
    pattern: /(?:~|\/home\/\w+|\$HOME|%APPDATA%)\/(?:\.config\/gcloud|gcloud)\/application_default_credentials\.json/i,
    severity: 'high',
    mitre: ['T1552.001'],
    remediation: 'Remove hardcoded ADC file paths. Use GOOGLE_APPLICATION_CREDENTIALS environment variable or Workload Identity.',
  },
  {
    id: 'gcp-credentials-env',
    name: 'GOOGLE_APPLICATION_CREDENTIALS Env Var',
    description: 'GOOGLE_APPLICATION_CREDENTIALS set to a file path',
    provider: 'gcp',
    category: 'credential_file',
    pattern: /GOOGLE_APPLICATION_CREDENTIALS\s*[:=]\s*['"`]?[^\s'"`,;]+\.json['"`]?/,
    severity: 'medium',
    mitre: ['T1552.001'],
    remediation: 'Ensure the credential file path does not point to a committed JSON key. Use runtime injection or Workload Identity.',
  },
  {
    id: 'gcp-gcloud-auth-print',
    name: 'gcloud Auth Print Token',
    description: 'Command to print gcloud access or identity token',
    provider: 'gcp',
    category: 'auth_token',
    pattern: /gcloud\s+auth\s+(?:print-access-token|print-identity-token|application-default\s+print-access-token)/,
    severity: 'medium',
    mitre: ['T1552'],
    remediation: 'Avoid embedding gcloud CLI token commands in source code. Use client libraries with automatic credential resolution.',
  },

  // --- Metadata Service ---
  {
    id: 'gcp-metadata-url',
    name: 'GCP Compute Metadata URL',
    description: 'HTTP request to the GCP Compute metadata server (metadata.google.internal)',
    provider: 'gcp',
    category: 'metadata_service',
    pattern: /https?:\/\/metadata\.google\.internal\/computeMetadata\/v1\/?/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove direct metadata server access. Use the GCP client libraries which handle metadata securely.',
  },
  {
    id: 'gcp-metadata-ip',
    name: 'GCP Metadata IP Access',
    description: 'HTTP request to the GCP metadata server via IP (169.254.169.254)',
    provider: 'gcp',
    category: 'metadata_service',
    pattern: /169\.254\.169\.254\/computeMetadata\/v1\/?/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove metadata service IP access. Use metadata.google.internal hostname if metadata access is necessary, and prefer client libraries.',
  },
  {
    id: 'gcp-metadata-flavor-header',
    name: 'GCP Metadata-Flavor Header',
    description: 'Metadata-Flavor: Google header used for GCP metadata service requests',
    provider: 'gcp',
    category: 'metadata_service',
    pattern: /Metadata-Flavor\s*[:=]\s*['"`]?Google['"`]?/i,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Review why GCP metadata headers appear in source code. This suggests direct metadata service interaction that should use SDK methods.',
  },

  // --- Additional GCP Patterns ---
  {
    id: 'gcp-service-account-impersonation',
    name: 'GCP Service Account Impersonation',
    description: 'IAM service account impersonation configuration',
    provider: 'gcp',
    category: 'iam_role',
    pattern: /(?:impersonate_service_account|source_service_account|target_service_account)\s*[:=]\s*['"`]?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.iam\.gserviceaccount\.com/i,
    severity: 'high',
    mitre: ['T1078.004', 'T1098'],
    remediation: 'Review service account impersonation chains. Ensure least-privilege and document the impersonation graph.',
  },
  {
    id: 'gcp-project-number',
    name: 'GCP Project Number in Credential Context',
    description: 'GCP project number appearing alongside credential patterns',
    provider: 'gcp',
    category: 'service_account',
    pattern: /"project_id"\s*:\s*"[a-z][a-z0-9-]{4,28}[a-z0-9]"[\s\S]{0,200}"private_key"/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove credential JSON structures containing project IDs. This is a full service account key file.',
  },
];

// ─── Azure Patterns ─────────────────────────────────────────────

const azurePatterns: CredentialPattern[] = [
  // --- Client Secrets ---
  {
    id: 'azure-client-secret',
    name: 'Azure Client Secret',
    description: 'Azure AD application client secret or password credential',
    provider: 'azure',
    category: 'client_secret',
    pattern: /(?:AZURE_CLIENT_SECRET|client_secret|clientSecret|aadClientSecret)\s*[:=]\s*['"`]?[A-Za-z0-9~._-]{34,}['"`]?/i,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the Azure client secret. Use managed identities or certificate-based authentication.',
  },
  {
    id: 'azure-client-id',
    name: 'Azure Client ID',
    description: 'Azure AD application (client) ID in credential context',
    provider: 'azure',
    category: 'client_secret',
    pattern: /(?:AZURE_CLIENT_ID|client_id|clientId|appId)\s*[:=]\s*['"`]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]?/i,
    severity: 'medium',
    mitre: ['T1078.004'],
    remediation: 'Avoid hardcoding Azure client IDs. Use configuration or environment variable injection.',
  },
  {
    id: 'azure-tenant-id',
    name: 'Azure Tenant ID',
    description: 'Azure AD tenant (directory) ID',
    provider: 'azure',
    category: 'client_secret',
    pattern: /(?:AZURE_TENANT_ID|tenant_id|tenantId|directoryId)\s*[:=]\s*['"`]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]?/i,
    severity: 'low',
    mitre: ['T1078.004'],
    remediation: 'While tenant IDs are less sensitive, avoid hardcoding Azure AD identifiers. Use runtime configuration.',
  },

  // --- Connection Strings ---
  {
    id: 'azure-storage-connection-string',
    name: 'Azure Storage Connection String',
    description: 'Azure Blob/Queue/Table/File storage connection string with account key',
    provider: 'azure',
    category: 'connection_string',
    pattern: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};/,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the storage connection string. Use managed identities with RBAC, or store connection strings in Azure Key Vault.',
  },
  {
    id: 'azure-sql-connection-string',
    name: 'Azure SQL Connection String',
    description: 'Azure SQL or SQL Server connection string with password',
    provider: 'azure',
    category: 'connection_string',
    pattern: /Server=.*\.database\.windows\.net.*Password\s*=\s*[^;]+/i,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the SQL connection string with embedded password. Use Azure AD authentication or Key Vault references.',
  },
  {
    id: 'azure-cosmosdb-connection',
    name: 'Azure CosmosDB Connection String',
    description: 'Azure CosmosDB connection string with account key',
    provider: 'azure',
    category: 'connection_string',
    pattern: /AccountEndpoint=https:\/\/[^;]+\.documents\.azure\.com[^;]*;AccountKey=[A-Za-z0-9+/=]{86,88}/i,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the CosmosDB connection string. Use managed identities for data plane access.',
  },
  {
    id: 'azure-service-bus-connection',
    name: 'Azure Service Bus Connection String',
    description: 'Azure Service Bus connection string with shared access key',
    provider: 'azure',
    category: 'connection_string',
    pattern: /Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net\/?\s*;SharedAccessKeyName=[^;]+;SharedAccessKey=[A-Za-z0-9+/=]+/i,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the Service Bus connection string. Use managed identities or store in Key Vault.',
  },
  {
    id: 'azure-eventhub-connection',
    name: 'Azure Event Hub Connection String',
    description: 'Azure Event Hub connection string with shared access key',
    provider: 'azure',
    category: 'connection_string',
    pattern: /Endpoint=sb:\/\/[^;]+\.servicebus\.windows\.net\/?\s*;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;]+;EntityPath=/i,
    severity: 'critical',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the Event Hub connection string. Use managed identities with RBAC for Event Hub access.',
  },

  // --- SAS Tokens ---
  {
    id: 'azure-sas-token',
    name: 'Azure Shared Access Signature (SAS) Token',
    description: 'Azure Storage SAS token with signature',
    provider: 'azure',
    category: 'sas_token',
    pattern: /[?&](?:sv|se|sp|sig)=[^&\s]+&(?:sv|se|sp|sig)=[^&\s]+&(?:sv|se|sp|sig)=[^&\s]+&sig=[A-Za-z0-9%+/=]+/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove SAS tokens from source code. Generate SAS tokens at runtime with minimal permissions and short expiry.',
  },
  {
    id: 'azure-sas-url',
    name: 'Azure SAS URL',
    description: 'Azure Blob Storage URL with embedded SAS token',
    provider: 'azure',
    category: 'sas_token',
    pattern: /https:\/\/[a-z0-9]+\.blob\.core\.windows\.net\/[^?]+\?[^\s]*sig=[A-Za-z0-9%+/=]+/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove SAS URLs from code. Generate them at runtime with short expiry times.',
  },

  // --- Managed Identity ---
  {
    id: 'azure-managed-identity-endpoint',
    name: 'Azure Managed Identity Endpoint',
    description: 'Azure IMDS managed identity token endpoint access',
    provider: 'azure',
    category: 'metadata_service',
    pattern: /169\.254\.169\.254\/metadata\/identity\/oauth2\/token/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Avoid direct IMDS identity calls. Use Azure Identity client library (DefaultAzureCredential) for secure token acquisition.',
  },
  {
    id: 'azure-identity-endpoint',
    name: 'Azure Identity Endpoint Env Var',
    description: 'IDENTITY_ENDPOINT environment variable for managed identity',
    provider: 'azure',
    category: 'metadata_service',
    pattern: /IDENTITY_ENDPOINT\s*[:=]\s*['"`]?https?:\/\/[^\s'"`,]+['"`]?/,
    severity: 'medium',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Review direct use of IDENTITY_ENDPOINT. Prefer the Azure Identity SDK which handles endpoint discovery automatically.',
  },
  {
    id: 'azure-msi-endpoint',
    name: 'Azure MSI Endpoint',
    description: 'Legacy Managed Service Identity (MSI) endpoint reference',
    provider: 'azure',
    category: 'metadata_service',
    pattern: /MSI_ENDPOINT\s*[:=]\s*['"`]?https?:\/\/[^\s'"`,]+['"`]?/,
    severity: 'medium',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'MSI_ENDPOINT is a legacy pattern. Migrate to DefaultAzureCredential which handles both legacy and modern identity endpoints.',
  },

  // --- Key Vault ---
  {
    id: 'azure-keyvault-url',
    name: 'Azure Key Vault URL',
    description: 'Azure Key Vault URL reference',
    provider: 'azure',
    category: 'credential_file',
    pattern: /https:\/\/[a-zA-Z0-9-]+\.vault\.azure\.net\/?/,
    severity: 'low',
    mitre: ['T1078.004'],
    remediation: 'Key Vault URLs themselves are low risk but verify that access policies follow least privilege.',
  },

  // --- Environment Variables ---
  {
    id: 'azure-env-subscription-id',
    name: 'Azure Subscription ID Env Var',
    description: 'Azure subscription ID in environment or config',
    provider: 'azure',
    category: 'env_exposure',
    pattern: /AZURE_SUBSCRIPTION_ID\s*[:=]\s*['"`]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"`]?/i,
    severity: 'low',
    mitre: ['T1078.004'],
    remediation: 'Subscription IDs are not credentials but do expose account structure. Use runtime configuration.',
  },

  // --- Azure Metadata ---
  {
    id: 'azure-imds-metadata-url',
    name: 'Azure IMDS Metadata URL',
    description: 'Azure Instance Metadata Service URL access',
    provider: 'azure',
    category: 'metadata_service',
    pattern: /169\.254\.169\.254\/metadata\/instance\/?/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Avoid direct IMDS access. Use Azure SDK methods for instance metadata if required.',
  },
  {
    id: 'azure-metadata-header',
    name: 'Azure Metadata Header',
    description: 'Metadata: true header used for Azure IMDS requests',
    provider: 'azure',
    category: 'metadata_service',
    pattern: /['"`]?Metadata['"`]?\s*[:=]\s*['"`]?true['"`]?/i,
    severity: 'medium',
    mitre: ['T1552'],
    remediation: 'Review the use of Azure IMDS metadata headers. This indicates direct metadata service interaction.',
  },
];

// ─── Generic / Cross-Cloud Patterns ─────────────────────────────

const genericPatterns: CredentialPattern[] = [
  // --- IMDS (All Clouds) ---
  {
    id: 'generic-imds-link-local',
    name: 'IMDS Link-Local IP',
    description: 'Generic reference to the cloud metadata link-local IP address (169.254.169.254)',
    provider: 'generic',
    category: 'metadata_service',
    pattern: /169\.254\.169\.254/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove references to the metadata service IP. Use cloud SDK methods for metadata and credential resolution.',
  },
  {
    id: 'generic-imds-alternative-ip',
    name: 'IMDS Alternative IP (fd00:ec2::254)',
    description: 'IPv6 link-local address used for AWS EC2 IMDS',
    provider: 'generic',
    category: 'metadata_service',
    pattern: /fd00:ec2::254/,
    severity: 'high',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Remove the IPv6 IMDS address. Use SDK credential provider chains instead of direct IMDS access.',
  },

  // --- Environment Variable Exposure ---
  {
    id: 'generic-cloud-env-dump',
    name: 'Cloud Environment Variable Dump',
    description: 'Code that reads and exposes multiple cloud credential environment variables',
    provider: 'generic',
    category: 'env_exposure',
    pattern: /(?:process\.env|os\.environ|ENV)\[?\s*['"`]?(?:AWS_|AZURE_|GOOGLE_|GCP_|CLOUD_)[A-Z_]+['"`]?\]?/i,
    severity: 'medium',
    mitre: ['T1552', 'T1552.001'],
    remediation: 'Avoid directly accessing cloud credential environment variables in application code. Use SDK credential providers.',
  },
  {
    id: 'generic-env-file-cloud-creds',
    name: 'Cloud Credentials in .env File',
    description: 'Cloud provider credentials defined in a .env file',
    provider: 'generic',
    category: 'env_exposure',
    pattern: /^(?:AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|AWS_ACCESS_KEY_ID)\s*=/m,
    severity: 'critical',
    mitre: ['T1552', 'T1552.001'],
    remediation: 'Remove cloud credentials from .env files committed to source control. Use a secrets manager or .env.local (gitignored).',
  },

  // --- Private Keys ---
  {
    id: 'generic-rsa-private-key',
    name: 'RSA Private Key',
    description: 'RSA private key in PEM format',
    provider: 'generic',
    category: 'private_key',
    pattern: /-----BEGIN RSA PRIVATE KEY-----/,
    severity: 'critical',
    mitre: ['T1552.004'],
    remediation: 'Remove the RSA private key from the codebase. Store private keys in a secrets manager or hardware security module (HSM).',
  },
  {
    id: 'generic-ec-private-key',
    name: 'EC Private Key',
    description: 'Elliptic Curve private key in PEM format',
    provider: 'generic',
    category: 'private_key',
    pattern: /-----BEGIN EC PRIVATE KEY-----/,
    severity: 'critical',
    mitre: ['T1552.004'],
    remediation: 'Remove the EC private key. Use a key management service (KMS) for private key storage.',
  },
  {
    id: 'generic-encrypted-private-key',
    name: 'Encrypted Private Key',
    description: 'Encrypted private key in PEM format (may have a weak passphrase)',
    provider: 'generic',
    category: 'private_key',
    pattern: /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
    severity: 'high',
    mitre: ['T1552.004'],
    remediation: 'Remove encrypted private keys from source code. Even encrypted keys can be brute-forced if the passphrase is weak.',
  },
  {
    id: 'generic-pkcs8-private-key',
    name: 'PKCS8 Private Key',
    description: 'PKCS#8 format private key in PEM format',
    provider: 'generic',
    category: 'private_key',
    pattern: /-----BEGIN PRIVATE KEY-----/,
    severity: 'critical',
    mitre: ['T1552.004'],
    remediation: 'Remove the private key from the repository. Keys must be stored in a secrets manager.',
  },

  // --- Cloud CLI Config Files ---
  {
    id: 'generic-cloud-cli-config',
    name: 'Cloud CLI Configuration File Path',
    description: 'Reference to cloud CLI configuration directories',
    provider: 'generic',
    category: 'credential_file',
    pattern: /(?:~|\/home\/\w+|\$HOME|%USERPROFILE%)\/\.(?:aws|azure|config\/gcloud)\//i,
    severity: 'medium',
    mitre: ['T1552.001'],
    remediation: 'Avoid hardcoding cloud CLI config paths. Use SDK defaults for credential file resolution.',
  },

  // --- Kubernetes / Cloud Tokens ---
  {
    id: 'generic-k8s-service-token',
    name: 'Kubernetes Service Account Token Path',
    description: 'Path to Kubernetes service account token (used for cloud IAM integration)',
    provider: 'generic',
    category: 'auth_token',
    pattern: /\/var\/run\/secrets\/kubernetes\.io\/serviceaccount\/token/,
    severity: 'medium',
    mitre: ['T1552', 'T1078.004'],
    remediation: 'Avoid hardcoding K8s service account token paths. Use the official Kubernetes client library for token projection.',
  },
  {
    id: 'generic-bearer-token',
    name: 'Bearer Token in Cloud Context',
    description: 'Authorization Bearer token in a cloud service context',
    provider: 'generic',
    category: 'auth_token',
    pattern: /[Aa]uthorization\s*[:=]\s*['"`]?Bearer\s+[A-Za-z0-9._~+/=-]{20,}['"`]?/,
    severity: 'high',
    mitre: ['T1552', 'T1078'],
    remediation: 'Remove hardcoded Bearer tokens. Tokens should be dynamically resolved from credential providers at runtime.',
  },

  // --- Terraform / IaC ---
  {
    id: 'generic-terraform-backend-creds',
    name: 'Terraform Backend Credentials',
    description: 'Terraform state backend configuration with embedded credentials',
    provider: 'generic',
    category: 'connection_string',
    pattern: /backend\s+['"`](?:s3|azurerm|gcs)['"`]\s*\{[\s\S]{0,500}(?:access_key|secret_key|account_key|credentials)\s*=/i,
    severity: 'critical',
    mitre: ['T1552', 'T1552.001'],
    remediation: 'Remove credentials from Terraform backend configs. Use environment variables or assume-role for backend authentication.',
  },
  {
    id: 'generic-terraform-provider-creds',
    name: 'Terraform Provider Credentials',
    description: 'Terraform provider block with hardcoded credentials',
    provider: 'generic',
    category: 'connection_string',
    pattern: /provider\s+['"`](?:aws|google|azurerm)['"`]\s*\{[\s\S]{0,500}(?:access_key|secret_key|credentials|client_secret)\s*=/i,
    severity: 'critical',
    mitre: ['T1552', 'T1552.001'],
    remediation: 'Remove provider credentials from Terraform code. Use environment variables or cloud identity for provider authentication.',
  },
];

// ─── Exports ────────────────────────────────────────────────────

/**
 * Complete set of 60+ cloud credential detection patterns across
 * AWS, GCP, Azure, and generic cross-cloud patterns.
 *
 * Each scanner module filters patterns by provider for efficient scanning.
 */
export const ALL_PATTERNS: readonly CredentialPattern[] = [
  ...awsPatterns,
  ...gcpPatterns,
  ...azurePatterns,
  ...genericPatterns,
];

/**
 * Get patterns filtered by cloud provider.
 */
export function getPatternsByProvider(provider: CloudProvider): CredentialPattern[] {
  return ALL_PATTERNS.filter((p) => p.provider === provider);
}

/**
 * Get patterns filtered by credential category.
 */
export function getPatternsByCategory(category: CredentialCategory): CredentialPattern[] {
  return ALL_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns filtered by minimum severity.
 */
export function getPatternsBySeverity(minSeverity: Severity): CredentialPattern[] {
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
 * Pattern count by provider (for logging/reporting).
 */
export function getPatternCounts(): Record<CloudProvider, number> {
  const counts: Record<CloudProvider, number> = {
    aws: 0,
    gcp: 0,
    azure: 0,
    generic: 0,
  };

  for (const p of ALL_PATTERNS) {
    counts[p.provider]++;
  }

  return counts;
}
