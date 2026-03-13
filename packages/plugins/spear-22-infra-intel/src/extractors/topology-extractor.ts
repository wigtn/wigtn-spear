/**
 * SPEAR-22: Service Topology & Authentication Flow Extractor
 *
 * Maps the service architecture and authentication patterns:
 *
 * Service Topology:
 *   - Dependencies between services (who calls whom)
 *   - External API dependencies (Google APIs, Firebase, Stripe, etc.)
 *   - Database connections (connection string patterns)
 *   - Message queue / pub-sub patterns (Redis, RabbitMQ, Kafka, etc.)
 *
 * Authentication Flow:
 *   - OAuth/OIDC providers
 *   - Firebase Auth usage
 *   - JWT token patterns
 *   - Session management
 *
 * All findings are severity 'info' -- this is an intelligence module.
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
  category: string,
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
      category,
      type,
      value,
      ...extra,
    },
  };
}

// ─── External API Dependencies ──────────────────────────────────

interface ExternalApiSignature {
  name: string;
  type: string;
  patterns: RegExp[];
}

const EXTERNAL_API_SIGNATURES: ExternalApiSignature[] = [
  {
    name: 'Google Cloud APIs',
    type: 'google_cloud_api',
    patterns: [
      /googleapis\.com/g,
      /google-cloud\/([a-z-]+)/g,
      /@google-cloud\/([a-z-]+)/g,
    ],
  },
  {
    name: 'Firebase',
    type: 'firebase',
    patterns: [
      /firebase(?:app|io)?\.(?:google)?\.com/g,
      /firebase\/([a-z-]+)/g,
      /firebase-admin/g,
      /initializeApp\s*\(/g,
      /getFirestore|getAuth|getStorage|getDatabase/g,
    ],
  },
  {
    name: 'Stripe',
    type: 'stripe',
    patterns: [
      /api\.stripe\.com/g,
      /stripe\(/g,
      /new\s+Stripe\(/g,
      /['"]stripe['"]\s*\)/g,
    ],
  },
  {
    name: 'Twilio',
    type: 'twilio',
    patterns: [
      /api\.twilio\.com/g,
      /twilio\(/g,
      /new\s+Twilio\(/g,
    ],
  },
  {
    name: 'SendGrid',
    type: 'sendgrid',
    patterns: [
      /api\.sendgrid\.com/g,
      /@sendgrid\/mail/g,
      /sendgrid/gi,
    ],
  },
  {
    name: 'AWS SDK',
    type: 'aws_sdk',
    patterns: [
      /@aws-sdk\/client-([a-z0-9-]+)/g,
      /aws-sdk/g,
      /AWS\.([A-Z][a-zA-Z]+)\(/g,
    ],
  },
  {
    name: 'Supabase',
    type: 'supabase',
    patterns: [
      /supabase\.co/g,
      /@supabase\/supabase-js/g,
      /createClient\s*\([^)]*supabase/gi,
    ],
  },
  {
    name: 'PlanetScale',
    type: 'planetscale',
    patterns: [
      /planetscale/gi,
      /@planetscale\/database/g,
    ],
  },
  {
    name: 'Vercel',
    type: 'vercel',
    patterns: [
      /api\.vercel\.com/g,
      /@vercel\/([a-z-]+)/g,
      /VERCEL_URL/g,
    ],
  },
  {
    name: 'Cloudflare',
    type: 'cloudflare',
    patterns: [
      /api\.cloudflare\.com/g,
      /cloudflare\/workers/g,
      /wrangler/g,
    ],
  },
  {
    name: 'GitHub API',
    type: 'github_api',
    patterns: [
      /api\.github\.com/g,
      /@octokit/g,
      /Octokit\(/g,
    ],
  },
  {
    name: 'Slack API',
    type: 'slack_api',
    patterns: [
      /slack\.com\/api/g,
      /@slack\/web-api/g,
      /@slack\/bolt/g,
    ],
  },
  {
    name: 'OpenAI',
    type: 'openai',
    patterns: [
      /api\.openai\.com/g,
      /new\s+OpenAI\(/g,
      /openai/gi,
    ],
  },
  {
    name: 'Anthropic',
    type: 'anthropic',
    patterns: [
      /api\.anthropic\.com/g,
      /new\s+Anthropic\(/g,
      /@anthropic-ai\/sdk/g,
    ],
  },
];

function* extractExternalApis(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const api of EXTERNAL_API_SIGNATURES) {
    for (const pattern of api.patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(content);
      if (match) {
        const key = `ext-api:${api.type}`;
        if (seen.has(key)) continue;
        seen.add(key);

        // Extract specific sub-service if captured
        const subService = match[1] ?? '';

        yield makeFinding(
          'external-api-dependency',
          `External API Dependency: ${api.name}${subService ? ` (${subService})` : ''}`,
          filePath,
          findLineNumber(content, match.index),
          pluginId,
          'service_topology',
          'external_api_dependency',
          api.name,
          { apiType: api.type, subService },
        );
        break; // One finding per API per file
      }
    }
  }
}

// ─── Database Connection Patterns ───────────────────────────────

interface DatabaseSignature {
  name: string;
  type: string;
  patterns: RegExp[];
}

const DATABASE_SIGNATURES: DatabaseSignature[] = [
  {
    name: 'PostgreSQL',
    type: 'postgresql',
    patterns: [
      /postgres(?:ql)?:\/\//g,
      /pg\.(?:Pool|Client)\(/g,
      /new\s+Pool\(\s*\{[^}]*(?:host|connectionString)/g,
      /DATABASE_URL.*postgres/gi,
      /knex\(\s*\{[^}]*client:\s*["']pg["']/g,
      /prisma.*postgresql/gi,
    ],
  },
  {
    name: 'MySQL',
    type: 'mysql',
    patterns: [
      /mysql:\/\//g,
      /mysql2?\./g,
      /createConnection\(\s*\{[^}]*host/g,
      /DATABASE_URL.*mysql/gi,
      /prisma.*mysql/gi,
    ],
  },
  {
    name: 'MongoDB',
    type: 'mongodb',
    patterns: [
      /mongodb(?:\+srv)?:\/\//g,
      /mongoose\.connect/g,
      /MongoClient\./g,
      /MONGO(?:DB)?_(?:URI|URL|CONNECTION)/gi,
    ],
  },
  {
    name: 'Redis',
    type: 'redis',
    patterns: [
      /redis:\/\//g,
      /rediss:\/\//g,
      /createClient\(\s*\{[^}]*(?:url|host).*redis/gi,
      /new\s+Redis\(/g,
      /ioredis/g,
      /REDIS_(?:URL|HOST|URI)/gi,
    ],
  },
  {
    name: 'SQLite',
    type: 'sqlite',
    patterns: [
      /better-sqlite3/g,
      /sqlite3/g,
      /\.sqlite/g,
      /prisma.*sqlite/gi,
    ],
  },
  {
    name: 'DynamoDB',
    type: 'dynamodb',
    patterns: [
      /DynamoDB/g,
      /@aws-sdk\/client-dynamodb/g,
      /dynamodb\.amazonaws\.com/g,
    ],
  },
  {
    name: 'Firestore',
    type: 'firestore',
    patterns: [
      /getFirestore/g,
      /firestore\(\)/g,
      /collection\(\s*["'][^"']+["']\s*\)/g,
    ],
  },
  {
    name: 'Elasticsearch',
    type: 'elasticsearch',
    patterns: [
      /@elastic\/elasticsearch/g,
      /elasticsearch\.Client/g,
      /ELASTICSEARCH_(?:URL|HOST|NODE)/gi,
    ],
  },
];

function* extractDatabaseConnections(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const db of DATABASE_SIGNATURES) {
    for (const pattern of db.patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(content);
      if (match) {
        const key = `db:${db.type}`;
        if (seen.has(key)) continue;
        seen.add(key);
        yield makeFinding(
          'database-connection',
          `Database Connection: ${db.name}`,
          filePath,
          findLineNumber(content, match.index),
          pluginId,
          'service_topology',
          'database_connection',
          db.name,
          { databaseType: db.type },
        );
        break; // One finding per DB type per file
      }
    }
  }
}

// ─── Message Queue / Pub-Sub Patterns ───────────────────────────

interface MessageQueueSignature {
  name: string;
  type: string;
  patterns: RegExp[];
}

const MESSAGE_QUEUE_SIGNATURES: MessageQueueSignature[] = [
  {
    name: 'RabbitMQ',
    type: 'rabbitmq',
    patterns: [
      /amqp(?:s)?:\/\//g,
      /amqplib/g,
      /RABBITMQ_(?:URL|HOST)/gi,
    ],
  },
  {
    name: 'Apache Kafka',
    type: 'kafka',
    patterns: [
      /kafkajs/g,
      /new\s+Kafka\(/g,
      /KAFKA_(?:BROKER|BOOTSTRAP)/gi,
    ],
  },
  {
    name: 'Google Cloud Pub/Sub',
    type: 'gcp_pubsub',
    patterns: [
      /@google-cloud\/pubsub/g,
      /PubSub\(\)/g,
      /pubsub\.topic/g,
      /pubsub\.subscription/g,
    ],
  },
  {
    name: 'AWS SQS',
    type: 'aws_sqs',
    patterns: [
      /@aws-sdk\/client-sqs/g,
      /SQS\(\)/g,
      /sqs\.amazonaws\.com/g,
    ],
  },
  {
    name: 'AWS SNS',
    type: 'aws_sns',
    patterns: [
      /@aws-sdk\/client-sns/g,
      /SNS\(\)/g,
      /sns\.amazonaws\.com/g,
    ],
  },
  {
    name: 'Redis Pub/Sub',
    type: 'redis_pubsub',
    patterns: [
      /\.subscribe\(/g,
      /\.publish\(/g,
      /BullMQ/g,
      /new\s+Queue\(/g,
    ],
  },
  {
    name: 'NATS',
    type: 'nats',
    patterns: [
      /nats:\/\//g,
      /nats\.connect/g,
      /NATS_(?:URL|SERVER)/gi,
    ],
  },
];

function* extractMessageQueues(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const mq of MESSAGE_QUEUE_SIGNATURES) {
    for (const pattern of mq.patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(content);
      if (match) {
        const key = `mq:${mq.type}`;
        if (seen.has(key)) continue;
        seen.add(key);
        yield makeFinding(
          'message-queue',
          `Message Queue/Pub-Sub: ${mq.name}`,
          filePath,
          findLineNumber(content, match.index),
          pluginId,
          'service_topology',
          'message_queue',
          mq.name,
          { queueType: mq.type },
        );
        break; // One finding per MQ type per file
      }
    }
  }
}

// ─── Inter-Service Communication ────────────────────────────────

/** Detect service-to-service calls (gRPC, REST internal, tRPC, etc.) */
const SERVICE_COMM_PATTERNS: { name: string; type: string; pattern: RegExp }[] = [
  {
    name: 'gRPC Client',
    type: 'grpc',
    pattern: /@grpc\/grpc-js|grpc\.load|new\s+\w+Client\(\s*["'][^"']+:\d+["']/g,
  },
  {
    name: 'tRPC',
    type: 'trpc',
    pattern: /@trpc\/(?:client|server|next|react)/g,
  },
  {
    name: 'Service Mesh (Istio/Envoy)',
    type: 'service_mesh',
    pattern: /istio|envoy|sidecar.*proxy/gi,
  },
  {
    name: 'Internal Service URL',
    type: 'internal_service_url',
    pattern: /(?:INTERNAL_|SERVICE_)(?:URL|HOST|ENDPOINT)\s*[:=]\s*["']([^"']+)["']/g,
  },
];

function* extractServiceCommunication(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const svc of SERVICE_COMM_PATTERNS) {
    svc.pattern.lastIndex = 0;
    const match = svc.pattern.exec(content);
    if (match) {
      const key = `svc-comm:${svc.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const value = match[1] ?? svc.name;
      yield makeFinding(
        'service-communication',
        `Service Communication: ${svc.name}${match[1] ? ` (${match[1]})` : ''}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'service_topology',
        'service_communication',
        value,
        { communicationType: svc.type },
      );
    }
  }
}

// ─── Authentication Flow Detection ──────────────────────────────

interface AuthSignature {
  name: string;
  type: string;
  patterns: RegExp[];
}

const AUTH_SIGNATURES: AuthSignature[] = [
  {
    name: 'OAuth 2.0',
    type: 'oauth2',
    patterns: [
      /oauth2?\s*\(/gi,
      /authorization_code|client_credentials|implicit|refresh_token/g,
      /OAuth2Client/g,
      /\/oauth\/authorize/g,
      /\/oauth\/token/g,
      /grant_type/g,
    ],
  },
  {
    name: 'OpenID Connect (OIDC)',
    type: 'oidc',
    patterns: [
      /openid-connect|openid_connect|oidc/gi,
      /\.well-known\/openid-configuration/g,
      /id_token/g,
      /oidcProvider|OIDCStrategy/g,
    ],
  },
  {
    name: 'Firebase Auth',
    type: 'firebase_auth',
    patterns: [
      /firebase\/auth/g,
      /getAuth\(\)/g,
      /signInWith(?:Popup|Redirect|EmailAndPassword|Credential|CustomToken)/g,
      /onAuthStateChanged/g,
      /createUserWithEmailAndPassword/g,
      /firebase-admin.*auth/g,
    ],
  },
  {
    name: 'JWT',
    type: 'jwt',
    patterns: [
      /jsonwebtoken/g,
      /jwt\.sign\(/g,
      /jwt\.verify\(/g,
      /jose/g,
      /JWTPayload|JwtPayload/g,
      /Bearer\s+/g,
      /JWT_SECRET|JWT_KEY/gi,
    ],
  },
  {
    name: 'NextAuth.js / Auth.js',
    type: 'nextauth',
    patterns: [
      /next-auth/g,
      /NextAuth\(/g,
      /auth\.js/g,
      /authOptions/g,
      /getServerSession/g,
      /SessionProvider/g,
    ],
  },
  {
    name: 'Passport.js',
    type: 'passport',
    patterns: [
      /passport\./g,
      /passport-(?:local|jwt|google|github|facebook)/g,
      /passport\.authenticate/g,
      /passport\.use\(/g,
    ],
  },
  {
    name: 'Clerk',
    type: 'clerk',
    patterns: [
      /@clerk\/(?:nextjs|backend|clerk-js)/g,
      /ClerkProvider/g,
      /useUser\(\)/g,
      /CLERK_SECRET_KEY/g,
    ],
  },
  {
    name: 'Auth0',
    type: 'auth0',
    patterns: [
      /auth0/gi,
      /@auth0\/(?:nextjs-auth0|auth0-spa-js|auth0-react)/g,
      /AUTH0_(?:DOMAIN|CLIENT_ID|SECRET)/gi,
    ],
  },
  {
    name: 'Supabase Auth',
    type: 'supabase_auth',
    patterns: [
      /supabase.*auth\./g,
      /supabase\.auth\.signIn/g,
      /supabase\.auth\.signUp/g,
      /createServerComponentClient/g,
    ],
  },
  {
    name: 'Session Management',
    type: 'session',
    patterns: [
      /express-session/g,
      /cookie-session/g,
      /iron-session/g,
      /req\.session/g,
      /session\.(save|destroy|regenerate)/g,
      /SESSION_SECRET/gi,
    ],
  },
  {
    name: 'API Key Auth',
    type: 'api_key_auth',
    patterns: [
      /x-api-key/gi,
      /apiKey\s*[:=]/g,
      /API_KEY_HEADER/g,
      /req\.headers\[["'](?:x-api-key|authorization)["']\]/g,
    ],
  },
  {
    name: 'SAML',
    type: 'saml',
    patterns: [
      /saml/gi,
      /passport-saml/g,
      /SAMLResponse/g,
      /saml2/g,
    ],
  },
];

function* extractAuthPatterns(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const auth of AUTH_SIGNATURES) {
    for (const pattern of auth.patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(content);
      if (match) {
        const key = `auth:${auth.type}`;
        if (seen.has(key)) continue;
        seen.add(key);
        yield makeFinding(
          'auth-pattern',
          `Authentication Pattern: ${auth.name}`,
          filePath,
          findLineNumber(content, match.index),
          pluginId,
          'authentication',
          'auth_pattern',
          auth.name,
          { authType: auth.type },
        );
        break; // One finding per auth type per file
      }
    }
  }
}

// ─── OAuth Provider Detection ───────────────────────────────────

/** Specific OAuth provider references */
const OAUTH_PROVIDERS: { name: string; type: string; pattern: RegExp }[] = [
  { name: 'Google OAuth', type: 'google_oauth', pattern: /GoogleProvider|google-auth|accounts\.google\.com|googleapis.*oauth/gi },
  { name: 'GitHub OAuth', type: 'github_oauth', pattern: /GitHubProvider|github\.com\/login\/oauth/gi },
  { name: 'Facebook OAuth', type: 'facebook_oauth', pattern: /FacebookProvider|facebook\.com\/.*oauth|graph\.facebook\.com/gi },
  { name: 'Microsoft OAuth', type: 'microsoft_oauth', pattern: /AzureADProvider|login\.microsoftonline\.com|MicrosoftProvider/gi },
  { name: 'Apple Sign-In', type: 'apple_signin', pattern: /AppleProvider|appleid\.apple\.com/gi },
  { name: 'Twitter OAuth', type: 'twitter_oauth', pattern: /TwitterProvider|api\.twitter\.com.*oauth/gi },
  { name: 'Discord OAuth', type: 'discord_oauth', pattern: /DiscordProvider|discord\.com\/api\/oauth2/gi },
];

function* extractOAuthProviders(
  content: string,
  filePath: string,
  pluginId: string,
): Generator<Finding> {
  const seen = new Set<string>();

  for (const provider of OAUTH_PROVIDERS) {
    provider.pattern.lastIndex = 0;
    const match = provider.pattern.exec(content);
    if (match) {
      const key = `oauth-provider:${provider.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      yield makeFinding(
        'oauth-provider',
        `OAuth Provider: ${provider.name}`,
        filePath,
        findLineNumber(content, match.index),
        pluginId,
        'authentication',
        'oauth_provider',
        provider.name,
        { providerType: provider.type },
      );
    }
  }
}

// ─── Main Export ─────────────────────────────────────────────────

/**
 * Extract service topology and authentication flow intelligence from a file.
 *
 * Yields Finding objects with severity 'info' for each discovered topology
 * element or authentication pattern.
 */
export function* extractTopology(
  content: string,
  relativePath: string,
  pluginId: string,
): Generator<Finding> {
  // External API dependencies
  yield* extractExternalApis(content, relativePath, pluginId);

  // Database connections
  yield* extractDatabaseConnections(content, relativePath, pluginId);

  // Message queues and pub-sub
  yield* extractMessageQueues(content, relativePath, pluginId);

  // Inter-service communication
  yield* extractServiceCommunication(content, relativePath, pluginId);

  // Authentication patterns
  yield* extractAuthPatterns(content, relativePath, pluginId);

  // OAuth providers
  yield* extractOAuthProviders(content, relativePath, pluginId);
}
