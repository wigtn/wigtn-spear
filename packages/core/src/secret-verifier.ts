/**
 * Secret Verifier -- Live API verification for discovered credentials.
 *
 * Core engine for WIGTN-SPEAR aggressive mode. Given a raw secret string,
 * the verifier auto-detects which service it belongs to and makes a real
 * API call to determine whether the credential is valid and active.
 *
 * Supported services:
 *   - AWS (AKIA/ASIA keys via STS GetCallerIdentity with manual SigV4)
 *   - GitHub (ghp_, gho_, github_pat_ via /user endpoint)
 *   - Slack (xoxb-, xoxp- via auth.test)
 *   - GCP (ya29.* OAuth tokens via tokeninfo)
 *   - Google API Keys (AIza* -- tries Maps geocode then Firebase signUp)
 *   - Generic (unrecognized formats -- skipped, returns unverified)
 *
 * Security considerations:
 *   - Raw secrets are NEVER stored in results; only masked versions
 *   - All HTTP calls use a 10-second timeout via AbortController
 *   - Rate limiting prevents accidental API abuse
 *   - Results are cached by masked key to avoid redundant calls
 *
 * @module secret-verifier
 */

import { createHmac, createHash } from 'node:crypto';

import type { RateLimiter } from './rate-limiter.js';
import type { VerificationCache } from './verification-cache.js';

// ─── Types ───────────────────────────────────────────────────

export interface VerificationResult {
  /** Masked version of the secret (first 4 + *** + last 4 chars) */
  secret: string;
  /** Detected service: 'aws', 'gcp', 'github', 'slack', 'firebase', 'google-maps', 'generic' */
  service: string;
  /** Whether the secret was successfully verified against the API */
  verified: boolean;
  /** Whether the secret is currently active and usable */
  active: boolean;
  /** Permissions or scopes associated with the credential */
  permissions?: string[];
  /** Identity that the credential belongs to (username, ARN, email, etc.) */
  identity?: string;
  /** Expiration timestamp if known (ISO 8601 or descriptive) */
  expiresAt?: string;
  /** Additional metadata extracted from the verification response */
  metadata?: Record<string, unknown>;
  /** Error message if verification failed */
  error?: string;
}

// ─── Constants ───────────────────────────────────────────────

/** Request timeout in milliseconds. */
const REQUEST_TIMEOUT_MS = 10_000;

/** User-Agent header sent with all verification requests. */
const USER_AGENT = 'wigtn-spear/0.1.0 (security-scanner)';

// ─── Secret Format Detection Patterns ────────────────────────

/** Pattern -> service mapping for auto-detection. Order matters: first match wins. */
const SERVICE_PATTERNS: Array<{ pattern: RegExp; service: string }> = [
  { pattern: /^AKIA[0-9A-Z]{16}$/, service: 'aws' },
  { pattern: /^ASIA[0-9A-Z]{16}$/, service: 'aws' },
  { pattern: /^ghp_[a-zA-Z0-9]{36}$/, service: 'github' },
  { pattern: /^gho_[a-zA-Z0-9]{36}$/, service: 'github' },
  { pattern: /^github_pat_[a-zA-Z0-9_]+$/, service: 'github' },
  { pattern: /^xoxb-[0-9]+-[0-9]+-/, service: 'slack' },
  { pattern: /^xoxp-[0-9]+-[0-9]+-/, service: 'slack' },
  { pattern: /^ya29\.[a-zA-Z0-9_-]+$/, service: 'gcp' },
  { pattern: /^AIza[a-zA-Z0-9_-]{35}$/, service: 'google-api-key' },
];

// ─── Helper Functions ────────────────────────────────────────

/**
 * Mask a secret for safe storage and display.
 * Shows first 4 and last 4 characters, replaces middle with ***.
 * For secrets shorter than 12 chars, shows first 4 + ***.
 */
function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return secret.slice(0, 4) + '***';
  }
  return secret.slice(0, 4) + '***' + secret.slice(-4);
}

/**
 * Detect the service a secret belongs to based on its format.
 * Returns 'gcp-service-account' for JSON service account keys,
 * or looks up the pattern table for string tokens.
 */
function detectService(secret: string): string {
  // Check for GCP service account JSON (may start with whitespace)
  const trimmed = secret.trim();
  if (trimmed.startsWith('{') && trimmed.includes('"type"') && trimmed.includes('service_account')) {
    return 'gcp-service-account';
  }

  for (const { pattern, service } of SERVICE_PATTERNS) {
    if (pattern.test(secret)) {
      return service;
    }
  }

  return 'generic';
}

/**
 * Create a fetch request with a 10-second AbortController timeout.
 * Returns the Response or throws on timeout/network error.
 */
async function fetchWithTimeout(
  url: string,
  init?: RequestInit,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ─── AWS SigV4 Signing Utilities ─────────────────────────────

/**
 * SHA-256 hash of a string, returned as lowercase hex.
 */
function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

/**
 * HMAC-SHA256 of data with the given key (Buffer).
 */
function hmacSha256(key: Buffer, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

/**
 * Derive the SigV4 signing key.
 *
 *   kDate    = HMAC("AWS4" + secretKey, dateStamp)
 *   kRegion  = HMAC(kDate, region)
 *   kService = HMAC(kRegion, service)
 *   kSigning = HMAC(kService, "aws4_request")
 */
function deriveSigningKey(
  secretKey: string,
  dateStamp: string,
  region: string,
  service: string,
): Buffer {
  const kDate = hmacSha256(Buffer.from('AWS4' + secretKey, 'utf8'), dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, service);
  return hmacSha256(kService, 'aws4_request');
}

/**
 * Build and sign an AWS STS GetCallerIdentity request using SigV4.
 *
 * This implements the full AWS Signature Version 4 signing process
 * without any SDK dependency. We target sts.amazonaws.com with POST.
 *
 * @param accessKeyId     - The AWS access key ID (AKIA... or ASIA...)
 * @param secretAccessKey - The AWS secret access key
 * @returns Headers and body for the signed request, or null if signing fails
 */
function signStsGetCallerIdentity(
  accessKeyId: string,
  secretAccessKey: string,
): { url: string; headers: Record<string, string>; body: string } {
  const method = 'POST';
  const service = 'sts';
  const region = 'us-east-1';
  const host = 'sts.amazonaws.com';
  const endpoint = `https://${host}/`;

  const body = 'Action=GetCallerIdentity&Version=2011-06-15';

  // Timestamps
  const now = new Date();
  const amzDate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const dateStamp = amzDate.slice(0, 8);

  // Content hash
  const payloadHash = sha256Hex(body);

  // Canonical headers (must be sorted by lowercase header name)
  const canonicalHeaders =
    `content-type:application/x-www-form-urlencoded; charset=utf-8\n` +
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n`;

  const signedHeaders = 'content-type;host;x-amz-date';

  // Canonical request
  const canonicalRequest = [
    method,
    '/',           // canonical URI
    '',            // canonical query string (empty for POST)
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  // Credential scope
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;

  // String to sign
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  // Derive signing key and sign
  const signingKey = deriveSigningKey(secretAccessKey, dateStamp, region, service);
  const signature = createHmac('sha256', signingKey)
    .update(stringToSign, 'utf8')
    .digest('hex');

  // Authorization header
  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, ` +
    `Signature=${signature}`;

  return {
    url: endpoint,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
      'Host': host,
      'X-Amz-Date': amzDate,
      'Authorization': authorization,
      'User-Agent': USER_AGENT,
    },
    body,
  };
}

// ─── Service-Specific Verifiers ──────────────────────────────

/**
 * Verify an AWS access key pair using STS GetCallerIdentity.
 *
 * NOTE: AWS verification requires BOTH the access key ID and the secret
 * access key. The secret passed here is expected to be in the format:
 *   AKIAXXXXXXXXXXXXXXXX:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
 * (access key ID + colon + secret access key)
 *
 * If only the access key ID is provided (no colon separator), we cannot
 * sign the request and return an appropriate error.
 */
async function verifyAws(secret: string): Promise<Partial<VerificationResult>> {
  const colonIndex = secret.indexOf(':');
  if (colonIndex === -1) {
    return {
      verified: false,
      active: false,
      error: 'AWS verification requires both access key ID and secret key (format: AKIAXXXXX:secretkey)',
    };
  }

  const accessKeyId = secret.slice(0, colonIndex);
  const secretAccessKey = secret.slice(colonIndex + 1);

  if (!secretAccessKey) {
    return {
      verified: false,
      active: false,
      error: 'AWS secret access key is empty',
    };
  }

  const signed = signStsGetCallerIdentity(accessKeyId, secretAccessKey);

  const response = await fetchWithTimeout(signed.url, {
    method: 'POST',
    headers: signed.headers,
    body: signed.body,
  });

  const text = await response.text();

  if (response.status === 200) {
    // Parse XML response to extract Account, Arn, UserId
    const accountMatch = text.match(/<Account>([^<]+)<\/Account>/);
    const arnMatch = text.match(/<Arn>([^<]+)<\/Arn>/);
    const userIdMatch = text.match(/<UserId>([^<]+)<\/UserId>/);

    return {
      verified: true,
      active: true,
      identity: arnMatch?.[1],
      metadata: {
        accountId: accountMatch?.[1],
        userId: userIdMatch?.[1],
        arn: arnMatch?.[1],
      },
    };
  }

  // 403 means the key exists but is invalid or missing permissions
  // 401 means the key pair is wrong
  if (response.status === 403) {
    return {
      verified: true,
      active: false,
      error: `AWS STS returned 403: credentials recognized but access denied`,
    };
  }

  return {
    verified: false,
    active: false,
    error: `AWS STS returned ${response.status}: ${text.slice(0, 200)}`,
  };
}

/**
 * Verify a GitHub personal access token or OAuth token.
 *
 * Calls GET https://api.github.com/user with the token as Bearer auth.
 * Extracts the login, name, and OAuth scopes from response headers.
 */
async function verifyGitHub(secret: string): Promise<Partial<VerificationResult>> {
  const response = await fetchWithTimeout('https://api.github.com/user', {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${secret}`,
      'User-Agent': USER_AGENT,
      'Accept': 'application/vnd.github+json',
    },
  });

  if (response.status === 200) {
    const data = await response.json() as Record<string, unknown>;
    const scopesHeader = response.headers.get('x-oauth-scopes') ?? '';
    const scopes = scopesHeader
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    return {
      verified: true,
      active: true,
      identity: data.login as string | undefined,
      permissions: scopes.length > 0 ? scopes : undefined,
      metadata: {
        login: data.login,
        name: data.name,
        type: data.type,
        twoFactorEnabled: data.two_factor_authentication,
      },
    };
  }

  if (response.status === 401) {
    return {
      verified: true,
      active: false,
      error: 'GitHub token is invalid or expired',
    };
  }

  const text = await response.text();
  return {
    verified: false,
    active: false,
    error: `GitHub API returned ${response.status}: ${text.slice(0, 200)}`,
  };
}

/**
 * Verify a Slack bot or user token using auth.test.
 *
 * Calls POST https://slack.com/api/auth.test with the token as Bearer auth.
 * Slack always returns 200 with an { ok: boolean } envelope.
 */
async function verifySlack(secret: string): Promise<Partial<VerificationResult>> {
  const response = await fetchWithTimeout('https://slack.com/api/auth.test', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${secret}`,
      'User-Agent': USER_AGENT,
      'Content-Type': 'application/json; charset=utf-8',
    },
  });

  const data = await response.json() as Record<string, unknown>;

  if (data.ok === true) {
    return {
      verified: true,
      active: true,
      identity: (data.user as string | undefined) ?? (data.bot_id as string | undefined),
      metadata: {
        team: data.team,
        teamId: data.team_id,
        user: data.user,
        userId: data.user_id,
        botId: data.bot_id,
        url: data.url,
      },
    };
  }

  return {
    verified: true,
    active: false,
    error: `Slack auth.test failed: ${data.error as string ?? 'unknown error'}`,
  };
}

/**
 * Verify a GCP OAuth2 access token using the tokeninfo endpoint.
 *
 * Calls POST https://oauth2.googleapis.com/tokeninfo?access_token=TOKEN
 * Extracts email, scope, and expiry information.
 */
async function verifyGcpOAuth(secret: string): Promise<Partial<VerificationResult>> {
  const url = `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(secret)}`;

  const response = await fetchWithTimeout(url, {
    method: 'POST',
    headers: {
      'User-Agent': USER_AGENT,
    },
  });

  if (response.status === 200) {
    const data = await response.json() as Record<string, unknown>;
    const scopes = typeof data.scope === 'string'
      ? (data.scope as string).split(' ').filter(Boolean)
      : undefined;

    const expiresIn = data.expires_in as number | undefined;
    let expiresAt: string | undefined;
    if (expiresIn !== undefined) {
      expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
    }

    return {
      verified: true,
      active: true,
      identity: data.email as string | undefined,
      permissions: scopes,
      expiresAt,
      metadata: {
        email: data.email,
        emailVerified: data.email_verified,
        audience: data.aud,
        issuedTo: data.azp,
        expiresIn,
      },
    };
  }

  const text = await response.text();
  return {
    verified: true,
    active: false,
    error: `GCP tokeninfo returned ${response.status}: ${text.slice(0, 200)}`,
  };
}

/**
 * Verify a GCP service account JSON key.
 *
 * Service account keys require a JWT exchange flow. We parse the JSON
 * to extract identifying information but cannot fully verify without
 * performing a token exchange (which requires additional setup).
 * We mark the key as verified if it parses correctly as a valid
 * service account key structure.
 */
async function verifyGcpServiceAccount(secret: string): Promise<Partial<VerificationResult>> {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(secret) as Record<string, unknown>;
  } catch {
    return {
      verified: false,
      active: false,
      error: 'Failed to parse GCP service account JSON',
    };
  }

  if (parsed.type !== 'service_account') {
    return {
      verified: false,
      active: false,
      error: 'JSON is not a service_account type',
    };
  }

  // Validate required fields are present
  const requiredFields = ['project_id', 'private_key_id', 'private_key', 'client_email'];
  const missingFields = requiredFields.filter((f) => !parsed[f]);

  if (missingFields.length > 0) {
    return {
      verified: false,
      active: false,
      error: `Service account JSON missing required fields: ${missingFields.join(', ')}`,
    };
  }

  // The key structure is valid -- we can extract identity info
  // Full verification would require JWT signing + token exchange
  return {
    verified: true,
    active: true,
    identity: parsed.client_email as string,
    metadata: {
      projectId: parsed.project_id,
      privateKeyId: parsed.private_key_id,
      clientEmail: parsed.client_email,
      clientId: parsed.client_id,
      authUri: parsed.auth_uri,
      tokenUri: parsed.token_uri,
    },
  };
}

/**
 * Verify a Google Maps/Places API key by calling the Geocoding API.
 *
 * If the API returns status OK or ZERO_RESULTS, the key is valid.
 * REQUEST_DENIED means the key is invalid or the Geocoding API is not enabled.
 */
async function verifyGoogleMaps(secret: string): Promise<Partial<VerificationResult> & { fallthrough?: boolean }> {
  const url = `https://maps.googleapis.com/maps/api/geocode/json?address=test&key=${encodeURIComponent(secret)}`;

  const response = await fetchWithTimeout(url, {
    method: 'GET',
    headers: {
      'User-Agent': USER_AGENT,
    },
  });

  if (response.status === 200) {
    const data = await response.json() as Record<string, unknown>;
    const status = data.status as string | undefined;

    if (status === 'OK' || status === 'ZERO_RESULTS') {
      return {
        verified: true,
        active: true,
        permissions: ['maps-geocoding'],
        metadata: {
          apiStatus: status,
          service: 'google-maps',
        },
      };
    }

    // REQUEST_DENIED could mean the key is valid but Maps API is not
    // enabled -- fall through to Firebase verification
    if (status === 'REQUEST_DENIED') {
      return {
        verified: false,
        active: false,
        fallthrough: true,
        error: `Google Maps API returned REQUEST_DENIED`,
      };
    }

    return {
      verified: true,
      active: true,
      metadata: {
        apiStatus: status,
        service: 'google-maps',
      },
    };
  }

  return {
    verified: false,
    active: false,
    fallthrough: true,
    error: `Google Maps API returned ${response.status}`,
  };
}

/**
 * Verify a Firebase API key by attempting anonymous user creation.
 *
 * Calls POST identitytoolkit.googleapis.com/v1/accounts:signUp?key=KEY
 * If it returns 200 with a valid response, the key is valid and can
 * create anonymous users (a significant security finding).
 */
async function verifyFirebase(secret: string): Promise<Partial<VerificationResult>> {
  const url = `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${encodeURIComponent(secret)}`;

  const response = await fetchWithTimeout(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
    },
    body: JSON.stringify({ returnSecureToken: true }),
  });

  if (response.status === 200) {
    const data = await response.json() as Record<string, unknown>;

    return {
      verified: true,
      active: true,
      permissions: ['firebase-anonymous-auth'],
      metadata: {
        kind: data.kind,
        hasIdToken: Boolean(data.idToken),
        hasRefreshToken: Boolean(data.refreshToken),
        service: 'firebase',
      },
    };
  }

  const text = await response.text();
  return {
    verified: true,
    active: false,
    error: `Firebase signUp returned ${response.status}: ${text.slice(0, 200)}`,
  };
}

// ─── SecretVerifier Class ────────────────────────────────────

export class SecretVerifier {
  private readonly rateLimiter: RateLimiter;
  private readonly cache: VerificationCache;

  constructor(rateLimiter: RateLimiter, cache: VerificationCache) {
    this.rateLimiter = rateLimiter;
    this.cache = cache;
  }

  /**
   * Auto-detect the service a secret belongs to and verify it.
   *
   * The secret format is inspected to determine which verifier to invoke.
   * Results are cached by the masked secret to avoid redundant API calls.
   * Rate limiting is applied per-service before each verification request.
   *
   * @param secret - The raw secret to verify
   * @returns Verification result with masked secret, never throws
   */
  async verify(secret: string): Promise<VerificationResult> {
    const masked = maskSecret(secret);
    let service = detectService(secret);

    // Normalize the service name for the result
    // 'google-api-key' is an internal detection label; the actual service
    // is determined by which verifier succeeds (maps vs firebase)
    const resultService = service === 'google-api-key'
      ? 'google-maps'
      : service === 'gcp-service-account'
        ? 'gcp'
        : service;

    // Check cache first
    const cached = this.cache.get(masked);
    if (cached) {
      return {
        secret: masked,
        service: cached.service ?? resultService,
        verified: cached.verified,
        active: cached.active,
        permissions: cached.permissions,
      };
    }

    // Generic secrets cannot be verified
    if (service === 'generic') {
      const result: VerificationResult = {
        secret: masked,
        service: 'generic',
        verified: false,
        active: false,
        error: 'Cannot verify generic secrets without knowing the target service',
      };
      this.cacheResult(masked, result);
      return result;
    }

    // Perform verification with rate limiting
    try {
      const partial = await this.verifyWithRateLimit(secret, service);
      const finalService = partial.metadata?.service as string | undefined;

      const result: VerificationResult = {
        secret: masked,
        service: finalService ?? resultService,
        verified: partial.verified ?? false,
        active: partial.active ?? false,
        permissions: partial.permissions,
        identity: partial.identity,
        expiresAt: partial.expiresAt,
        metadata: partial.metadata,
        error: partial.error,
      };

      this.cacheResult(masked, result);
      return result;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);

      // Map AbortError to a more descriptive message
      const message = errorMessage.includes('abort')
        ? `Verification timed out after ${REQUEST_TIMEOUT_MS}ms`
        : `Verification failed: ${errorMessage}`;

      const result: VerificationResult = {
        secret: masked,
        service: resultService,
        verified: false,
        active: false,
        error: message,
      };

      this.cacheResult(masked, result);
      return result;
    }
  }

  /**
   * Verify a batch of secrets with rate limiting.
   *
   * Secrets are verified concurrently (bounded by the rate limiter).
   * Each secret is independently verified and errors are isolated.
   *
   * @param secrets - Array of raw secrets to verify
   * @returns Array of verification results in the same order
   */
  async verifyBatch(secrets: string[]): Promise<VerificationResult[]> {
    return Promise.all(secrets.map((secret) => this.verify(secret)));
  }

  // ─── Private Helpers ─────────────────────────────────────────

  /**
   * Acquire rate limit, call the appropriate verifier, and release.
   *
   * For Google API keys (AIza*), this implements a two-step fallback:
   * first try Google Maps, then Firebase if Maps returns REQUEST_DENIED.
   */
  private async verifyWithRateLimit(
    secret: string,
    service: string,
  ): Promise<Partial<VerificationResult>> {
    // Google API keys get special handling: try Maps first, then Firebase
    if (service === 'google-api-key') {
      return this.verifyGoogleApiKey(secret);
    }

    const rateLimitService = this.getRateLimitService(service);

    await this.rateLimiter.acquire(rateLimitService);
    try {
      return await this.callVerifier(secret, service);
    } finally {
      this.rateLimiter.release(rateLimitService);
    }
  }

  /**
   * Two-phase verification for Google API keys.
   * Tries Maps geocoding first; on fallthrough, tries Firebase signUp.
   */
  private async verifyGoogleApiKey(secret: string): Promise<Partial<VerificationResult>> {
    // Phase 1: Try Google Maps
    await this.rateLimiter.acquire('google-maps');
    let mapsResult: Partial<VerificationResult> & { fallthrough?: boolean };
    try {
      mapsResult = await verifyGoogleMaps(secret);
    } finally {
      this.rateLimiter.release('google-maps');
    }

    // If Maps verification succeeded or failed definitively, return
    if (!mapsResult.fallthrough) {
      const { fallthrough: _, ...rest } = mapsResult;
      return rest;
    }

    // Phase 2: Fall through to Firebase
    await this.rateLimiter.acquire('firebase');
    try {
      const firebaseResult = await verifyFirebase(secret);
      if (firebaseResult.verified && firebaseResult.active) {
        return {
          ...firebaseResult,
          metadata: {
            ...firebaseResult.metadata,
            service: 'firebase',
          },
        };
      }

      // Neither Maps nor Firebase worked -- return the maps error
      // combined with firebase info
      return {
        verified: false,
        active: false,
        error: 'Google API key not valid for Maps or Firebase',
        metadata: {
          mapsError: mapsResult.error,
          firebaseError: firebaseResult.error,
        },
      };
    } finally {
      this.rateLimiter.release('firebase');
    }
  }

  /**
   * Dispatch to the correct service verifier.
   */
  private async callVerifier(
    secret: string,
    service: string,
  ): Promise<Partial<VerificationResult>> {
    switch (service) {
      case 'aws':
        return verifyAws(secret);
      case 'github':
        return verifyGitHub(secret);
      case 'slack':
        return verifySlack(secret);
      case 'gcp':
        return verifyGcpOAuth(secret);
      case 'gcp-service-account':
        return verifyGcpServiceAccount(secret);
      default:
        return {
          verified: false,
          active: false,
          error: `No verifier available for service: ${service}`,
        };
    }
  }

  /**
   * Map internal service names to rate limiter service identifiers.
   */
  private getRateLimitService(service: string): string {
    switch (service) {
      case 'gcp-service-account':
        return 'gcp';
      default:
        return service;
    }
  }

  /**
   * Store a verification result in the cache.
   */
  private cacheResult(maskedKey: string, result: VerificationResult): void {
    this.cache.set(maskedKey, {
      verified: result.verified,
      active: result.active,
      service: result.service,
      permissions: result.permissions,
      cachedAt: Date.now(),
    });
  }
}
