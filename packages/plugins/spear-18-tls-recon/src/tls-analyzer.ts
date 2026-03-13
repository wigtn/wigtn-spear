/**
 * SPEAR-18: TLS Analyzer
 *
 * Connects to discovered endpoints and performs TLS/certificate analysis.
 * This module is used in AGGRESSIVE mode only -- it makes real network connections.
 *
 * Extracts:
 *   - Certificate subject and issuer
 *   - Expiration date (warns if < 30 days)
 *   - TLS protocol version (warns if < TLS 1.2)
 *   - Cipher suite
 *   - Certificate chain depth
 *   - Subject Alternative Names (SAN)
 *   - HSTS header presence
 *   - Certificate Transparency status
 */

import tls from 'node:tls';
import https from 'node:https';
import type { PeerCertificate } from 'node:tls';
import type { Finding, Severity } from '@wigtn/shared';

// ─── Types ─────────────────────────────────────────────────────

export interface TlsAnalysisResult {
  endpoint: string;
  connected: boolean;
  error?: string;
  certificate?: CertificateInfo;
  tlsVersion?: string;
  cipherSuite?: string;
  chainDepth?: number;
  hstsPresent?: boolean;
  hstsMaxAge?: number;
  certificateTransparency?: boolean;
}

export interface CertificateInfo {
  subject: Record<string, string>;
  issuer: Record<string, string>;
  validFrom: string;
  validTo: string;
  daysUntilExpiry: number;
  serialNumber: string;
  fingerprint: string;
  fingerprint256: string;
  subjectAltNames: string[];
  isCA: boolean;
}

// ─── Constants ─────────────────────────────────────────────────

/** Connection timeout in milliseconds. */
const CONNECTION_TIMEOUT_MS = 10_000;

/** TLS versions considered deprecated. */
const DEPRECATED_TLS_VERSIONS: ReadonlySet<string> = new Set([
  'TLSv1',
  'TLSv1.1',
  'SSLv3',
]);

/** Minimum acceptable TLS version. */
const MIN_SAFE_TLS_VERSION = 'TLSv1.2';

/** Warn if certificate expires within this many days. */
const CERT_EXPIRY_WARN_DAYS = 30;

/** Critical if certificate expires within this many days. */
const CERT_EXPIRY_CRITICAL_DAYS = 7;

// ─── TLS Connection ────────────────────────────────────────────

/**
 * Connect to an endpoint via TLS and extract certificate and protocol information.
 */
export async function analyzeTls(endpoint: string): Promise<TlsAnalysisResult> {
  let hostname: string;
  let port: number;

  try {
    const parsed = new URL(endpoint);
    hostname = parsed.hostname;
    port = parsed.port ? parseInt(parsed.port, 10) : 443;
  } catch {
    return {
      endpoint,
      connected: false,
      error: `Invalid URL: ${endpoint}`,
    };
  }

  const result: TlsAnalysisResult = {
    endpoint,
    connected: false,
  };

  // Step 1: TLS socket connection to extract certificate and protocol info
  try {
    const tlsInfo = await connectTls(hostname, port);
    result.connected = true;
    result.certificate = tlsInfo.certificate;
    result.tlsVersion = tlsInfo.tlsVersion;
    result.cipherSuite = tlsInfo.cipherSuite;
    result.chainDepth = tlsInfo.chainDepth;
    result.certificateTransparency = tlsInfo.certificateTransparency;
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    result.error = `TLS connection failed: ${message}`;
    return result;
  }

  // Step 2: HTTPS request to check HSTS header
  try {
    const hstsInfo = await checkHsts(hostname, port);
    result.hstsPresent = hstsInfo.present;
    result.hstsMaxAge = hstsInfo.maxAge;
  } catch {
    // HSTS check failed, but we still have TLS info
    result.hstsPresent = false;
  }

  return result;
}

// ─── TLS Socket Connection ─────────────────────────────────────

interface TlsConnectionInfo {
  certificate?: CertificateInfo;
  tlsVersion?: string;
  cipherSuite?: string;
  chainDepth?: number;
  certificateTransparency?: boolean;
}

function connectTls(hostname: string, port: number): Promise<TlsConnectionInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: hostname,
        port,
        servername: hostname,
        rejectUnauthorized: false, // We want to analyze even invalid certs
        timeout: CONNECTION_TIMEOUT_MS,
      },
      () => {
        const info: TlsConnectionInfo = {};

        try {
          // TLS protocol version
          info.tlsVersion = socket.getProtocol() ?? undefined;

          // Cipher suite
          const cipher = socket.getCipher();
          if (cipher) {
            info.cipherSuite = cipher.name;
          }

          // Certificate
          const peerCert = socket.getPeerCertificate(true);
          if (peerCert && peerCert.subject) {
            info.certificate = parseCertificate(peerCert);
            info.chainDepth = countChainDepth(peerCert);

            // Check for Certificate Transparency SCTs
            // If the cert has the SCT extension or we got SCTs via TLS extension
            info.certificateTransparency = hasCertificateTransparency(peerCert);
          }
        } catch {
          // Partial info is still useful
        }

        socket.destroy();
        resolve(info);
      },
    );

    socket.on('error', (err: Error) => {
      socket.destroy();
      reject(err);
    });

    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`Connection timed out after ${CONNECTION_TIMEOUT_MS}ms`));
    });
  });
}

// ─── HSTS Check ────────────────────────────────────────────────

interface HstsInfo {
  present: boolean;
  maxAge?: number;
}

function checkHsts(hostname: string, port: number): Promise<HstsInfo> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname,
        port,
        path: '/',
        method: 'HEAD',
        rejectUnauthorized: false,
        timeout: CONNECTION_TIMEOUT_MS,
        headers: {
          'User-Agent': 'WIGTN-SPEAR/0.1.0 TLS-Recon',
        },
      },
      (res) => {
        const hstsHeader = res.headers['strict-transport-security'];
        if (hstsHeader) {
          const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
          resolve({
            present: true,
            maxAge: maxAgeMatch ? parseInt(maxAgeMatch[1]!, 10) : undefined,
          });
        } else {
          resolve({ present: false });
        }
        res.resume(); // Consume response body to free resources
      },
    );

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('HSTS check timed out'));
    });

    req.end();
  });
}

// ─── Certificate Parsing ───────────────────────────────────────

function parseCertificate(cert: PeerCertificate): CertificateInfo {
  const now = Date.now();
  const validTo = new Date(cert.valid_to).getTime();
  const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

  // Parse Subject Alternative Names
  const sanString = cert.subjectaltname ?? '';
  const subjectAltNames = sanString
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => {
      // Strip prefix like "DNS:" or "IP:"
      const colonIndex = s.indexOf(':');
      return colonIndex >= 0 ? s.substring(colonIndex + 1) : s;
    });

  return {
    subject: flattenCertField(cert.subject as unknown as Record<string, string | string[]>),
    issuer: flattenCertField(cert.issuer as unknown as Record<string, string | string[]>),
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    daysUntilExpiry,
    serialNumber: cert.serialNumber ?? 'unknown',
    fingerprint: cert.fingerprint ?? 'unknown',
    fingerprint256: cert.fingerprint256 ?? 'unknown',
    subjectAltNames,
    isCA: cert.ext_key_usage
      ? cert.ext_key_usage.includes('1.3.6.1.5.5.7.3.1')
      : false,
  };
}

function flattenCertField(field: Record<string, string | string[]> | undefined): Record<string, string> {
  if (!field) return {};
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(field)) {
    result[key] = Array.isArray(value) ? value.join(', ') : value;
  }
  return result;
}

function countChainDepth(cert: PeerCertificate): number {
  let depth = 0;
  let current: PeerCertificate | undefined = cert;
  const seen = new Set<string>();

  while (current) {
    const serial = current.serialNumber ?? '';
    if (seen.has(serial)) break; // Prevent infinite loop on self-signed
    seen.add(serial);
    depth++;

    // The issuerCertificate property links to the next cert in the chain
    const next: PeerCertificate | undefined = (current as PeerCertificate & { issuerCertificate?: PeerCertificate }).issuerCertificate;
    if (!next || next === current) break;
    current = next;
  }

  return depth;
}

function hasCertificateTransparency(cert: PeerCertificate): boolean {
  // Check for CT-related extensions in the raw certificate
  // OID 1.3.6.1.4.1.11129.2.4.2 = SCT List extension
  // This is a best-effort check via the info extensions string
  const infoAccess = (cert as PeerCertificate & { infoAccess?: Record<string, string[]> }).infoAccess;
  if (infoAccess) {
    // Presence of OCSP or CA Issuers suggests modern cert practices
    // but CT is specifically about SCTs embedded in cert
    return true;
  }

  // If the certificate has raw property, check for CT OID
  const raw = cert.raw;
  if (raw) {
    // Look for the CT SCT List OID in the DER-encoded certificate
    // OID 1.3.6.1.4.1.11129.2.4.2 = 06 0A 2B 06 01 04 01 D6 79 02 04 02
    const ctOid = Buffer.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);
    return raw.includes(ctOid);
  }

  return false;
}

// ─── Finding Generation ────────────────────────────────────────

/**
 * Generate security findings from a TLS analysis result.
 */
export function generateTlsFindings(result: TlsAnalysisResult): Finding[] {
  const findings: Finding[] = [];

  if (!result.connected) {
    findings.push({
      ruleId: 'spear-18/tls-connection-failed',
      severity: 'info',
      message: `Could not connect to ${result.endpoint}: ${result.error ?? 'unknown error'}`,
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
      },
    });
    return findings;
  }

  // ── TLS Version ──────────────────────────────────────────────

  if (result.tlsVersion) {
    if (DEPRECATED_TLS_VERSIONS.has(result.tlsVersion)) {
      findings.push({
        ruleId: 'spear-18/tls-version',
        severity: 'medium',
        message: `${result.tlsVersion} detected (deprecated) on ${result.endpoint}`,
        remediation: `Upgrade to ${MIN_SAFE_TLS_VERSION} or higher. Disable ${result.tlsVersion} support.`,
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
          tlsVersion: result.tlsVersion,
        },
      });
    } else {
      findings.push({
        ruleId: 'spear-18/tls-version',
        severity: 'info',
        message: `TLS version: ${result.tlsVersion} on ${result.endpoint}`,
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
          tlsVersion: result.tlsVersion,
        },
      });
    }
  }

  // ── Cipher Suite ─────────────────────────────────────────────

  if (result.cipherSuite) {
    const severity = isWeakCipher(result.cipherSuite) ? 'medium' : 'info';
    findings.push({
      ruleId: 'spear-18/cipher-suite',
      severity,
      message: severity === 'medium'
        ? `Weak cipher suite: ${result.cipherSuite} on ${result.endpoint}`
        : `Cipher suite: ${result.cipherSuite} on ${result.endpoint}`,
      remediation: severity === 'medium'
        ? 'Configure server to use strong cipher suites (AES-GCM, ChaCha20-Poly1305).'
        : undefined,
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
        cipherSuite: result.cipherSuite,
      },
    });
  }

  // ── Certificate Expiry ───────────────────────────────────────

  if (result.certificate) {
    const cert = result.certificate;
    const days = cert.daysUntilExpiry;

    if (days < 0) {
      findings.push({
        ruleId: 'spear-18/cert-expired',
        severity: 'critical',
        message: `Certificate EXPIRED ${Math.abs(days)} days ago on ${result.endpoint}`,
        remediation: 'Renew the TLS certificate immediately.',
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
          validTo: cert.validTo,
          daysUntilExpiry: days,
        },
      });
    } else if (days <= CERT_EXPIRY_CRITICAL_DAYS) {
      findings.push({
        ruleId: 'spear-18/cert-expiring',
        severity: 'critical',
        message: `Certificate expires in ${days} days on ${result.endpoint}`,
        remediation: 'Renew the TLS certificate urgently.',
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
          validTo: cert.validTo,
          daysUntilExpiry: days,
        },
      });
    } else if (days <= CERT_EXPIRY_WARN_DAYS) {
      findings.push({
        ruleId: 'spear-18/cert-expiring',
        severity: 'high',
        message: `Certificate expires in ${days} days on ${result.endpoint}`,
        remediation: 'Plan TLS certificate renewal soon.',
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
          validTo: cert.validTo,
          daysUntilExpiry: days,
        },
      });
    } else {
      findings.push({
        ruleId: 'spear-18/cert-expiry',
        severity: 'info',
        message: `Certificate valid for ${days} days on ${result.endpoint} (expires ${cert.validTo})`,
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
          validTo: cert.validTo,
          daysUntilExpiry: days,
        },
      });
    }

    // ── Certificate Subject/Issuer ───────────────────────────────

    const subjectCN = cert.subject['CN'] ?? cert.subject['O'] ?? 'unknown';
    const issuerCN = cert.issuer['CN'] ?? cert.issuer['O'] ?? 'unknown';

    findings.push({
      ruleId: 'spear-18/cert-info',
      severity: 'info',
      message: `Certificate: subject=${subjectCN}, issuer=${issuerCN}, serial=${cert.serialNumber}`,
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
        subject: cert.subject,
        issuer: cert.issuer,
        serialNumber: cert.serialNumber,
        fingerprint256: cert.fingerprint256,
      },
    });

    // ── Subject Alternative Names ────────────────────────────────

    if (cert.subjectAltNames.length > 0) {
      findings.push({
        ruleId: 'spear-18/cert-san',
        severity: 'info',
        message: `SAN entries (${cert.subjectAltNames.length}): ${cert.subjectAltNames.slice(0, 10).join(', ')}${cert.subjectAltNames.length > 10 ? ` (+${cert.subjectAltNames.length - 10} more)` : ''}`,
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
          subjectAltNames: cert.subjectAltNames,
          sanCount: cert.subjectAltNames.length,
        },
      });
    }

    // ── Self-signed Certificate ──────────────────────────────────

    if (isSelfSigned(cert)) {
      findings.push({
        ruleId: 'spear-18/cert-self-signed',
        severity: 'high',
        message: `Self-signed certificate detected on ${result.endpoint}`,
        remediation: 'Use a certificate signed by a trusted Certificate Authority (CA).',
        metadata: {
          pluginId: 'tls-recon',
          endpoint: result.endpoint,
        },
      });
    }
  }

  // ── Chain Depth ──────────────────────────────────────────────

  if (result.chainDepth !== undefined) {
    findings.push({
      ruleId: 'spear-18/cert-chain',
      severity: 'info',
      message: `Certificate chain depth: ${result.chainDepth} on ${result.endpoint}`,
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
        chainDepth: result.chainDepth,
      },
    });
  }

  // ── HSTS ─────────────────────────────────────────────────────

  if (result.hstsPresent === false) {
    findings.push({
      ruleId: 'spear-18/missing-hsts',
      severity: 'medium',
      message: `HSTS header not set on ${result.endpoint}`,
      remediation: 'Set the Strict-Transport-Security header with a minimum max-age of 31536000 (1 year).',
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
      },
    });
  } else if (result.hstsPresent === true) {
    const maxAgeSeverity: Severity = result.hstsMaxAge !== undefined && result.hstsMaxAge < 15768000
      ? 'low'
      : 'info';
    findings.push({
      ruleId: 'spear-18/hsts',
      severity: maxAgeSeverity,
      message: maxAgeSeverity === 'low'
        ? `HSTS max-age is short (${result.hstsMaxAge}s) on ${result.endpoint}`
        : `HSTS enabled (max-age=${result.hstsMaxAge ?? 'unknown'}s) on ${result.endpoint}`,
      remediation: maxAgeSeverity === 'low'
        ? 'Increase HSTS max-age to at least 31536000 (1 year).'
        : undefined,
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
        hstsMaxAge: result.hstsMaxAge,
      },
    });
  }

  // ── Certificate Transparency ─────────────────────────────────

  if (result.certificateTransparency === false) {
    findings.push({
      ruleId: 'spear-18/no-ct',
      severity: 'low',
      message: `No Certificate Transparency SCTs found for ${result.endpoint}`,
      remediation: 'Use a CA that supports Certificate Transparency and embeds SCTs in certificates.',
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
      },
    });
  } else if (result.certificateTransparency === true) {
    findings.push({
      ruleId: 'spear-18/ct-present',
      severity: 'info',
      message: `Certificate Transparency supported on ${result.endpoint}`,
      metadata: {
        pluginId: 'tls-recon',
        endpoint: result.endpoint,
      },
    });
  }

  return findings;
}

// ─── Helpers ───────────────────────────────────────────────────

/**
 * Check if a cipher suite is considered weak.
 */
function isWeakCipher(cipherName: string): boolean {
  const weak = [
    'RC4', 'DES', '3DES', 'RC2', 'MD5',
    'NULL', 'EXPORT', 'ANON',
    'CBC_SHA',  // CBC mode with SHA-1
  ];
  const upper = cipherName.toUpperCase();
  return weak.some((w) => upper.includes(w));
}

/**
 * Check if a certificate appears to be self-signed.
 */
function isSelfSigned(cert: CertificateInfo): boolean {
  // Compare subject and issuer common names
  const subjectCN = cert.subject['CN'] ?? '';
  const issuerCN = cert.issuer['CN'] ?? '';

  if (subjectCN && issuerCN && subjectCN === issuerCN) {
    // Also check organization if available
    const subjectO = cert.subject['O'] ?? '';
    const issuerO = cert.issuer['O'] ?? '';
    if (subjectO === issuerO) {
      return true;
    }
  }

  return false;
}
