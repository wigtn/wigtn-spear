/**
 * SPEAR-12: Container Security Auditor -- Pattern Definitions
 *
 * Defines 36 detection patterns across six categories:
 *
 *   - privileged_container   -- Privileged mode, capabilities, security contexts
 *   - root_user             -- Running as root in container images
 *   - exposed_port          -- Unnecessary or dangerous port exposure
 *   - sensitive_mount       -- Host filesystem mounts leaking secrets
 *   - insecure_registry     -- Untrusted or HTTP registries
 *   - misconfiguration      -- General container security misconfigurations
 *
 * Each pattern includes MITRE ATT&CK mappings for enterprise threat classification.
 *
 * MITRE references used:
 *   T1610     -- Deploy Container
 *   T1611     -- Escape to Host
 *   T1613     -- Container and Resource Discovery
 *   T1053     -- Scheduled Task/Job
 *   T1552     -- Unsecured Credentials
 *   T1078     -- Valid Accounts
 *   T1562     -- Impair Defenses
 *   T1059     -- Command and Scripting Interpreter
 */

import type { Severity } from '@wigtn/shared';

// ─── Pattern Interface ─────────────────────────────────────────

export type ContainerCategory =
  | 'privileged_container'
  | 'root_user'
  | 'exposed_port'
  | 'sensitive_mount'
  | 'insecure_registry'
  | 'misconfiguration';

export interface ContainerPattern {
  id: string;
  name: string;
  description: string;
  category: ContainerCategory;
  pattern: RegExp;
  severity: Severity;
  mitre: string[];
  remediation: string;
  /** Which file types this pattern applies to: dockerfile, compose, k8s, or all */
  appliesTo: ('dockerfile' | 'compose' | 'k8s')[];
}

// ─── Privileged Container Patterns ─────────────────────────────

const privilegedPatterns: ContainerPattern[] = [
  {
    id: 'container-privileged-mode',
    name: 'Privileged Container Mode',
    description: 'Container running in privileged mode with full host access',
    category: 'privileged_container',
    pattern: /privileged\s*:\s*true/i,
    severity: 'critical',
    mitre: ['T1611'],
    remediation: 'Remove privileged: true. Use specific capabilities instead of full privileged mode.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-cap-sys-admin',
    name: 'SYS_ADMIN Capability',
    description: 'Container granted SYS_ADMIN capability allowing host escape',
    category: 'privileged_container',
    pattern: /(?:cap_add|capabilities|add)\s*:?\s*(?:\[?\s*|-\s*)["']?SYS_ADMIN["']?/i,
    severity: 'critical',
    mitre: ['T1611'],
    remediation: 'Remove SYS_ADMIN capability. This grants near-full root access and enables container escape.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-cap-net-admin',
    name: 'NET_ADMIN Capability',
    description: 'Container granted NET_ADMIN capability allowing network manipulation',
    category: 'privileged_container',
    pattern: /(?:cap_add|capabilities|add)\s*:?\s*(?:\[?\s*|-\s*)["']?NET_ADMIN["']?/i,
    severity: 'high',
    mitre: ['T1611', 'T1562'],
    remediation: 'Remove NET_ADMIN capability unless explicitly needed for network configuration.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-cap-sys-ptrace',
    name: 'SYS_PTRACE Capability',
    description: 'Container granted SYS_PTRACE capability allowing process debugging and escape',
    category: 'privileged_container',
    pattern: /(?:cap_add|capabilities|add)\s*:?\s*(?:\[?\s*|-\s*)["']?SYS_PTRACE["']?/i,
    severity: 'high',
    mitre: ['T1611'],
    remediation: 'Remove SYS_PTRACE capability. It allows container escape via process debugging.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-host-pid',
    name: 'Host PID Namespace',
    description: 'Container sharing host PID namespace allowing process visibility and control',
    category: 'privileged_container',
    pattern: /(?:pid\s*:\s*["']?host["']?|hostPID\s*:\s*true)/i,
    severity: 'critical',
    mitre: ['T1611', 'T1613'],
    remediation: 'Remove host PID namespace sharing. Containers should use isolated PID namespaces.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-host-network',
    name: 'Host Network Mode',
    description: 'Container using host network namespace bypassing network isolation',
    category: 'privileged_container',
    pattern: /(?:network_mode\s*:\s*["']?host["']?|hostNetwork\s*:\s*true)/i,
    severity: 'high',
    mitre: ['T1611'],
    remediation: 'Remove host network mode. Use bridge or overlay networking for proper isolation.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-host-ipc',
    name: 'Host IPC Namespace',
    description: 'Container sharing host IPC namespace allowing inter-process communication attack',
    category: 'privileged_container',
    pattern: /(?:ipc\s*:\s*["']?host["']?|hostIPC\s*:\s*true)/i,
    severity: 'high',
    mitre: ['T1611'],
    remediation: 'Remove host IPC sharing. Use isolated IPC namespaces for containers.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-seccomp-disabled',
    name: 'Seccomp Profile Disabled',
    description: 'Container with seccomp profile disabled removing syscall restrictions',
    category: 'privileged_container',
    pattern: /(?:seccomp\s*[=:]\s*["']?unconfined["']?|seccompProfile[\s\S]*?type\s*:\s*["']?Unconfined["']?)/i,
    severity: 'critical',
    mitre: ['T1611', 'T1562'],
    remediation: 'Enable seccomp profiles. Use RuntimeDefault or a custom profile instead of Unconfined.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-apparmor-disabled',
    name: 'AppArmor Disabled',
    description: 'Container with AppArmor profile disabled removing mandatory access control',
    category: 'privileged_container',
    pattern: /(?:apparmor\s*[=:]\s*["']?unconfined["']?|apparmor.*:\s*["']?unconfined["']?)/i,
    severity: 'high',
    mitre: ['T1562'],
    remediation: 'Enable AppArmor profiles. Use runtime/default or a custom profile.',
    appliesTo: ['compose', 'k8s'],
  },
];

// ─── Root User Patterns ────────────────────────────────────────

const rootUserPatterns: ContainerPattern[] = [
  {
    id: 'container-user-root',
    name: 'Running as Root User',
    description: 'Container running as root user (UID 0)',
    category: 'root_user',
    pattern: /^\s*USER\s+(?:root|0)\s*$/im,
    severity: 'high',
    mitre: ['T1078'],
    remediation: 'Use a non-root user with USER directive. Create a dedicated user with useradd.',
    appliesTo: ['dockerfile'],
  },
  {
    id: 'container-no-user-directive',
    name: 'Missing USER Directive',
    description: 'Dockerfile without USER directive defaults to running as root',
    category: 'root_user',
    pattern: /^FROM\s+/im,
    severity: 'medium',
    mitre: ['T1078'],
    remediation: 'Add a USER directive to run the container as a non-root user.',
    appliesTo: ['dockerfile'],
  },
  {
    id: 'container-run-as-root-k8s',
    name: 'RunAsUser Root in K8s',
    description: 'Kubernetes pod spec explicitly running as root user',
    category: 'root_user',
    pattern: /runAsUser\s*:\s*0/i,
    severity: 'high',
    mitre: ['T1078'],
    remediation: 'Set runAsUser to a non-zero UID in the pod security context.',
    appliesTo: ['k8s'],
  },
  {
    id: 'container-run-as-non-root-false',
    name: 'RunAsNonRoot Disabled',
    description: 'Kubernetes security context allows running as root',
    category: 'root_user',
    pattern: /runAsNonRoot\s*:\s*false/i,
    severity: 'high',
    mitre: ['T1078'],
    remediation: 'Set runAsNonRoot: true in the pod security context.',
    appliesTo: ['k8s'],
  },
  {
    id: 'container-allow-privilege-escalation',
    name: 'Allow Privilege Escalation',
    description: 'Container allows privilege escalation via setuid/setgid binaries',
    category: 'root_user',
    pattern: /allowPrivilegeEscalation\s*:\s*true/i,
    severity: 'high',
    mitre: ['T1611', 'T1078'],
    remediation: 'Set allowPrivilegeEscalation: false in the container security context.',
    appliesTo: ['k8s'],
  },
];

// ─── Exposed Port Patterns ─────────────────────────────────────

const exposedPortPatterns: ContainerPattern[] = [
  {
    id: 'container-expose-all-interfaces',
    name: 'Expose on All Interfaces',
    description: 'Port exposed on 0.0.0.0 making it accessible from all network interfaces',
    category: 'exposed_port',
    pattern: /(?:ports\s*:[\s\S]*?-\s*["']?0\.0\.0\.0:|["']0\.0\.0\.0:\d+:\d+["'])/i,
    severity: 'medium',
    mitre: ['T1613'],
    remediation: 'Bind ports to 127.0.0.1 instead of 0.0.0.0 unless external access is required.',
    appliesTo: ['compose'],
  },
  {
    id: 'container-expose-ssh',
    name: 'SSH Port Exposed',
    description: 'Container exposing SSH port (22) which should not be needed',
    category: 'exposed_port',
    pattern: /(?:EXPOSE\s+22\b|["']?\d*:?22(?:\/tcp)?["']?)/i,
    severity: 'high',
    mitre: ['T1613', 'T1078'],
    remediation: 'Remove SSH port exposure. Use docker exec for container access.',
    appliesTo: ['dockerfile', 'compose'],
  },
  {
    id: 'container-expose-debug-port',
    name: 'Debug Port Exposed',
    description: 'Container exposing common debug ports (5005, 9229, 4200, 8787)',
    category: 'exposed_port',
    pattern: /(?:EXPOSE|ports\s*:[\s\S]*?-\s*["']?\d*:?)\s*(?:5005|9229|4200|8787|5858)\b/i,
    severity: 'medium',
    mitre: ['T1613'],
    remediation: 'Remove debug port exposure in production configurations.',
    appliesTo: ['dockerfile', 'compose'],
  },
  {
    id: 'container-expose-database-port',
    name: 'Database Port Exposed to Host',
    description: 'Database port directly exposed to host without internal-only networking',
    category: 'exposed_port',
    pattern: /ports\s*:[\s\S]*?["']?\d*:(?:3306|5432|27017|6379|9200|5984|1433|1521)\b/i,
    severity: 'high',
    mitre: ['T1613'],
    remediation: 'Use internal Docker networks for database connections instead of exposing ports to host.',
    appliesTo: ['compose'],
  },
];

// ─── Sensitive Mount Patterns ──────────────────────────────────

const sensitiveMountPatterns: ContainerPattern[] = [
  {
    id: 'container-mount-docker-sock',
    name: 'Docker Socket Mount',
    description: 'Mounting Docker socket gives full control over the Docker daemon',
    category: 'sensitive_mount',
    pattern: /(?:volumes?\s*:[\s\S]*?|[-:])\s*\/var\/run\/docker\.sock/i,
    severity: 'critical',
    mitre: ['T1611'],
    remediation: 'Remove Docker socket mount. Use Docker-in-Docker or rootless alternatives if needed.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-mount-etc',
    name: 'Host /etc Mount',
    description: 'Mounting host /etc directory exposes system configuration and credentials',
    category: 'sensitive_mount',
    pattern: /(?:volumes?\s*:[\s\S]*?|[-:])\s*\/etc(?:\/|["':,\s])/i,
    severity: 'critical',
    mitre: ['T1552', 'T1611'],
    remediation: 'Remove host /etc mount. Mount only specific files if configuration access is needed.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-mount-proc',
    name: 'Host /proc Mount',
    description: 'Mounting host /proc exposes process information and enables escape',
    category: 'sensitive_mount',
    pattern: /(?:volumes?\s*:[\s\S]*?|hostPath[\s\S]*?path\s*:\s*)["']?\/proc\b/i,
    severity: 'critical',
    mitre: ['T1611'],
    remediation: 'Remove host /proc mount. Containers should not access host process information.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-mount-root-fs',
    name: 'Host Root Filesystem Mount',
    description: 'Mounting the entire host root filesystem into the container',
    category: 'sensitive_mount',
    pattern: /(?:volumes?\s*:[\s\S]*?|hostPath[\s\S]*?path\s*:\s*)["']?\/(?:["':,\s]|$)/m,
    severity: 'critical',
    mitre: ['T1611'],
    remediation: 'Never mount the host root filesystem. Use specific subdirectory mounts.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-mount-ssh-keys',
    name: 'SSH Keys Mount',
    description: 'Mounting host SSH keys directory into container',
    category: 'sensitive_mount',
    pattern: /(?:volumes?\s*:[\s\S]*?|hostPath[\s\S]*?path\s*:\s*)["']?~?\/?\.ssh\b/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Remove SSH key mounts. Use Docker secrets or build-time SSH agent forwarding.',
    appliesTo: ['compose', 'k8s'],
  },
  {
    id: 'container-mount-kubeconfig',
    name: 'Kubeconfig Mount',
    description: 'Mounting kubeconfig into container exposing cluster credentials',
    category: 'sensitive_mount',
    pattern: /(?:volumes?\s*:[\s\S]*?|hostPath[\s\S]*?path\s*:\s*)["']?~?\/?\.kube\b/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Remove kubeconfig mounts. Use service accounts and RBAC instead.',
    appliesTo: ['compose', 'k8s'],
  },
];

// ─── Insecure Registry Patterns ────────────────────────────────

const insecureRegistryPatterns: ContainerPattern[] = [
  {
    id: 'container-http-registry',
    name: 'HTTP Container Registry',
    description: 'Container image pulled from insecure HTTP registry',
    category: 'insecure_registry',
    pattern: /(?:FROM|image\s*:)\s*["']?http:\/\//i,
    severity: 'high',
    mitre: ['T1610'],
    remediation: 'Use HTTPS registries only. HTTP registries expose images to MITM attacks.',
    appliesTo: ['dockerfile', 'compose'],
  },
  {
    id: 'container-latest-tag',
    name: 'Latest Tag Used',
    description: 'Container image using :latest tag which is mutable and unpinned',
    category: 'insecure_registry',
    pattern: /(?:FROM|image\s*:)\s*["']?[a-zA-Z0-9._\/-]+:latest\b/i,
    severity: 'medium',
    mitre: ['T1610'],
    remediation: 'Pin images to specific version tags or SHA256 digests for reproducibility.',
    appliesTo: ['dockerfile', 'compose', 'k8s'],
  },
  {
    id: 'container-no-tag',
    name: 'Image Without Tag',
    description: 'Container image referenced without any tag defaults to :latest',
    category: 'insecure_registry',
    pattern: /(?:FROM|image\s*:)\s*["']?([a-zA-Z0-9._\/-]+)["']?\s*$/im,
    severity: 'medium',
    mitre: ['T1610'],
    remediation: 'Always specify an explicit image tag or SHA256 digest.',
    appliesTo: ['dockerfile', 'compose', 'k8s'],
  },
  {
    id: 'container-insecure-registry-flag',
    name: 'Insecure Registry Configuration',
    description: 'Docker daemon configured to allow insecure registries',
    category: 'insecure_registry',
    pattern: /(?:insecure-registries|insecure_registries)\s*[=:]/i,
    severity: 'high',
    mitre: ['T1610'],
    remediation: 'Remove insecure registry configurations. All registries should use TLS.',
    appliesTo: ['compose'],
  },
];

// ─── Misconfiguration Patterns ─────────────────────────────────

const misconfigPatterns: ContainerPattern[] = [
  {
    id: 'container-add-instead-of-copy',
    name: 'ADD Instead of COPY',
    description: 'Using ADD instruction which can fetch remote URLs and auto-extract archives',
    category: 'misconfiguration',
    pattern: /^\s*ADD\s+https?:\/\//im,
    severity: 'medium',
    mitre: ['T1610'],
    remediation: 'Use COPY instead of ADD for local files. Use curl/wget in RUN for remote fetches with verification.',
    appliesTo: ['dockerfile'],
  },
  {
    id: 'container-env-secrets',
    name: 'Secrets in Environment Variables',
    description: 'Sensitive values hardcoded in container environment variables',
    category: 'misconfiguration',
    pattern: /(?:ENV|environment\s*:[\s\S]*?)\s*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|AWS_SECRET)\s*[=:]\s*["']?[^\s"']+/i,
    severity: 'critical',
    mitre: ['T1552'],
    remediation: 'Use Docker secrets, Vault, or external secret managers instead of ENV for sensitive values.',
    appliesTo: ['dockerfile', 'compose', 'k8s'],
  },
  {
    id: 'container-healthcheck-missing',
    name: 'Missing HEALTHCHECK',
    description: 'Dockerfile without HEALTHCHECK instruction',
    category: 'misconfiguration',
    pattern: /^FROM\s+/im,
    severity: 'low',
    mitre: ['T1610'],
    remediation: 'Add a HEALTHCHECK instruction to enable container health monitoring.',
    appliesTo: ['dockerfile'],
  },
  {
    id: 'container-read-only-fs-disabled',
    name: 'Writable Root Filesystem',
    description: 'Container without read-only root filesystem enabling persistent modifications',
    category: 'misconfiguration',
    pattern: /readOnlyRootFilesystem\s*:\s*false/i,
    severity: 'medium',
    mitre: ['T1611'],
    remediation: 'Set readOnlyRootFilesystem: true and use emptyDir volumes for writable paths.',
    appliesTo: ['k8s'],
  },
  {
    id: 'container-resource-limits-missing',
    name: 'Missing Resource Limits',
    description: 'Container without CPU/memory resource limits enabling resource abuse',
    category: 'misconfiguration',
    pattern: /containers\s*:[\s\S]*?(?:name\s*:[\s\S]*?)(?!resources\s*:)/i,
    severity: 'medium',
    mitre: ['T1610'],
    remediation: 'Add resource limits (cpu, memory) to prevent container resource abuse.',
    appliesTo: ['k8s'],
  },
  {
    id: 'container-curl-pipe-bash',
    name: 'Curl Pipe to Shell',
    description: 'Dockerfile downloads and executes remote scripts without verification',
    category: 'misconfiguration',
    pattern: /RUN\s+.*(?:curl|wget)\s+.*\|\s*(?:sh|bash|zsh)/i,
    severity: 'high',
    mitre: ['T1059', 'T1610'],
    remediation: 'Download scripts separately, verify checksums, then execute. Never pipe remote content directly to shell.',
    appliesTo: ['dockerfile'],
  },
];

// ─── All Patterns Export ───────────────────────────────────────

/**
 * Complete set of 36 container security detection patterns.
 */
export const ALL_CONTAINER_PATTERNS: readonly ContainerPattern[] = [
  ...privilegedPatterns,
  ...rootUserPatterns,
  ...exposedPortPatterns,
  ...sensitiveMountPatterns,
  ...insecureRegistryPatterns,
  ...misconfigPatterns,
];

/**
 * Get patterns filtered by category.
 */
export function getPatternsByCategory(category: ContainerCategory): ContainerPattern[] {
  return ALL_CONTAINER_PATTERNS.filter((p) => p.category === category);
}

/**
 * Get patterns applicable to a specific file type.
 */
export function getPatternsForFileType(fileType: 'dockerfile' | 'compose' | 'k8s'): ContainerPattern[] {
  return ALL_CONTAINER_PATTERNS.filter((p) => p.appliesTo.includes(fileType));
}

/**
 * Pattern count by category (for logging/reporting).
 */
export function getPatternCounts(): Record<ContainerCategory, number> {
  const counts: Record<ContainerCategory, number> = {
    privileged_container: 0,
    root_user: 0,
    exposed_port: 0,
    sensitive_mount: 0,
    insecure_registry: 0,
    misconfiguration: 0,
  };

  for (const p of ALL_CONTAINER_PATTERNS) {
    counts[p.category]++;
  }

  return counts;
}
