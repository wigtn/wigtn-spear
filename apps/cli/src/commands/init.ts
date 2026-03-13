/**
 * `spear init` command
 *
 * Initializes a WIGTN-SPEAR project in the current (or specified) directory.
 *
 * Creates:
 *   - .spear/          -- directory for local SQLite DB and cache
 *   - .spearignore     -- default ignore patterns (node_modules, dist, etc.)
 *   - .spearrc.yaml    -- default configuration file
 *
 * This command is idempotent: running it again will not overwrite existing files.
 */

import { Command, Args } from '@oclif/core';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import chalk from 'chalk';

// ─── Default File Contents ────────────────────────────────

const DEFAULT_SPEARIGNORE = `# WIGTN-SPEAR Ignore Patterns
# Files and directories listed here will be excluded from scanning.
# Syntax follows .gitignore conventions.

# Dependencies
node_modules/
vendor/
bower_components/

# Build outputs
dist/
build/
out/
.next/
.nuxt/

# Package manager
pnpm-lock.yaml
package-lock.json
yarn.lock

# IDE & Editor
.idea/
.vscode/
*.swp
*.swo
*~

# OS files
.DS_Store
Thumbs.db

# Test fixtures & snapshots
__snapshots__/
*.snap

# SPEAR local data
.spear/

# Binary files
*.png
*.jpg
*.jpeg
*.gif
*.ico
*.svg
*.woff
*.woff2
*.ttf
*.eot
*.pdf
*.zip
*.tar.gz
*.tgz
`;

const DEFAULT_SPEARRC_YAML = `# WIGTN-SPEAR Configuration
# See: https://github.com/wigtn/wigtn-spear

# Scan mode: 'safe' (no network, read-only) or 'aggressive' (live verification)
mode: safe

# Modules to run: ['all'] or specific module IDs
modules:
  - all

# Paths to exclude from scanning (in addition to .spearignore)
exclude: []

# Maximum number of secrets to live-verify in aggressive mode
verifyLimit: 100

# Worker threads: 0 = auto (cpu count - 1)
maxWorkers: 0

# Git history depth: number of commits to scan (0 = HEAD only, -1 = unlimited)
gitDepth: 1000

# Output format: 'text', 'json', or 'sarif'
outputFormat: text

# Database path (relative to project root)
dbPath: .spear/spear.db

# Custom rules directory (empty = use built-in rules only)
rulesDir: ""

# Verbose logging
verbose: false
`;

// ─── Command ──────────────────────────────────────────────

export default class Init extends Command {
  static override description = 'Initialize WIGTN-SPEAR in the current directory';

  static override examples = [
    '<%= config.bin %> init',
    '<%= config.bin %> init /path/to/project',
  ];

  static override args = {
    directory: Args.string({
      description: 'Target directory to initialize (default: current directory)',
      required: false,
      default: '.',
    }),
  };

  async run(): Promise<void> {
    const { args } = await this.parse(Init);
    const targetDir = resolve(args.directory as string);

    this.log(chalk.red.bold('\n  WIGTN-SPEAR') + chalk.dim(' -- Initialization\n'));

    let created = 0;
    let skipped = 0;

    // 1. Create .spear/ directory
    const spearDir = join(targetDir, '.spear');
    if (!existsSync(spearDir)) {
      mkdirSync(spearDir, { recursive: true });
      this.log(`  ${chalk.green('+')} Created ${chalk.dim('.spear/')}`);
      created++;
    } else {
      this.log(`  ${chalk.yellow('-')} Exists  ${chalk.dim('.spear/')}`);
      skipped++;
    }

    // 2. Create .spearignore
    const ignorePath = join(targetDir, '.spearignore');
    if (!existsSync(ignorePath)) {
      writeFileSync(ignorePath, DEFAULT_SPEARIGNORE, 'utf-8');
      this.log(`  ${chalk.green('+')} Created ${chalk.dim('.spearignore')}`);
      created++;
    } else {
      this.log(`  ${chalk.yellow('-')} Exists  ${chalk.dim('.spearignore')}`);
      skipped++;
    }

    // 3. Create .spearrc.yaml
    const rcPath = join(targetDir, '.spearrc.yaml');
    if (!existsSync(rcPath)) {
      writeFileSync(rcPath, DEFAULT_SPEARRC_YAML, 'utf-8');
      this.log(`  ${chalk.green('+')} Created ${chalk.dim('.spearrc.yaml')}`);
      created++;
    } else {
      this.log(`  ${chalk.yellow('-')} Exists  ${chalk.dim('.spearrc.yaml')}`);
      skipped++;
    }

    // Summary
    this.log('');
    if (created > 0) {
      this.log(
        `  ${chalk.green('Initialized!')} ` +
        `${created} file${created > 1 ? 's' : ''} created` +
        (skipped > 0 ? `, ${skipped} already existed` : '') +
        '.',
      );
    } else {
      this.log(`  ${chalk.yellow('Already initialized.')} All files exist.`);
    }

    this.log(`\n  Run ${chalk.cyan('spear scan')} to start scanning.\n`);
  }
}
