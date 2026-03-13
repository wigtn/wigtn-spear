/**
 * @wigtn/cli -- WIGTN-SPEAR Command Line Interface
 *
 * This is the main entry point for the CLI package. It re-exports
 * the oclif run function for programmatic usage.
 *
 * CLI commands are auto-discovered by oclif from the ./commands/ directory:
 *   - spear init         -- Initialize a SPEAR project
 *   - spear scan         -- Run a security scan
 *   - spear report       -- Generate reports from past scans
 *   - spear config set   -- Set a config value
 *   - spear config get   -- Get a config value
 *   - spear config list  -- List all config values
 *
 * Usage:
 *   $ spear scan ./my-project --mode safe --output sarif
 */

export { run } from '@oclif/core';
