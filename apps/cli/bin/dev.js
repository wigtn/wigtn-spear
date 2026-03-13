#!/usr/bin/env node

/**
 * Development entry point for WIGTN-SPEAR CLI.
 *
 * Uses ts-node/esm loader to run TypeScript source directly,
 * bypassing the build step for faster iteration.
 */

import {execute} from '@oclif/core';
await execute({development: true, dir: import.meta.url});
