import { rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';

await rm(new URL('../dist', import.meta.url), { recursive: true, force: true });

const command = process.platform === 'win32' ? 'tsc.cmd' : 'tsc';
const child = spawn(command, ['-p', 'tsconfig.json'], {
  cwd: new URL('..', import.meta.url),
  stdio: 'inherit',
  shell: false,
});

const exitCode = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('exit', (code) => resolve(code ?? 1));
});
process.exitCode = exitCode;
