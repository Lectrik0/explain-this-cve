// Local development: loads .env.local, then starts the real Vercel dev server (without linking a project).
//   npm run dev        -> http://localhost:3000
//
// Why this script exists: `vercel dev --local` does not read .env.local by itself. Variables set in this
// process are inherited by the dev server, so the API sees your keys exactly as it will on Vercel.
// Nothing is printed except whether the file was found: never any value.

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';

const envFile = new URL('../.env.local', import.meta.url);
if (existsSync(envFile)) {
  try {
    process.loadEnvFile(envFile);
    console.log('Loaded .env.local (values are never printed).');
  } catch {
    console.error('Could not parse .env.local: check that every line looks like NAME=value.');
  }
} else {
  console.log('No .env.local found: starting without keys (template summary, lower NVD rate limit). See .env.example.');
}

// Fixed arguments only; the shell is needed on Windows, where `vercel` is a .cmd file.
const child = spawn('vercel', ['dev', '--local', '--yes', '--listen', '3000'], { stdio: 'inherit', shell: true });
child.on('exit', (code) => process.exit(code ?? 0));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
