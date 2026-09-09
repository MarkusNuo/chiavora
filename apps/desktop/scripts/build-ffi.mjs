import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..', '..', '..');

const artifact = {
  win32: 'chiavora_ffi_node.dll',
  darwin: 'libchiavora_ffi_node.dylib',
  linux: 'libchiavora_ffi_node.so',
}[process.platform];

if (!artifact) {
  throw new Error(`unsupported platform for the ffi-node addon: ${process.platform}`);
}

execFileSync('cargo', ['build', '-p', 'chiavora-ffi-node'], {
  cwd: repoRoot,
  stdio: 'inherit',
});

const from = join(repoRoot, 'target', 'debug', artifact);
const outDir = join(here, '..', 'native');
mkdirSync(outDir, { recursive: true });
copyFileSync(from, join(outDir, 'chiavora_ffi_node.node'));
process.stdout.write(`copied ${artifact} -> native/chiavora_ffi_node.node\n`);
