import { createRequire } from 'node:module';
import { describe, expect, it } from 'vitest';

const require = createRequire(import.meta.url);

interface FfiNodeAddon {
  ffiSmoke: () => string;
}

describe('napi-rs binding (Node)', () => {
  it('calls a trivial Rust function and gets its value back', () => {
    const addon = require('../native/chiavora_ffi_node.node') as FfiNodeAddon;
    expect(addon.ffiSmoke()).toBe('chiavora-ffi-node:ok');
  });
});
