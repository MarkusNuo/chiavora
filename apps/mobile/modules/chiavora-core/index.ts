import { requireNativeModule } from 'expo-modules-core';

export interface DerivationOutcome {
  readonly completed: boolean;
  readonly millis: number;
  readonly refusal: string | null;
  readonly oomScoreAdjBefore: number | null;
  readonly oomScoreAdjAfter: number | null;
  readonly memAvailableKibBefore: number | null;
  readonly memAvailableKibAfter: number | null;
  readonly memoryKib: number;
  readonly iterations: number;
}

interface ChiavoraCoreNativeModule {
  ffiSmoke(): string;
  hasHarness(): boolean;
  harnessDeriveOnce?(
    memoryKib: number,
    iterations: number,
    delayMs: number,
  ): Promise<DerivationOutcome>;
}

const ChiavoraCore = requireNativeModule<ChiavoraCoreNativeModule>('ChiavoraCore');

export default ChiavoraCore;

export async function harnessDeriveOnce(
  memoryKib: number,
  iterations: number,
  delayMs: number,
): Promise<DerivationOutcome | null> {
  if (!ChiavoraCore.hasHarness() || !ChiavoraCore.harnessDeriveOnce) {
    return null;
  }
  return ChiavoraCore.harnessDeriveOnce(memoryKib, iterations, delayMs);
}
