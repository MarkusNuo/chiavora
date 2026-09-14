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

export interface VaultState {
  readonly hasSecretKey: boolean;
  readonly hasWrappedMuk: boolean;
  readonly mukKeyInvalidated: boolean;
}

/** Read {@link KeystoreProviderReport.controlWorked} first. */
export interface KeystoreProviderReport {
  readonly spiClass?: string;
  readonly chain?: string;
  readonly byteBufferDoFinalDeclaredBy?: string | null;
  readonly byteArrayDoFinalDeclaredBy?: string | null;
  readonly controlWorked?: boolean;
  readonly verdict?: string;
  readonly error?: string;
}

export interface KeystoreReport {
  readonly mukBacking: string;
  /** Must be true: a new fingerprint destroys the MUK's wrapping key. */
  readonly mukInvalidatedByEnrollment: boolean;
  readonly secretKeyBacking: string;
  /** Must be false (I8). */
  readonly secretKeyInvalidatedByEnrollment: boolean;
}

export type UnlockOutcome = {
  mukLen: number;
  rollbackProtection: 'Anchored' | 'IntegrityOnly';
};

interface ChiavoraCoreNativeModule {

  ffiSmoke(): Promise<string>;
  hasHarness(): boolean;
  harnessDeriveOnce?(
    memoryKib: number,
    iterations: number,
    delayMs: number,
  ): Promise<DerivationOutcome>;
  keystoreProviderReport?(): Promise<KeystoreProviderReport>;

  enroll(
    password: Uint8Array,
    secretKey: Uint8Array,
    accountId: Uint8Array,
    accountSalt: Uint8Array,
    memoryKib: number,
    iterations: number,
  ): Promise<boolean>;
  unlockWithPassword(
    password: Uint8Array,
    accountId: Uint8Array,
    accountSalt: Uint8Array,
    memoryKib: number,
    iterations: number,
  ): Promise<UnlockOutcome>;
  unlockWithBiometric(): Promise<UnlockOutcome>;
  /** Refused if the device has moved past `discardingAfter`, the generation the user saw. */
  restoreFromOlderBackup(
    password: Uint8Array,
    accountId: Uint8Array,
    accountSalt: Uint8Array,
    memoryKib: number,
    iterations: number,
    discardingAfter: number,
  ): Promise<number>;
  vaultState(): Promise<VaultState>;
  keystoreReport(): Promise<KeystoreReport>;
  forgetDevice(): Promise<boolean>;
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

export async function keystoreProviderReport(): Promise<KeystoreProviderReport | null> {
  if (!ChiavoraCore.hasHarness() || !ChiavoraCore.keystoreProviderReport) {
    return null;
  }
  return ChiavoraCore.keystoreProviderReport();
}
