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

export interface GeneratedValue {
  readonly value: string;
  readonly entropyBits: number;
}

export interface GeneratorLimits {
  readonly maxLength: number;
  readonly maxWords: number;
  readonly wordCount: number;
  readonly symbols: string;
  /** The CC BY 3.0 US attribution the about screen must show. */
  readonly wordlistAttribution: string;
  readonly wordlistSource: string;
}

/** Title and username only, never the item (N1). */
export interface ItemSummary {
  readonly itemId: string;
  readonly version: number;
  readonly kind: string;
  readonly title: string;
  readonly username: string;
}

export interface ItemField {
  readonly name: string;
  readonly value: string;
  readonly concealed: boolean;
}

export interface ItemDetail {
  readonly itemId: string;
  readonly kind: string;
  readonly fields: readonly ItemField[];
}

export interface LockPolicy {
  readonly idleTimeoutSeconds: number;
  readonly minIdleTimeoutSeconds: number;
  readonly maxIdleTimeoutSeconds: number;
  readonly clipboardTtlSeconds: number;
  readonly maxFailedAttempts: number;
  /** True while these numbers are placeholders rather than decisions. */
  readonly provisional: boolean;
}

export interface CopyOutcome {
  readonly ttlSeconds: number;
  readonly sensitiveFlag: boolean;
}

export type LockReason = 'manual' | 'backgrounded' | 'idle';

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
  addListener(
    event: 'onLock',
    listener: (payload: { reason: LockReason }) => void,
  ): { remove: () => void };

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
  /** Every lock is reported through {@link onLock}. */
  lock(): Promise<boolean>;
  isUnlocked(): Promise<boolean>;
  vaultState(): Promise<VaultState>;
  keystoreReport(): Promise<KeystoreReport>;
  forgetDevice(): Promise<boolean>;

  lockPolicy(): Promise<LockPolicy>;
  /** `label` may be shown by the OS, so it is a field name, never a value. */
  copySecret(label: string, secret: string): Promise<CopyOutcome>;
  holdSecureForGeneratedValue(holding: boolean): Promise<boolean>;
  filterObscuredTouches(filtering: boolean): Promise<boolean>;
  reapplyWindowFlags(): Promise<boolean>;

  isProvisioned(): Promise<boolean>;
  /** Rejects `AlreadyProvisioned` on a second run: a new Vault Key would orphan every item. */
  provisionAccount(): Promise<boolean>;

  listItems(): Promise<ItemSummary[]>;
  /** Concealment is the screen's job, not this call's. */
  readItem(itemId: string): Promise<ItemDetail>;
  createItem(kind: string, fields: ItemField[]): Promise<string>;
  updateItem(itemId: string, kind: string, fields: ItemField[]): Promise<number>;
  deleteItem(itemId: string): Promise<void>;

  generatorLimits(): Promise<GeneratorLimits>;
  generatePassword(
    length: number,
    lowercase: boolean,
    uppercase: boolean,
    digits: boolean,
    symbols: boolean,
    excludeAmbiguous: boolean,
    requireOneOfEach: boolean,
  ): Promise<GeneratedValue>;
  generatePassphrase(
    words: number,
    separator: string,
    capitalise: boolean,
  ): Promise<GeneratedValue>;
}

const ChiavoraCore = requireNativeModule<ChiavoraCoreNativeModule>('ChiavoraCore');

export default ChiavoraCore;

/** The session is already gone when `listener` runs, so a screen should drop what it shows. */
export function onLock(listener: (reason: LockReason) => void): { remove: () => void } {
  return ChiavoraCore.addListener('onLock', (event: { reason: LockReason }) => {
    listener(event.reason);
  });
}

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
