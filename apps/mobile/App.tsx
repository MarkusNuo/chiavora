import { useCallback, useEffect, useRef, useState } from 'react';
import {
  AppState,
  Linking,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

import ChiavoraCore, {
  harnessDeriveOnce,
  type KeystoreReport,
  type VaultState,
} from './modules/chiavora-core';

export default function App() {
  const [lines, setLines] = useState<string[]>([]);
  const [password, setPassword] = useState('');
  const [state, setState] = useState<VaultState | null>(null);
  const [report, setReport] = useState<KeystoreReport | null>(null);
  const appState = useRef(AppState.currentState);
  const harnessStarted = useRef(false);

  const say = useCallback((line: string) => {
    console.log(`CHIAVORA-APP ${line}`);
    setLines((previous) => [...previous, line]);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const next = await ChiavoraCore.vaultState();
      setState(next);
      if (next.hasWrappedMuk) {
        setReport(await ChiavoraCore.keystoreReport());
      }
      return next;
    } catch (e) {
      say(`state: ${e}`);
      return null;
    }
  }, [say]);

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (next) => {
      appState.current = next;
    });
    return () => subscription.remove();
  }, []);

  useEffect(() => {
    void (async () => {
      say(`smoke: ${await ChiavoraCore.ffiSmoke()}`);
      const next = await refresh();
      say(
        next?.hasWrappedMuk
          ? 'a vault is enrolled on this device'
          : 'no vault enrolled — press Enrol',
      );

      const url = await Linking.getInitialURL();
      if (url?.includes('harness') && !harnessStarted.current) {
        harnessStarted.current = true;
        await runHarness(url, say);
      }
    })();
  }, [refresh, say]);

  const enrol = useCallback(async () => {
    try {
      await ChiavoraCore.enroll(
        bytes(password || DEMO_PASSWORD),
        bytes(DEMO_SECRET_KEY),
        bytes(DEMO_ACCOUNT_ID),
        bytes(DEMO_ACCOUNT_SALT),
        MEMORY_KIB,
        ITERATIONS,
      );
      say('enrolled: MUK wrapped under a fresh biometric key, Secret Key stored');
      await refresh();
    } catch (e) {
      say(`enrol failed: ${e}`);
    }
  }, [password, refresh, say]);

  const unlockBiometric = useCallback(async () => {
    try {
      const len = await ChiavoraCore.unlockWithBiometric();
      say(`UNLOCKED by biometric, muk_len=${len}`);
    } catch (e) {
      say(`biometric unlock refused: ${e}`);
      await refresh();
    }
  }, [refresh, say]);

  const unlockPassword = useCallback(async () => {
    try {
      const len = await ChiavoraCore.unlockWithPassword(
        bytes(password || DEMO_PASSWORD),
        bytes(DEMO_ACCOUNT_ID),
        bytes(DEMO_ACCOUNT_SALT),
        MEMORY_KIB,
        ITERATIONS,
      );
      say(`UNLOCKED by password, muk_len=${len}; MUK re-wrapped under a fresh biometric key`);
      await refresh();
    } catch (e) {
      say(`password unlock refused: ${e}`);
    }
  }, [password, refresh, say]);

  const forget = useCallback(async () => {
    await ChiavoraCore.forgetDevice();
    setReport(null);
    say('device forgotten: both keystore entries and both blobs removed');
    await refresh();
  }, [refresh, say]);

  const invalidated = state?.mukKeyInvalidated ?? false;

  return (
    <View style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Chiavora — unlock</Text>

        {invalidated ? (
          <Text style={styles.warning}>
            The biometric key was invalidated by a fingerprint change. Enter your account
            password — your Secret Key is still on this device, so the Emergency Kit is not
            needed.
          </Text>
        ) : null}

        <TextInput
          style={styles.input}
          placeholder="account password"
          autoCapitalize="none"
          autoCorrect={false}
          secureTextEntry
          value={password}
          onChangeText={setPassword}
        />

        <Button label="Enrol this device" onPress={enrol} />
        <Button
          label="Unlock with fingerprint"
          onPress={unlockBiometric}
          disabled={!state?.hasWrappedMuk || invalidated}
        />
        <Button label="Unlock with password" onPress={unlockPassword} disabled={!state?.hasSecretKey} />
        <Button label="Forget this device" onPress={forget} />

        {report ? (
          <View style={styles.report}>
            <Text style={styles.reportTitle}>Security</Text>
            <Text style={styles.line}>MUK key: {report.mukBacking}</Text>
            <Text style={styles.line}>
              {'  '}invalidated by a new fingerprint: {String(report.mukInvalidatedByEnrollment)}
            </Text>
            <Text style={styles.line}>Secret Key: {report.secretKeyBacking}</Text>
            <Text style={styles.line}>
              {'  '}invalidated by a new fingerprint: {String(report.secretKeyInvalidatedByEnrollment)}
              {report.secretKeyInvalidatedByEnrollment ? '  ← I8 VIOLATED' : '  (I8)'}
            </Text>
          </View>
        ) : null}

        {lines.map((line, index) => (
          // eslint-disable-next-line react/no-array-index-key -- an append-only log
          <Text key={index} style={styles.line}>
            {line}
          </Text>
        ))}
      </ScrollView>
    </View>
  );
}

function Button({
  label,
  onPress,
  disabled,
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
}) {
  return (
    <Pressable
      style={[styles.button, disabled === true ? styles.buttonDisabled : null]}
      onPress={onPress}
      disabled={disabled}
    >
      <Text style={styles.buttonLabel}>{label}</Text>
    </Pressable>
  );
}

async function runHarness(url: string, say: (line: string) => void): Promise<void> {
  const query = url.split('?')[1] ?? '';
  const params = new Map(
    query
      .split('&')
      .filter((pair) => pair.length > 0)
      .map((pair) => {
        const [key, value] = pair.split('=');
        return [key, decodeURIComponent(value ?? '')] as const;
      }),
  );
  const asInt = (key: string, fallback: number) => {
    const parsed = Number.parseInt(params.get(key) ?? '', 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  };
  const label = params.get('label') ?? 'unlabelled';
  const outcome = await harnessDeriveOnce(
    asInt('memoryKib', MEMORY_KIB),
    asInt('iterations', ITERATIONS),
    asInt('delayMs', 0),
  );
  if (!outcome) {
    say(`run '${label}': NO HARNESS IN THIS BUILD`);
    return;
  }
  console.log(
    `CHIAVORA-APP RESULT label=${label} completed=${outcome.completed}` +
      ` millis=${outcome.millis} oom_before=${outcome.oomScoreAdjBefore ?? '-'}`,
  );
  say(`run '${label}': ${outcome.completed ? 'COMPLETED' : 'REFUSED'} in ${outcome.millis} ms`);
}

/** The password crosses as bytes so `core` does the normalizing. */
function bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Fixed, published test values until signup exists; not credentials. */
const DEMO_PASSWORD = 'correct horse battery staple';
const DEMO_SECRET_KEY = 'CHV1-0000-0000-0000-0000-0000-0000-00XV';
const DEMO_ACCOUNT_ID = '0123456789abcdef';
const DEMO_ACCOUNT_SALT = '0123456789abcdef0123456789abcdef';

/** §2.1's measured parameters. */
const MEMORY_KIB = 256 * 1024;
const ITERATIONS = 4;

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#ffffff' },
  content: { padding: 24, paddingTop: 64 },
  title: { fontSize: 20, fontWeight: '600', marginBottom: 16 },
  warning: {
    backgroundColor: '#fff4e5',
    borderColor: '#e0a24a',
    borderWidth: 1,
    borderRadius: 6,
    padding: 12,
    marginBottom: 12,
    fontSize: 13,
  },
  input: {
    borderColor: '#cccccc',
    borderWidth: 1,
    borderRadius: 6,
    padding: 12,
    marginBottom: 12,
  },
  button: {
    backgroundColor: '#1f3a5f',
    borderRadius: 6,
    padding: 14,
    marginBottom: 8,
    alignItems: 'center',
  },
  buttonDisabled: { backgroundColor: '#9aa6b4' },
  buttonLabel: { color: '#ffffff', fontWeight: '600' },
  report: {
    marginTop: 16,
    marginBottom: 8,
    padding: 12,
    backgroundColor: '#f3f5f7',
    borderRadius: 6,
  },
  reportTitle: { fontWeight: '600', marginBottom: 6 },
  line: { fontFamily: 'monospace', fontSize: 12, marginBottom: 4 },
});
