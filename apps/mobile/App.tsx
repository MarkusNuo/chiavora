import { useEffect, useRef, useState } from 'react';
import { AppState, Linking, ScrollView, StyleSheet, Text, View } from 'react-native';

import ChiavoraCore, { harnessDeriveOnce } from './modules/chiavora-core';

export default function App() {
  const [lines, setLines] = useState<string[]>([]);
  const appState = useRef(AppState.currentState);
  const started = useRef(false);

  const say = (line: string) => {
    console.log(`CHIAVORA-APP ${line}`);
    setLines((previous) => [...previous, line]);
  };

  useEffect(() => {
    const subscription = AppState.addEventListener('change', (next) => {
      appState.current = next;
      console.log(`CHIAVORA-APP LIFECYCLE appState=${next}`);
    });
    return () => subscription.remove();
  }, []);

  useEffect(() => {
    if (started.current) {
      return;
    }
    started.current = true;
    void (async () => {
      say(`smoke: ${await ChiavoraCore.ffiSmoke()}`);
      say(`harness present: ${ChiavoraCore.hasHarness()}`);

      const url = await Linking.getInitialURL();
      const run = parseRun(url);
      if (!run) {
        say('no run requested: launch with a chiavora://harness?... deep link');
        return;
      }

      say(
        `run '${run.label}': m=${run.memoryKib / 1024} MiB t=${run.iterations},` +
          ` starting in ${run.delayMs} ms (native wait)`,
      );

      const appStateAtCall = appState.current;
      const outcome = await harnessDeriveOnce(run.memoryKib, run.iterations, run.delayMs);
      const appStateAtReturn = appState.current;
      if (!outcome) {
        say(`run '${run.label}': NO HARNESS IN THIS BUILD — nothing was measured`);
        return;
      }
      console.log(
        `CHIAVORA-APP RESULT label=${run.label} completed=${outcome.completed}` +
          ` millis=${outcome.millis} refusal=${outcome.refusal ?? '-'}` +
          ` oom_before=${outcome.oomScoreAdjBefore ?? '-'}` +
          ` oom_after=${outcome.oomScoreAdjAfter ?? '-'}` +
          ` mem_avail_kib_before=${outcome.memAvailableKibBefore ?? '-'}` +
          ` mem_avail_kib_after=${outcome.memAvailableKibAfter ?? '-'}` +
          ` m_kib=${outcome.memoryKib} t=${outcome.iterations}` +
          ` app_state_at_call=${appStateAtCall} app_state_at_return=${appStateAtReturn}`,
      );

      say(
        outcome.completed
          ? `run '${run.label}': COMPLETED in ${outcome.millis} ms,` +
              ` oom_score_adj ${outcome.oomScoreAdjBefore} -> ${outcome.oomScoreAdjAfter}`
          : `run '${run.label}': REFUSED (${outcome.refusal}) after ${outcome.millis} ms`,
      );
    })();
  }, []);

  return (
    <View style={styles.screen}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Chiavora — </Text>

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

interface Run {
  readonly memoryKib: number;
  readonly iterations: number;
  readonly delayMs: number;
  readonly label: string;
}

function parseRun(url: string | null): Run | null {
  if (!url || !url.includes('harness')) {
    return null;
  }
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
  return {
    memoryKib: asInt('memoryKib', 256 * 1024),
    iterations: asInt('iterations', 4),
    delayMs: asInt('delayMs', 0),
    label: params.get('label') ?? 'unlabelled',
  };
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#ffffff' },
  content: { padding: 24, paddingTop: 64 },
  title: { fontSize: 18, fontWeight: '600', marginBottom: 12 },
  line: { fontFamily: 'monospace', fontSize: 12, marginBottom: 4 },
});
