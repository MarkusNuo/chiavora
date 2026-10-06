import { useCallback, useEffect, useState } from 'react';
import { AppState, Pressable, ScrollView, Text, View } from 'react-native';

import ChiavoraCore, { type ItemDetail as Detail } from '../modules/chiavora-core';
import { Button } from './Button';
import { screenStyles as s } from './styles';

/** A revealed field stays revealed until unmount or until the app stops being `active`. */
export function ItemDetail({
  itemId,
  onBack,
  onEdit,
}: {
  itemId: string;
  onBack: () => void;
  onEdit: (itemId: string) => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<ReadonlySet<string>>(new Set());
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void (async () => {
      try {
        const opened = await ChiavoraCore.readItem(itemId);
        if (live) {
          setDetail(opened);
        }
      } catch (e) {
        if (live) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    return () => {
      live = false;
    };
  }, [itemId]);

  // `inactive` counts too: on Android it arrives ahead of the recents switcher.
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (next) => {
      if (next !== 'active') {
        setRevealed(new Set());
      }
    });
    return () => {
      subscription.remove();
    };
  }, []);

  const copy = useCallback((name: string, value: string) => {
    void (async () => {
      const outcome = await ChiavoraCore.copySecret(name, value);
      setCopied(
        outcome.sensitiveFlag
          ? `${name} copied — cleared in ${outcome.ttlSeconds}s, hidden from clipboard previews`
          : `${name} copied — cleared in ${outcome.ttlSeconds}s. This Android version has no sensitive-clipboard flag, so the timer is the only protection.`,
      );
    })();
  }, []);

  const toggle = useCallback((name: string) => {
    setRevealed((current) => {
      const next = new Set(current);
      if (next.has(name)) {
        next.delete(name);
      } else {
        next.add(name);
      }
      return next;
    });
  }, []);

  return (
    <View style={s.screen}>
      <ScrollView contentContainerStyle={s.content}>
        <Text style={s.title}>{titleOf(detail)}</Text>
        <Text style={s.subtitle}>
          {detail === null ? 'Opening…' : detail.kind}
        </Text>

        {error !== null ? (
          <View style={s.error}>
            <Text style={s.errorText}>{error}</Text>
          </View>
        ) : null}

        {copied !== null ? (
          <View style={s.notice}>
            <Text style={s.noticeText}>{copied}</Text>
          </View>
        ) : null}

        {(detail?.fields ?? []).map((field) => {
          const shown = !field.concealed || revealed.has(field.name);
          return (
            <View key={field.name} style={s.field}>
              <Text style={s.fieldName}>{field.name}</Text>
              {shown ? (
                <Text
                  style={field.concealed ? s.fieldValueMono : s.fieldValue}
                  // A long-press copy would bypass the clipboard's TTL.
                  selectable={!field.concealed}
                >
                  {field.value}
                </Text>
              ) : (
                <Text style={s.fieldConcealed}>{'•'.repeat(12)}</Text>
              )}
              {field.concealed ? (
                <View style={{ flexDirection: 'row', gap: 8 }}>
                  <Pressable
                    style={s.reveal}
                    onPress={() => {
                      toggle(field.name);
                    }}
                    accessibilityRole="button"
                    accessibilityLabel={`${shown ? 'Hide' : 'Reveal'} ${field.name}`}
                  >
                    <Text style={s.revealLabel}>{shown ? 'Hide' : 'Reveal'}</Text>
                  </Pressable>
                  <Pressable
                    style={s.reveal}
                    onPress={() => {
                      copy(field.name, field.value);
                    }}
                    accessibilityRole="button"
                    accessibilityLabel={`Copy ${field.name}`}
                  >
                    <Text style={s.revealLabel}>Copy</Text>
                  </Pressable>
                </View>
              ) : null}
            </View>
          );
        })}

        <View style={{ height: 16 }} />
        <Button
          label="Edit"
          onPress={() => {
            onEdit(itemId);
          }}
          disabled={detail === null}
        />
        <Button label="Back" onPress={onBack} tone="quiet" />
      </ScrollView>
    </View>
  );
}

function titleOf(detail: Detail | null): string {
  if (detail === null) {
    return 'Item';
  }
  const title = detail.fields.find((field) => field.name === 'title')?.value ?? '';
  return title.length > 0 ? title : 'Untitled';
}
