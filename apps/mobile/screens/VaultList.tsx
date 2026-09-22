import { useCallback, useEffect, useState } from 'react';
import { Pressable, ScrollView, Text, View } from 'react-native';

import ChiavoraCore, { type ItemSummary } from '../modules/chiavora-core';
import { Button } from './Button';
import { screenStyles as s } from './styles';

export function VaultList({
  onOpen,
  onCreate,
  onLock,
}: {
  onOpen: (itemId: string) => void;
  onCreate: () => void;
  onLock: () => void;
}) {
  const [items, setItems] = useState<ItemSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setItems(await ChiavoraCore.listItems());
    } catch (e) {
      // Shown, so a vault that would not open does not look empty.
      setItems(null);
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <View style={s.screen}>
      <ScrollView contentContainerStyle={s.content}>
        <Text style={s.title}>Vault</Text>
        <Text style={s.subtitle}>
          {items === null ? '' : `${items.length} item${items.length === 1 ? '' : 's'}`}
        </Text>

        {error !== null ? (
          <View style={s.error}>
            <Text style={s.errorText}>{error}</Text>
          </View>
        ) : null}

        {items !== null && items.length === 0 ? (
          <Text style={s.empty}>Nothing saved yet.</Text>
        ) : null}

        {(items ?? []).map((item) => (
          <Pressable
            key={item.itemId}
            style={s.row}
            onPress={() => {
              onOpen(item.itemId);
            }}
            accessibilityRole="button"
            accessibilityLabel={item.title.length > 0 ? item.title : 'Untitled item'}
          >
            <Text style={s.rowTitle}>{item.title.length > 0 ? item.title : 'Untitled'}</Text>
            {item.username.length > 0 ? (
              <Text style={s.rowUsername}>{item.username}</Text>
            ) : (
              <Text style={s.rowEmpty}>no username</Text>
            )}
            <Text style={s.rowKind}>{item.kind}</Text>
          </Pressable>
        ))}

        <View style={{ height: 24 }} />
        <Button label="New item" onPress={onCreate} />
        <Button label="Refresh" onPress={() => void load()} tone="quiet" />
        <Button label="Lock" onPress={onLock} tone="quiet" />
      </ScrollView>
    </View>
  );
}
