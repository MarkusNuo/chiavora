import { useCallback, useEffect, useState } from 'react';
import { ScrollView, Text, TextInput, View } from 'react-native';

import ChiavoraCore, { type ItemField } from '../modules/chiavora-core';
import { Button } from './Button';
import { screenStyles as s } from './styles';

/** Changes wait for Save, because each save advances the generation and moves the anchor. */
export function ItemEditor({
  itemId,
  onSaved,
  onCancel,
}: {
  itemId: string | null;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const creating = itemId === null;
  const [kind, setKind] = useState('login');
  const [fields, setFields] = useState<ItemField[]>(blankLogin());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(creating);

  useEffect(() => {
    if (itemId === null) {
      return;
    }
    let live = true;
    void (async () => {
      try {
        const opened = await ChiavoraCore.readItem(itemId);
        if (live) {
          setKind(opened.kind);
          setFields([...opened.fields]);
          setLoaded(true);
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

  const edit = useCallback((name: string, value: string) => {
    setFields((current) =>
      current.map((field) => (field.name === name ? { ...field, value } : field)),
    );
  }, []);

  const save = useCallback(() => {
    setBusy(true);
    setError(null);
    void (async () => {
      try {
        if (itemId === null) {
          await ChiavoraCore.createItem(kind, fields);
        } else {
          await ChiavoraCore.updateItem(itemId, kind, fields);
        }
        onSaved();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    })();
  }, [itemId, kind, fields, onSaved]);

  const remove = useCallback(() => {
    if (itemId === null) {
      return;
    }
    setBusy(true);
    setError(null);
    void (async () => {
      try {
        await ChiavoraCore.deleteItem(itemId);
        onSaved();
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setBusy(false);
      }
    })();
  }, [itemId, onSaved]);

  return (
    <View style={s.screen}>
      <ScrollView contentContainerStyle={s.content}>
        <Text style={s.title}>{creating ? 'New item' : 'Edit item'}</Text>
        <Text style={s.subtitle}>{kind}</Text>

        {error !== null ? (
          <View style={s.error}>
            <Text style={s.errorText}>{error}</Text>
          </View>
        ) : null}

        {loaded
          ? fields.map((field) => (
              <View key={field.name} style={s.field}>
                <Text style={s.fieldName}>{field.name}</Text>
                <TextInput
                  style={s.input}
                  value={field.value}
                  onChangeText={(value) => {
                    edit(field.name, value);
                  }}
                  secureTextEntry={field.concealed}
                  autoCapitalize="none"
                  autoCorrect={false}
                  accessibilityLabel={field.name}
                />
              </View>
            ))
          : null}

        <View style={{ height: 8 }} />
        <Button label={busy ? 'Saving…' : 'Save'} onPress={save} disabled={busy || !loaded} />
        <Button label="Cancel" onPress={onCancel} tone="quiet" disabled={busy} />
        {creating ? null : (
          <Button label="Delete" onPress={remove} tone="danger" disabled={busy} />
        )}
      </ScrollView>
    </View>
  );
}

function blankLogin(): ItemField[] {
  return [
    { name: 'title', value: '', concealed: false },
    { name: 'username', value: '', concealed: false },
    { name: 'password', value: '', concealed: true },
    { name: 'url', value: '', concealed: false },
  ];
}
