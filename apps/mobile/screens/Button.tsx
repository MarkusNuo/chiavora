import { Pressable, Text } from 'react-native';

import { screenStyles as s } from './styles';

export function Button({
  label,
  onPress,
  disabled,
  tone,
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  tone?: 'primary' | 'quiet' | 'danger';
}) {
  const quiet = tone === 'quiet';
  return (
    <Pressable
      style={[
        s.button,
        quiet ? s.buttonQuiet : null,
        tone === 'danger' ? s.buttonDanger : null,
        disabled === true ? s.buttonDisabled : null,
      ]}
      onPress={onPress}
      disabled={disabled}
      accessibilityRole="button"
      accessibilityLabel={label}
    >
      <Text style={quiet && disabled !== true ? s.buttonLabelQuiet : s.buttonLabel}>{label}</Text>
    </Pressable>
  );
}
