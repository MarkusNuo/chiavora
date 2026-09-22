import { StyleSheet } from 'react-native';

export const screenStyles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: '#ffffff' },
  content: { padding: 24, paddingTop: 64, paddingBottom: 48 },
  title: { fontSize: 20, fontWeight: '600', marginBottom: 4 },
  subtitle: { fontSize: 13, color: '#5a6672', marginBottom: 16 },

  row: {
    borderBottomColor: '#e4e8ec',
    borderBottomWidth: 1,
    paddingVertical: 14,
  },
  rowTitle: { fontSize: 16, fontWeight: '600', color: '#1f3a5f' },
  rowUsername: { fontSize: 13, color: '#5a6672', marginTop: 2 },
  rowEmpty: { fontSize: 13, color: '#9aa6b4', marginTop: 2, fontStyle: 'italic' },
  rowKind: { fontSize: 11, color: '#9aa6b4', marginTop: 2, textTransform: 'uppercase' },

  field: { marginBottom: 14 },
  fieldName: { fontSize: 11, color: '#5a6672', textTransform: 'uppercase', marginBottom: 4 },
  fieldValue: { fontSize: 15, color: '#1a1a1a' },
  fieldValueMono: { fontSize: 15, fontFamily: 'monospace', color: '#1a1a1a' },
  fieldConcealed: { fontSize: 15, fontFamily: 'monospace', color: '#9aa6b4', letterSpacing: 2 },

  input: {
    borderColor: '#cccccc',
    borderWidth: 1,
    borderRadius: 6,
    padding: 12,
    marginBottom: 12,
    fontSize: 15,
  },

  button: {
    backgroundColor: '#1f3a5f',
    borderRadius: 6,
    padding: 14,
    marginBottom: 8,
    alignItems: 'center',
  },
  buttonQuiet: { backgroundColor: '#ffffff', borderColor: '#1f3a5f', borderWidth: 1 },
  buttonDanger: { backgroundColor: '#c0392b' },
  buttonDisabled: { backgroundColor: '#9aa6b4', borderColor: '#9aa6b4' },
  buttonLabel: { color: '#ffffff', fontWeight: '600' },
  buttonLabelQuiet: { color: '#1f3a5f', fontWeight: '600' },

  reveal: {
    alignSelf: 'flex-start',
    paddingVertical: 6,
    paddingHorizontal: 10,
    borderRadius: 4,
    borderColor: '#1f3a5f',
    borderWidth: 1,
    marginTop: 6,
  },
  revealLabel: { color: '#1f3a5f', fontSize: 12, fontWeight: '600' },

  notice: {
    backgroundColor: '#f3f5f7',
    borderRadius: 6,
    padding: 12,
    marginBottom: 16,
  },
  noticeText: { fontSize: 13, color: '#4a5560', lineHeight: 19 },
  error: {
    backgroundColor: '#fdf2f0',
    borderColor: '#c0392b',
    borderWidth: 1,
    borderRadius: 6,
    padding: 12,
    marginBottom: 16,
  },
  errorText: { fontSize: 13, color: '#8e2a1f', lineHeight: 19 },
  empty: { fontSize: 14, color: '#5a6672', paddingVertical: 24, textAlign: 'center' },
});
