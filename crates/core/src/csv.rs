//! RFC 4180 as exports write it: a leading BOM is skipped, ragged rows are delivered as is.

use std::io::BufRead;

use zeroize::Zeroizing;

use crate::import::{ImportError, MAX_FIELDS_PER_RECORD, MAX_RECORD_BYTES};

const BOM: &[u8] = b"\xEF\xBB\xBF";
const BLOCK: usize = 64 << 10;

pub type Row = Vec<Zeroizing<String>>;

pub fn parse<R: BufRead>(
    mut reader: R,
    mut on_row: impl FnMut(usize, Row) -> Result<(), ImportError>,
) -> Result<usize, ImportError> {
    let mut block = Zeroizing::new(vec![0_u8; BLOCK]);
    let mut field: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let mut row: Row = Vec::new();
    let mut rows = 0_usize;
    let mut row_bytes = 0_usize;
    let mut row_started = false;
    let mut at_field_start = true;
    let mut in_quotes = false;
    let mut quote_pending = false;
    let mut first_block = true;

    loop {
        let n = reader.read(&mut block)?;
        if n == 0 {
            break;
        }
        let mut chunk = block
            .get(..n)
            .ok_or(ImportError::Io(std::io::ErrorKind::Other))?;
        if first_block {
            first_block = false;
            if let Some(rest) = chunk.strip_prefix(BOM) {
                chunk = rest;
            }
        }
        for &byte in chunk {
            row_bytes += 1;
            if row_bytes > MAX_RECORD_BYTES {
                return Err(ImportError::RecordTooLong {
                    at: rows,
                    max: MAX_RECORD_BYTES,
                });
            }
            if in_quotes {
                if quote_pending {
                    quote_pending = false;
                    if byte == b'"' {
                        field.push(b'"');
                        continue;
                    }
                    in_quotes = false;
                    // The quote closed the field; `byte` is read as unquoted below.
                } else {
                    if byte == b'"' {
                        quote_pending = true;
                    } else {
                        field.push(byte);
                    }
                    continue;
                }
            }
            match byte {
                b'"' if at_field_start => {
                    in_quotes = true;
                    at_field_start = false;
                    row_started = true;
                }
                b',' => {
                    push_field(&mut row, &mut field, rows)?;
                    at_field_start = true;
                    row_started = true;
                }
                b'\n' => {
                    if row_started {
                        push_field(&mut row, &mut field, rows)?;
                        on_row(rows, std::mem::take(&mut row))?;
                        rows += 1;
                    }
                    row_bytes = 0;
                    row_started = false;
                    at_field_start = true;
                }
                b'\r' => {}
                _ => {
                    field.push(byte);
                    at_field_start = false;
                    row_started = true;
                }
            }
        }
    }
    // End of input: a row in progress is delivered, an open quote closed here.
    if row_started {
        push_field(&mut row, &mut field, rows)?;
        on_row(rows, row)?;
        rows += 1;
    }
    Ok(rows)
}

fn push_field(row: &mut Row, field: &mut Zeroizing<Vec<u8>>, at: usize) -> Result<(), ImportError> {
    if row.len() >= MAX_FIELDS_PER_RECORD {
        return Err(ImportError::TooManyFields {
            at,
            max: MAX_FIELDS_PER_RECORD,
        });
    }
    let text = Zeroizing::new(String::from_utf8_lossy(field).into_owned());
    field.clear();
    row.push(text);
    Ok(())
}

pub struct Header {
    names: Vec<String>,
}

impl core::fmt::Debug for Header {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Header({} columns)", self.names.len())
    }
}

impl Header {
    #[must_use]
    pub fn from_row(row: &Row) -> Self {
        Self {
            names: row.iter().map(|f| f.trim().to_ascii_lowercase()).collect(),
        }
    }

    #[must_use]
    pub fn positional(width: usize) -> Self {
        Self {
            names: (1..=width).map(|n| format!("column {n}")).collect(),
        }
    }

    #[must_use]
    pub fn index_of(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|n| n == name)
    }

    #[must_use]
    pub fn name_at(&self, index: usize) -> String {
        match self.names.get(index) {
            Some(name) => name.clone(),
            None => format!("column {}", index + 1),
        }
    }

    #[must_use]
    pub fn width(&self) -> usize {
        self.names.len()
    }
}

#[must_use]
pub fn row_has_columns(row: &Row, required: &[&str]) -> bool {
    let header = Header::from_row(row);
    required.iter().all(|name| header.index_of(name).is_some())
}

#[must_use]
pub fn column<'a>(header: &Header, row: &'a Row, name: &str) -> &'a str {
    match header.index_of(name).and_then(|i| row.get(i)) {
        Some(value) => value,
        None => "",
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn rows(text: &[u8]) -> Vec<Vec<String>> {
        let mut out = Vec::new();
        parse(Cursor::new(text), |_, row| {
            out.push(row.iter().map(|f| f.as_str().to_owned()).collect());
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn quoted_fields_keep_commas_newlines_and_doubled_quotes() {
        let got = rows(b"a,\"b,c\",\"line1\nline2\",\"say \"\"hi\"\"\"\r\nx,y\n");
        assert_eq!(
            got,
            vec![
                vec!["a", "b,c", "line1\nline2", "say \"hi\""],
                vec!["x", "y"],
            ]
        );
    }

    #[test]
    fn a_bom_blank_lines_and_a_missing_final_newline_are_handled() {
        let got = rows(b"\xEF\xBB\xBFname,url\n\n\nlast,row");
        assert_eq!(got, vec![vec!["name", "url"], vec!["last", "row"]]);
    }

    #[test]
    fn an_unterminated_quote_delivers_the_row_rather_than_dropping_it() {
        let got = rows(b"a,\"never closed\nmore");
        assert_eq!(got, vec![vec!["a", "never closed\nmore"]]);
    }

    #[test]
    fn a_header_maps_by_name_and_positional_names_fill_the_gaps() {
        let row: Row = vec!["URL".to_owned().into(), " Password".to_owned().into()];
        let header = Header::from_row(&row);
        assert_eq!(header.index_of("url"), Some(0));
        assert_eq!(header.index_of("password"), Some(1));
        assert_eq!(header.name_at(5), "column 6");
        assert!(row_has_columns(&row, &["url", "password"]));
        assert!(!row_has_columns(&row, &["url", "username"]));
        let data: Row = vec!["https://x.test".to_owned().into()];
        assert_eq!(column(&header, &data, "url"), "https://x.test");
        assert_eq!(
            column(&header, &data, "password"),
            "",
            "a short row reads as empty, not as a panic"
        );
    }
}
