/*
  csv.js (CsvParseLite)
  Robust CSV parser designed for offline use and easy debugging.

  Supports:
    - RFC4180-style parsing
    - Quotes, commas, CRLF/LF newlines
    - Newlines inside quoted fields
    - Escaped quotes (""")

  Usage:
    const result = CsvParseLite.parse(text);
    result.data -> array of rows (arrays)
*/
(function () {
  'use strict';

  function parse(text, options) {
    const delimiter = options?.delimiter ?? ',';
    const quote = options?.quote ?? '"';

    const rows = [];
    const errors = [];

    let row = [];
    let field = '';
    let i = 0;
    let inQuotes = false;

    function pushField() {
      row.push(field);
      field = '';
    }

    function pushRow() {
      // Avoid pushing a trailing empty row for files ending with newline.
      if (row.length === 1 && row[0] === '' && rows.length === 0) {
        // Allow empty header row? We'll still include it.
      }
      rows.push(row);
      row = [];
    }

    function isNewline(ch) {
      return ch === '\n' || ch === '\r';
    }

    while (i < text.length) {
      const ch = text[i];

      if (inQuotes) {
        if (ch === quote) {
          const next = text[i + 1];
          if (next === quote) {
            // Escaped quote.
            field += quote;
            i += 2;
            continue;
          }
          // Closing quote.
          inQuotes = false;
          i += 1;
          continue;
        }

        // Any character inside quotes, including newlines.
        field += ch;
        i += 1;
        continue;
      }

      // Not in quotes
      if (ch === quote) {
        // Opening quote. If field has data, it's a malformed CSV but we'll still treat as quote start.
        inQuotes = true;
        i += 1;
        continue;
      }

      if (ch === delimiter) {
        pushField();
        i += 1;
        continue;
      }

      if (isNewline(ch)) {
        // End field and row.
        pushField();
        pushRow();

        // Consume CRLF as a single newline.
        if (ch === '\r' && text[i + 1] === '\n') i += 2;
        else i += 1;
        continue;
      }

      field += ch;
      i += 1;
    }

    // Flush remaining.
    if (inQuotes) {
      errors.push({
        type: 'UnclosedQuote',
        message: 'CSV ended while still inside a quoted field.',
      });
    }
    pushField();
    // If the file ended with newline, we already pushed an empty row above. We want to avoid
    // adding an extra blank row.
    const isTrailingBlankRow = row.length === 1 && row[0] === '' && rows.length > 0;
    if (!isTrailingBlankRow) pushRow();

    return { data: rows, errors };
  }

  window.CsvParseLite = Object.freeze({ parse });
})();
