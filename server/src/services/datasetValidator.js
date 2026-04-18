const { parse } = require('csv-parse/sync');
const XLSX = require('xlsx');
const path = require('path');

const REQUIRED_COLUMNS = ['mobile_number', 'tower_id', 'location', 'timestamp'];
const MOBILE_REGEX = /^[6-9][0-9]{9}$/;
const COLUMN_ALIASES = {
  mobile_number: ['mobile_number', 'mobile_no', 'mobileno', 'mobile', 'phone', 'phone_number'],
  tower_id: ['tower_id', 'tower'],
  location: ['location', 'place', 'area'],
  lat: ['lat', 'latitude'],
  lng: ['lng', 'longitude', 'long'],
  timestamp: ['timestamp', 'datetime', 'date_time', 'time_stamp'],
  dataset_id: ['dataset_id', 'dataset'],
};

/**
 * Parses a CSV or XLSX file and returns raw row objects.
 */
function parseFile(filePath, mimetype) {
  const ext = path.extname(filePath).toLowerCase();

  if (ext === '.csv' || mimetype === 'text/csv') {
    const fs = require('fs');
    const content = fs.readFileSync(filePath, 'utf8');
    return parse(content, { columns: true, skip_empty_lines: true, trim: true });
  }

  if (ext === '.xlsx' || ext === '.xls') {
    const workbook = XLSX.readFile(filePath);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    return XLSX.utils.sheet_to_json(sheet, { defval: '' });
  }

  throw new Error(`Unsupported file type: ${ext}`);
}

function normalizeHeader(key) {
  return String(key)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

function canonicalColumn(key) {
  const normalized = normalizeHeader(key);
  const match = Object.entries(COLUMN_ALIASES).find(([, aliases]) => aliases.includes(normalized));
  return match ? match[0] : normalized;
}

/**
 * Normalizes column names to lowercase with underscores.
 */
function normalizeRow(row) {
  const normalized = {};
  for (const key of Object.keys(row)) {
    normalized[canonicalColumn(key)] = String(row[key]).trim();
  }
  return normalized;
}

/**
 * Validates whether all required columns are present in the header.
 */
function validateColumns(rows) {
  if (!rows.length) throw new Error('File is empty');
  const sample = normalizeRow(rows[0]);
  const missing = REQUIRED_COLUMNS.filter((col) => !(col in sample));
  if (missing.length) {
    throw new Error(`Missing required columns: ${missing.join(', ')}`);
  }
}

/**
 * Validates and deduplicates rows.
 *
 * @returns {{
 *   validRows: object[],
 *   invalidRows: { row: number, data: object, reason: string }[],
 *   duplicatesRemoved: number,
 *   total: number
 * }}
 */
function validateRows(rawRows) {
  const seen = new Set();
  const validRows = [];
  const invalidRows = [];
  let duplicatesRemoved = 0;

  rawRows.forEach((rawRow, index) => {
    const row = normalizeRow(rawRow);
    const rowNum = index + 2; // 1-based, +1 for header

    // Mobile number format
    if (!MOBILE_REGEX.test(row.mobile_number)) {
      invalidRows.push({ row: rowNum, data: row, reason: 'Invalid mobile number format' });
      return;
    }

    // Timestamp — accept ISO 8601 or DD/MM/YYYY HH:MM:SS
    const ts = row.timestamp;
    const parsedDate = new Date(ts);
    if (isNaN(parsedDate.getTime())) {
      invalidRows.push({ row: rowNum, data: row, reason: 'Invalid timestamp format' });
      return;
    }

    // Tower ID and location must be non-empty
    if (!row.tower_id || !row.location) {
      invalidRows.push({ row: rowNum, data: row, reason: 'Missing tower_id or location' });
      return;
    }

    // Deduplication key: mobile + tower + timestamp
    const dedupKey = `${row.mobile_number}|${row.tower_id}|${row.timestamp}`;
    if (seen.has(dedupKey)) {
      duplicatesRemoved++;
      return;
    }
    seen.add(dedupKey);

    validRows.push(row);
  });

  return {
    validRows,
    invalidRows,
    duplicatesRemoved,
    total: rawRows.length,
  };
}

/**
 * Full dataset validation pipeline.
 * Returns a validation summary and the validated rows ready for encryption.
 */
function validateDataset(filePath, mimetype) {
  const rawRows = parseFile(filePath, mimetype);
  validateColumns(rawRows);
  const result = validateRows(rawRows);

  return {
    totalRows: result.total,
    validRows: result.validRows.length,
    invalidRows: result.invalidRows.length,
    duplicatesRemoved: result.duplicatesRemoved,
    invalidDetails: result.invalidRows.slice(0, 50), // cap to first 50 for response size
    validData: result.validRows,
  };
}

module.exports = { validateDataset };
