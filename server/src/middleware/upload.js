const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const QUARANTINE_DIR = path.resolve(__dirname, '../../quarantine');
const MAX_FILE_SIZE_MB = 50;
const ALLOWED_MIMETYPES = [
  'text/csv',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
];
const ALLOWED_EXTENSIONS = ['.csv', '.xls', '.xlsx'];

// Ensure quarantine directory exists
if (!fs.existsSync(QUARANTINE_DIR)) {
  fs.mkdirSync(QUARANTINE_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, QUARANTINE_DIR),
  filename: (req, file, cb) => {
    // Sanitize original name; prefix with UUID to prevent path traversal
    const safeOriginal = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${uuidv4()}_${safeOriginal}`);
  },
});

function fileFilter(req, file, cb) {
  const ext = path.extname(file.originalname).toLowerCase();
  const mimeOk = ALLOWED_MIMETYPES.includes(file.mimetype);
  const extOk = ALLOWED_EXTENSIONS.includes(ext);

  if (mimeOk || extOk) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type. Only CSV and Excel files are accepted.`), false);
  }
}

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: MAX_FILE_SIZE_MB * 1024 * 1024 },
});

/**
 * Deletes a file from quarantine after processing.
 */
function cleanupQuarantine(filePath) {
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }
  } catch (err) {
    console.error('[Upload] Failed to clean quarantine file:', err.message);
  }
}

module.exports = { upload, cleanupQuarantine, QUARANTINE_DIR };
