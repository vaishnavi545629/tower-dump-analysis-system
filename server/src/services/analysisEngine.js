const { decrypt } = require('../utils/crypto');
const {
  listTowerRecords,
  replaceSuspiciousFlagsForDataset,
  listSuspiciousFlags,
  getSuspiciousFlag,
} = require('../utils/localStore');

const SUSPICIOUS_LOCATION_COUNT = 2;   // flag if seen across ≥2 distinct locations
const SUSPICIOUS_WINDOW_HOURS = 24;    // within this many hours

function normalizeDigits(value) {
  return String(value || '').replace(/\D/g, '');
}

/**
 * Fetches tower records for a dataset, applying optional filters.
 * Investigators receive masked numbers; admins receive decrypted numbers.
 *
 * @param {string} datasetId
 * @param {{ role: string, towerId?: string, location?: string, limit?: number, offset?: number }} opts
 */
async function getTowerRecords(datasetId, opts = {}) {
  const { role, towerId, location, limit = 100, offset = 0 } = opts;
  const docs = listTowerRecords(datasetId)
    .filter((record) => !towerId || record.towerId === towerId)
    .filter((record) => !location || record.location === location)
    .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)))
    .slice(offset, offset + limit);

  return docs.map((record) => sanitizeRecord(record, role));
}

/**
 * Tracks a masked number across all towers and timestamps.
 * Only admins may supply the full number; investigators supply the masked form
 * and only see masked results.
 *
 * @param {string} datasetId
 * @param {string} mobileQuery  - masked form (XXXXXX3210) for investigators
 * @param {'admin'|'investigator'} role
 */
async function trackNumber(datasetId, mobileQuery, role) {
  const queryDigits = normalizeDigits(mobileQuery);
  const records = listTowerRecords(datasetId)
    .filter((record) => {
      const maskedDigits = normalizeDigits(record.mobileMasked);
      if (role === 'admin') {
        try {
          const plaintextDigits = normalizeDigits(decrypt(record.mobileEncrypted));
          return plaintextDigits.includes(queryDigits);
        } catch {
          return maskedDigits.endsWith(queryDigits);
        }
      }
      return maskedDigits.endsWith(queryDigits);
    })
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)))
    .map((record) => sanitizeRecord(record, role));
  return {
    mobile: mobileQuery,
    count: records.length,
    towers: records.map((r) => ({ towerId: r.towerId, location: r.location, timestamp: r.timestamp })),
    records,
  };
}

/**
 * Detects numbers that appear across multiple distinct locations within a time window.
 * Returns a list of suspicious flags with masked numbers for all roles.
 *
 * @param {string} datasetId
 */
async function detectSuspiciousNumbers(datasetId) {
  // Group records by maskedMobile
  const byNumber = {};
  listTowerRecords(datasetId).forEach((r) => {
    if (!byNumber[r.mobileMasked]) byNumber[r.mobileMasked] = [];
    byNumber[r.mobileMasked].push(r);
  });

  const flagged = [];

  for (const [maskedMobile, records] of Object.entries(byNumber)) {
    records.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    const locations = [...new Set(records.map((r) => r.location))];
    if (locations.length < SUSPICIOUS_LOCATION_COUNT) continue;

    // Check if any span of records fits within the time window
    let suspicious = false;
    for (let i = 0; i < records.length; i++) {
      const windowStart = new Date(records[i].timestamp);
      const windowEnd = new Date(windowStart.getTime() + SUSPICIOUS_WINDOW_HOURS * 3600_000);
      const inWindow = records.filter(
        (r) => new Date(r.timestamp) >= windowStart && new Date(r.timestamp) <= windowEnd
      );
      const windowLocations = [...new Set(inWindow.map((r) => r.location))];
      if (windowLocations.length >= SUSPICIOUS_LOCATION_COUNT) {
        suspicious = true;
        break;
      }
    }

    if (!suspicious) continue;

    flagged.push({
      mobileMasked: maskedMobile,
      datasetId,
      locations,
      count: records.length,
      reason: `Appeared in ${locations.length} distinct locations within ${SUSPICIOUS_WINDOW_HOURS}h`,
      flaggedAt: new Date().toISOString(),
    });
  }

  return flagged;
}

/**
 * Saves suspicious flags to Firestore and returns them.
 */
async function saveSuspiciousFlags(flags) {
  const { v4: uuidv4 } = require('uuid');
  const saved = flags.map((flag) => ({ id: uuidv4(), ...flag }));
  if (saved[0]?.datasetId) replaceSuspiciousFlagsForDataset(saved[0].datasetId, saved);
  return saved;
}

/**
 * Admin-only: decrypt a suspicious flag's number.
 * Returns the plaintext number IN MEMORY only — never stored in plaintext.
 */
async function revealSuspiciousNumber(flagId, adminUid) {
  const flag = getSuspiciousFlag(flagId);
  if (!flag) throw new Error('Suspicious flag not found');

  // Fetch one record matching the masked number to get the encrypted value
  const record = listTowerRecords(flag.datasetId).find((entry) => entry.mobileMasked === flag.mobileMasked);
  if (!record) throw new Error('No matching record found for decryption');
  const plaintext = decrypt(record.mobileEncrypted);

  // Return in-memory only; caller must NOT persist this
  return {
    flagId,
    mobilePlaintext: plaintext,
    mobileMasked: flag.mobileMasked,
    reason: flag.reason,
    revealedBy: adminUid,
    revealedAt: new Date().toISOString(),
    warning: 'This number is returned in memory only. Do not log or persist plaintext.',
  };
}

/**
 * Strips sensitive fields from a record based on caller's role.
 */
function sanitizeRecord(record, role) {
  const base = {
    id: record.id,
    datasetId: record.datasetId,
    towerId: record.towerId,
    location: record.location,
    lat: record.lat,
    lng: record.lng,
    timestamp: record.timestamp,
    suspicious: record.suspicious,
    recordHash: record.recordHash,
  };

  if (role === 'admin') {
    // Admin gets decrypted number in memory
    try {
      base.mobileNumber = decrypt(record.mobileEncrypted);
    } catch {
      base.mobileNumber = record.mobileMasked; // fallback if decryption fails
    }
  } else {
    base.mobileNumber = record.mobileMasked;
  }

  return base;
}

module.exports = {
  getTowerRecords,
  trackNumber,
  detectSuspiciousNumbers,
  saveSuspiciousFlags,
  revealSuspiciousNumber,
  listSuspiciousFlags,
};
