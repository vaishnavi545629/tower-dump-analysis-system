const { v4: uuidv4 } = require('uuid');
const { addAuditLog } = require('./localStore');

/**
 * Writes an audit log entry to Firestore.
 *
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.email
 * @param {string} params.role
 * @param {string} params.action   - e.g. 'dataset.upload', 'number.reveal', 'auth.denied'
 * @param {string} [params.target] - resource ID or description
 * @param {string} [params.ip]
 * @param {'success'|'denied'|'error'} params.status
 * @param {object} [params.meta]   - any extra structured data
 */
async function writeAuditLog({ userId, email, role, action, target, ip, status, meta }) {
  const entry = {
    id: uuidv4(),
    userId: userId || 'anonymous',
    email: email || '',
    role: role || 'unknown',
    action,
    target: target || '',
    timestamp: new Date().toISOString(),
    ip: ip || '',
    status,
    meta: meta || {},
  };

  try {
    addAuditLog(entry);
  } catch (err) {
    // Audit failures must never crash the main request
    console.error('[AuditLog] Failed to write audit log:', err.message);
  }

  return entry;
}

module.exports = { writeAuditLog };
