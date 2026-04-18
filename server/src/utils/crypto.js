const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128-bit IV
const TAG_LENGTH = 16; // 128-bit auth tag

/**
 * Returns the 32-byte AES key from the environment variable.
 * The env var is expected as a 64-character hex string.
 */
function getEncryptionKey() {
  const hexKey = process.env.AES_ENCRYPTION_KEY;
  if (!hexKey || hexKey.length !== 64) {
    throw new Error('AES_ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hexKey, 'hex');
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Returns a colon-delimited string: iv:authTag:ciphertext (all hex-encoded).
 */
function encrypt(plaintext) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return [iv.toString('hex'), authTag.toString('hex'), encrypted.toString('hex')].join(':');
}

/**
 * Decrypts an AES-256-GCM encrypted string produced by encrypt().
 * Returns the original plaintext.
 */
function decrypt(encryptedString) {
  const key = getEncryptionKey();
  const [ivHex, authTagHex, ciphertextHex] = encryptedString.split(':');

  if (!ivHex || !authTagHex || !ciphertextHex) {
    throw new Error('Invalid encrypted string format');
  }

  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const ciphertext = Buffer.from(ciphertextHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

/**
 * Masks a mobile number, showing only the last 4 digits.
 * e.g. "9876543210" → "XXXXXX3210"
 */
function maskMobileNumber(mobile) {
  if (!mobile || mobile.length < 4) return 'XXXXXXXX';
  return 'X'.repeat(mobile.length - 4) + mobile.slice(-4);
}

/**
 * Computes a SHA-256 integrity hash for a tower record.
 * record_hash = SHA256(mobileNumber + timestamp + towerId)
 */
function computeRecordHash(mobileNumber, timestamp, towerId) {
  return crypto
    .createHash('sha256')
    .update(`${mobileNumber}${timestamp}${towerId}`)
    .digest('hex');
}

/**
 * Verifies a stored record hash against recomputed values.
 * Returns { valid: boolean, reason: string }
 */
function verifyRecordHash(storedHash, mobileNumber, timestamp, towerId) {
  const recomputed = computeRecordHash(mobileNumber, timestamp, towerId);
  const valid = crypto.timingSafeEqual(
    Buffer.from(storedHash, 'hex'),
    Buffer.from(recomputed, 'hex')
  );
  return {
    valid,
    reason: valid ? 'Integrity OK' : 'Hash mismatch — possible tampering detected',
  };
}

module.exports = {
  encrypt,
  decrypt,
  maskMobileNumber,
  computeRecordHash,
  verifyRecordHash,
};
