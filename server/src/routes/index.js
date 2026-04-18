const express = require('express');
const { verifyToken } = require('../middleware/auth');
const { requireRole } = require('../middleware/rbac');
const { upload } = require('../middleware/upload');

const { uploadDataset, getDatasets, getDataset, deleteDataset } = require('../controllers/datasetController');
const { getRecords, trackMobileNumber, detectSuspicious, getSuspiciousFlags, revealNumber } = require('../controllers/analysisController');
const { getAuditLogs, getUsers, updateUserRole, disableUser } = require('../controllers/adminController');
const { getMonitorSummary } = require('../controllers/monitorController');

const router = express.Router();

// ── Health ────────────────────────────────────────────────────────────────────
router.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));
router.get('/monitor/summary', getMonitorSummary);

// ── Datasets ─────────────────────────────────────────────────────────────────
router.post(
  '/datasets/upload',
  verifyToken,
  requireRole('admin'),
  upload.single('file'),
  uploadDataset
);

router.get('/datasets', verifyToken, getDatasets);
router.get('/datasets/:id', verifyToken, getDataset);
router.delete('/datasets/:id', verifyToken, requireRole('admin'), deleteDataset);

// ── Analysis ──────────────────────────────────────────────────────────────────
router.get('/analysis/records/:datasetId', verifyToken, getRecords);
router.post('/analysis/track', verifyToken, trackMobileNumber);
router.post('/analysis/detect-suspicious/:datasetId', verifyToken, detectSuspicious);
router.get('/analysis/suspicious', verifyToken, getSuspiciousFlags);

// Admin-only: reveal a suspicious number's decrypted value
router.post('/analysis/reveal/:flagId', verifyToken, requireRole('admin'), revealNumber);

// ── Admin ─────────────────────────────────────────────────────────────────────
router.get('/admin/audit-logs', verifyToken, requireRole('admin'), getAuditLogs);
router.get('/admin/users', verifyToken, requireRole('admin'), getUsers);
router.patch('/admin/users/:uid/role', verifyToken, requireRole('admin'), updateUserRole);
router.delete('/admin/users/:uid', verifyToken, requireRole('admin'), disableUser);

module.exports = router;
