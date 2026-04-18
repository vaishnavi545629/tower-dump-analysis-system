const { v4: uuidv4 } = require('uuid');
const { validateDataset } = require('../services/datasetValidator');
const { scanFile } = require('../services/malwareScan');
const { encrypt, maskMobileNumber, computeRecordHash } = require('../utils/crypto');
const { writeAuditLog } = require('../utils/auditLog');
const { cleanupQuarantine } = require('../middleware/upload');
const { addMonitorEvent } = require('../utils/monitorStore');
const {
  addDataset,
  listDatasets,
  getDataset: getStoredDataset,
  addTowerRecords,
  deleteDatasetCascade,
} = require('../utils/localStore');

/**
 * POST /api/datasets/upload
 * Admin only. Runs the full pipeline:
 *   quarantine → scan → validate → encrypt → store → audit
 */
async function uploadDataset(req, res) {
  const { uid, email, role } = req.user;
  const file = req.file;

  if (!file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const pipeline = [];

  try {
    pipeline.push({ step: 'upload_received', status: 'complete', real: true });
    pipeline.push({ step: 'quarantine', status: 'complete', real: true, path: file.path });
    addMonitorEvent({
      level: 'info',
      category: 'upload',
      title: 'Upload received',
      detail: `${email} uploaded ${file.originalname}.`,
    });

    // ── Step 1: Malware scan ───────────────────────────────────────────────
    const scanResult = await scanFile(file.path);
    addMonitorEvent({
      level: scanResult.clean ? 'success' : 'error',
      category: 'scan',
      title: 'Malware scan finished',
      detail: scanResult.detail,
    });
    pipeline.push({
      step: 'malware_scan',
      status: scanResult.clean ? 'complete' : 'rejected',
      real: !scanResult.simulated,
      simulated: scanResult.simulated,
      detail: scanResult.detail,
    });

    if (!scanResult.clean) {
      cleanupQuarantine(file.path);
      await writeAuditLog({ userId: uid, email, role, action: 'dataset.upload.infected',
        target: file.originalname, ip: req.ip, status: 'denied',
        meta: { scanDetail: scanResult.detail } });
      return res.status(422).json({ error: 'File rejected by malware scanner', detail: scanResult.detail });
    }

    // ── Step 2: Validate CSV/XLSX ──────────────────────────────────────────
    const validation = validateDataset(file.path, file.mimetype);
    addMonitorEvent({
      level: 'success',
      category: 'validation',
      title: 'Dataset validated',
      detail: `${validation.validRows} valid rows, ${validation.invalidRows} invalid rows, ${validation.duplicatesRemoved} duplicates removed.`,
    });
    pipeline.push({
      step: 'validation_complete',
      status: 'complete',
      real: true,
      summary: {
        totalRows: validation.totalRows,
        validRows: validation.validRows,
        invalidRows: validation.invalidRows,
        duplicatesRemoved: validation.duplicatesRemoved,
      },
    });

    if (validation.validRows === 0) {
      cleanupQuarantine(file.path);
      return res.status(422).json({
        error: 'No valid rows found in dataset',
        validationSummary: {
          totalRows: validation.totalRows,
          validRows: validation.validRows,
          invalidRows: validation.invalidRows,
          duplicatesRemoved: validation.duplicatesRemoved,
          invalidDetails: validation.invalidDetails,
        },
      });
    }

    // ── Step 3: Encrypt and hash records ──────────────────────────────────
    const datasetId = uuidv4();
    const records = [];

    for (const row of validation.validData) {
      const recordId = uuidv4();
      const mobileEncrypted = encrypt(row.mobile_number);
      const mobileMasked = maskMobileNumber(row.mobile_number);
      const recordHash = computeRecordHash(row.mobile_number, row.timestamp, row.tower_id);

      const record = {
        id: recordId,
        datasetId,
        sourceDatasetId: row.dataset_id || null,
        mobileEncrypted,
        mobileMasked,
        towerId: row.tower_id,
        location: row.location,
        lat: Number.isFinite(parseFloat(row.lat)) ? parseFloat(row.lat) : null,
        lng: Number.isFinite(parseFloat(row.lng)) ? parseFloat(row.lng) : null,
        timestamp: row.timestamp,
        recordHash,
        suspicious: false,
      };

      records.push(record);
    }

    pipeline.push({ step: 'encryption_complete', status: 'complete', real: true });
    pipeline.push({ step: 'hashing_complete', status: 'complete', real: true });
    addMonitorEvent({
      level: 'success',
      category: 'crypto',
      title: 'Encryption and hashing complete',
      detail: `${records.length} records encrypted and hashed before storage.`,
    });

    // ── Step 4: Write dataset metadata ────────────────────────────────────
    const datasetMeta = {
      id: datasetId,
      name: req.body.name || file.originalname,
      fileName: file.originalname,
      uploadedBy: uid,
      uploadedByEmail: email,
      uploadedAt: new Date().toISOString(),
      status: 'active',
      totalRecords: validation.totalRows,
      validRecords: validation.validRows,
      invalidRecords: validation.invalidRows,
      duplicatesRemoved: validation.duplicatesRemoved,
    };

    addTowerRecords(records);
    addDataset(datasetMeta);
    pipeline.push({ step: 'database_write_complete', status: 'complete', real: true });
    addMonitorEvent({
      level: 'success',
      category: 'database',
      title: 'Dataset stored',
      detail: `Dataset ${datasetMeta.name} saved with ${records.length} records.`,
    });

    // ── Step 5: Audit log ─────────────────────────────────────────────────
    await writeAuditLog({
      userId: uid, email, role,
      action: 'dataset.upload',
      target: datasetId,
      ip: req.ip,
      status: 'success',
      meta: { fileName: file.originalname, validRecords: validation.validRows },
    });
    pipeline.push({ step: 'audit_log_written', status: 'complete', real: true });
    addMonitorEvent({
      level: 'info',
      category: 'audit',
      title: 'Audit log written',
      detail: `Upload audit entry recorded for ${datasetMeta.name}.`,
    });

    // ── Cleanup quarantine ────────────────────────────────────────────────
    cleanupQuarantine(file.path);

    return res.status(201).json({
      message: 'Dataset uploaded and processed successfully',
      dataset: datasetMeta,
      validationSummary: {
        totalRows: validation.totalRows,
        validRows: validation.validRows,
        invalidRows: validation.invalidRows,
        duplicatesRemoved: validation.duplicatesRemoved,
        invalidDetails: validation.invalidDetails,
      },
      pipeline,
    });

  } catch (err) {
    addMonitorEvent({
      level: 'error',
      category: 'upload',
      title: 'Upload failed',
      detail: err.message,
    });
    cleanupQuarantine(file?.path);
    console.error('[uploadDataset] Error:', err);
    await writeAuditLog({
      userId: uid, email, role,
      action: 'dataset.upload.error',
      target: file?.originalname,
      ip: req.ip,
      status: 'error',
      meta: { error: err.message },
    });
    return res.status(500).json({ error: 'Upload processing failed', detail: err.message });
  }
}

/**
 * GET /api/datasets
 * Returns all datasets (summary only — no records).
 */
async function getDatasets(req, res) {
  const { uid, email, role } = req.user;

  try {
    const datasets = listDatasets().sort((a, b) => String(b.uploadedAt).localeCompare(String(a.uploadedAt)));

    await writeAuditLog({ userId: uid, email, role, action: 'datasets.list', ip: req.ip, status: 'success' });
    return res.json({ datasets });
  } catch (err) {
    console.error('[getDatasets]', err);
    return res.status(500).json({ error: 'Failed to fetch datasets' });
  }
}

/**
 * GET /api/datasets/:id
 * Returns a single dataset metadata object.
 */
async function getDataset(req, res) {
  const { id } = req.params;

  try {
    const dataset = getStoredDataset(id);
    if (!dataset) return res.status(404).json({ error: 'Dataset not found' });
    return res.json({ dataset });
  } catch (err) {
    console.error('[getDataset]', err);
    return res.status(500).json({ error: 'Failed to fetch dataset' });
  }
}

/**
 * DELETE /api/datasets/:id
 * Admin only. Removes dataset metadata, related tower records, and related suspicious flags.
 */
async function deleteDataset(req, res) {
  const { uid, email, role } = req.user;
  const { id } = req.params;

  try {
    const deleted = deleteDatasetCascade(id);
    if (!deleted.dataset) {
      return res.status(404).json({ error: 'Dataset not found' });
    }

    addMonitorEvent({
      level: 'warn',
      category: 'database',
      title: 'Dataset deleted',
      detail: `${deleted.dataset.name || id} deleted with ${deleted.recordsDeleted} records removed.`,
    });
    await writeAuditLog({
      userId: uid,
      email,
      role,
      action: 'dataset.delete',
      target: id,
      ip: req.ip,
      status: 'success',
      meta: { recordsDeleted: deleted.recordsDeleted, flagsDeleted: deleted.flagsDeleted },
    });

    return res.json({
      message: 'Dataset deleted successfully',
      deleted: {
        datasetId: id,
        recordsDeleted: deleted.recordsDeleted,
        flagsDeleted: deleted.flagsDeleted,
      },
    });
  } catch (err) {
    console.error('[deleteDataset]', err);
    return res.status(500).json({ error: 'Failed to delete dataset' });
  }
}

module.exports = { uploadDataset, getDatasets, getDataset, deleteDataset };
