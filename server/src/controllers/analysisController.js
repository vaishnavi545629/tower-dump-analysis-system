const { z } = require('zod');
const {
  getTowerRecords,
  trackNumber,
  detectSuspiciousNumbers,
  saveSuspiciousFlags,
  revealSuspiciousNumber,
  listSuspiciousFlags,
} = require('../services/analysisEngine');
const { writeAuditLog } = require('../utils/auditLog');
const { addMonitorEvent } = require('../utils/monitorStore');

/**
 * GET /api/analysis/records/:datasetId
 * Returns tower records. Investigators see masked numbers; admins see full numbers.
 */
async function getRecords(req, res) {
  const { uid, email, role } = req.user;
  const { datasetId } = req.params;

  const schema = z.object({
    towerId: z.string().optional(),
    location: z.string().optional(),
    limit: z.coerce.number().min(1).max(10000).default(1000),
    offset: z.coerce.number().min(0).default(0),
  });

  const parsed = schema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  try {
    const records = await getTowerRecords(datasetId, { role, ...parsed.data });
    addMonitorEvent({
      level: 'info',
      category: 'analysis',
      title: 'Records fetched',
      detail: `${records.length} records served for dataset ${datasetId}.`,
    });
    await writeAuditLog({
      userId: uid, email, role,
      action: 'analysis.records.fetch',
      target: datasetId,
      ip: req.ip,
      status: 'success',
      meta: { count: records.length },
    });
    return res.json({ records, count: records.length });
  } catch (err) {
    console.error('[getRecords]', err);
    return res.status(500).json({ error: 'Failed to fetch records' });
  }
}

/**
 * POST /api/analysis/track
 * Track a masked mobile number across towers.
 */
async function trackMobileNumber(req, res) {
  const { uid, email, role } = req.user;

  const schema = z.object({
    datasetId: z.string().min(1),
    mobileQuery: z.string().min(4), // masked form, e.g. XXXXXX3210
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  const { datasetId, mobileQuery } = parsed.data;

  try {
    const result = await trackNumber(datasetId, mobileQuery, role);
    addMonitorEvent({
      level: 'info',
      category: 'tracking',
      title: 'Tracking request',
      detail: `${email} tracked ${mobileQuery} in dataset ${datasetId}. Matches: ${result.count}.`,
    });
    await writeAuditLog({
      userId: uid, email, role,
      action: 'analysis.track',
      target: mobileQuery,
      ip: req.ip,
      status: 'success',
      meta: { datasetId, matches: result.count },
    });
    return res.json(result);
  } catch (err) {
    console.error('[trackMobileNumber]', err);
    return res.status(500).json({ error: 'Tracking failed' });
  }
}

/**
 * POST /api/analysis/detect-suspicious/:datasetId
 * Runs suspicious number detection. Admin or investigator.
 */
async function detectSuspicious(req, res) {
  const { uid, email, role } = req.user;
  const { datasetId } = req.params;

  try {
    const flags = await detectSuspiciousNumbers(datasetId);
    if (flags.length > 0) {
      await saveSuspiciousFlags(flags);
    }
    addMonitorEvent({
      level: 'success',
      category: 'analysis',
      title: 'Suspicious detection complete',
      detail: `${flags.length} suspicious flags generated for dataset ${datasetId}.`,
    });

    await writeAuditLog({
      userId: uid, email, role,
      action: 'analysis.detect_suspicious',
      target: datasetId,
      ip: req.ip,
      status: 'success',
      meta: { flagsFound: flags.length },
    });

    return res.json({ flagsFound: flags.length, flags });
  } catch (err) {
    console.error('[detectSuspicious]', err);
    return res.status(500).json({ error: 'Detection failed' });
  }
}

/**
 * GET /api/analysis/suspicious
 * Returns all suspicious flags (masked numbers only for all roles).
 */
async function getSuspiciousFlags(req, res) {
  const { uid, email, role } = req.user;

  try {
    const flags = listSuspiciousFlags().sort((a, b) => String(b.flaggedAt).localeCompare(String(a.flaggedAt)));
    addMonitorEvent({
      level: 'info',
      category: 'analysis',
      title: 'Suspicious flags listed',
      detail: `${flags.length} suspicious flags returned.`,
    });
    await writeAuditLog({ userId: uid, email, role, action: 'analysis.suspicious.list', ip: req.ip, status: 'success' });
    return res.json({ flags });
  } catch (err) {
    console.error('[getSuspiciousFlags]', err);
    return res.status(500).json({ error: 'Failed to fetch suspicious flags' });
  }
}

/**
 * POST /api/analysis/reveal/:flagId
 * Admin only. Decrypts a suspicious number with justification.
 */
async function revealNumber(req, res) {
  const { uid, email, role } = req.user;
  const { flagId } = req.params;

  const schema = z.object({
    justification: z.string().min(10, 'Justification must be at least 10 characters'),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  try {
    const result = await revealSuspiciousNumber(flagId, uid);
    addMonitorEvent({
      level: 'warn',
      category: 'reveal',
      title: 'Sensitive number revealed',
      detail: `${email} revealed suspicious number for flag ${flagId}.`,
    });

    await writeAuditLog({
      userId: uid, email, role,
      action: 'number.reveal',
      target: flagId,
      ip: req.ip,
      status: 'success',
      meta: {
        justification: parsed.data.justification,
        mobileMasked: result.mobileMasked,
      },
    });

    return res.json(result);
  } catch (err) {
    console.error('[revealNumber]', err);
    return res.status(500).json({ error: err.message || 'Reveal failed' });
  }
}

module.exports = {
  getRecords,
  trackMobileNumber,
  detectSuspicious,
  getSuspiciousFlags,
  revealNumber,
};
