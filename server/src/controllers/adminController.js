const { z } = require('zod');
const { getAuth } = require('../config/firebase');
const { writeAuditLog } = require('../utils/auditLog');
const { listAuditLogs, listUsers } = require('../utils/localStore');

// ── Audit Logs ────────────────────────────────────────────────────────────────

/**
 * GET /api/admin/audit-logs
 * Returns audit log entries with optional filters.
 */
async function getAuditLogs(req, res) {
  const schema = z.object({
    limit: z.coerce.number().min(1).max(500).default(100),
    action: z.string().optional(),
    userId: z.string().optional(),
    status: z.enum(['success', 'denied', 'error']).optional(),
  });

  const parsed = schema.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  try {
    let logs = listAuditLogs()
      .sort((a, b) => String(b.timestamp).localeCompare(String(a.timestamp)));
    if (parsed.data.action) logs = logs.filter((l) => l.action === parsed.data.action);
    if (parsed.data.userId) logs = logs.filter((l) => l.userId === parsed.data.userId);
    if (parsed.data.status) logs = logs.filter((l) => l.status === parsed.data.status);
    logs = logs.slice(0, parsed.data.limit);

    // Simple suspicious activity detection
    const deniedCount = logs.filter((l) => l.status === 'denied').length;
    const suspiciousActivity = deniedCount >= 10
      ? { alert: true, reason: `${deniedCount} denied/failed events detected in recent logs` }
      : null;

    return res.json({ logs, count: logs.length, suspiciousActivity });
  } catch (err) {
    console.error('[getAuditLogs]', err);
    return res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
}

// ── User Management ───────────────────────────────────────────────────────────

/**
 * GET /api/admin/users
 * Returns all user records from Firestore.
 */
async function getUsers(req, res) {
  try {
    const users = listUsers();
    return res.json({ users });
  } catch (err) {
    console.error('[getUsers]', err);
    return res.status(500).json({ error: 'Failed to fetch users' });
  }
}

/**
 * PATCH /api/admin/users/:uid/role
 * Updates a user's role.
 */
async function updateUserRole(req, res) {
  const { uid: adminUid, email, role } = req.user;
  const { uid: targetUid } = req.params;
  const db = getFirestore();

  const schema = z.object({ role: z.enum(['admin', 'investigator']) });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });

  try {
    await db.collection('users').doc(targetUid).update({ role: parsed.data.role });

    await writeAuditLog({
      userId: adminUid, email, role,
      action: 'admin.user.role_update',
      target: targetUid,
      ip: req.ip,
      status: 'success',
      meta: { newRole: parsed.data.role },
    });

    return res.json({ message: 'Role updated successfully' });
  } catch (err) {
    console.error('[updateUserRole]', err);
    return res.status(500).json({ error: 'Failed to update role' });
  }
}

/**
 * DELETE /api/admin/users/:uid
 * Disables (soft-delete) a user. Removes from Firestore; disables in Firebase Auth.
 */
async function disableUser(req, res) {
  const { uid: adminUid, email, role } = req.user;
  const { uid: targetUid } = req.params;

  try {
    const auth = getAuth();
    await auth.updateUser(targetUid, { disabled: true });

    const db = getFirestore();
    await db.collection('users').doc(targetUid).update({ disabled: true });

    await writeAuditLog({
      userId: adminUid, email, role,
      action: 'admin.user.disabled',
      target: targetUid,
      ip: req.ip,
      status: 'success',
    });

    return res.json({ message: 'User disabled successfully' });
  } catch (err) {
    console.error('[disableUser]', err);
    return res.status(500).json({ error: 'Failed to disable user' });
  }
}

module.exports = { getAuditLogs, getUsers, updateUserRole, disableUser };
