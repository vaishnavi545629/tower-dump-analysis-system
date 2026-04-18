const { writeAuditLog } = require('../utils/auditLog');
const { addMonitorEvent } = require('../utils/monitorStore');

/**
 * Returns middleware that enforces a required role.
 * Must be used AFTER verifyToken.
 *
 * Usage: router.post('/upload', verifyToken, requireRole('admin'), handler)
 */
function requireRole(...allowedRoles) {
  return async (req, res, next) => {
    const { uid, email, role } = req.user;

    if (!allowedRoles.includes(role)) {
      addMonitorEvent({
        level: 'warn',
        category: 'rbac',
        title: 'Access denied',
        detail: `${email || uid} attempted ${req.path} with role ${role}. Required: ${allowedRoles.join(', ')}`,
      });
      await writeAuditLog({
        userId: uid,
        email,
        role,
        action: 'rbac.access_denied',
        target: req.path,
        ip: req.ip,
        status: 'denied',
        meta: { requiredRoles: allowedRoles },
      });
      return res.status(403).json({
        error: `Access denied. Required role: ${allowedRoles.join(' or ')}`,
      });
    }

    addMonitorEvent({
      level: 'info',
      category: 'rbac',
      title: 'Role check passed',
      detail: `${email || uid} authorized for ${req.path} as ${role}.`,
    });
    next();
  };
}

module.exports = { requireRole };
