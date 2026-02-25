const AuditLog = require('./auditLog.model');

async function audit({ actorId, action, target, outcome = 'success', meta = {}, correlationId = '' }) {
  try {
    await AuditLog.create({ actorId, action, target, outcome, meta, correlationId });
  } catch {
    // best effort
  }
}

module.exports = { audit };
