const { getMonitorSnapshot } = require('../utils/monitorStore');
const { getCounts } = require('../utils/localStore');

async function getMonitorSummary(req, res) {
  const monitor = getMonitorSnapshot();
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  return res.json({
    status: 'ok',
    startedAt: monitor.startedAt,
    counts: getCounts(),
    recentEvents: monitor.events.slice(0, 40),
  });
}

module.exports = { getMonitorSummary };
