const MAX_EVENTS = 200;

const state = {
  startedAt: new Date().toISOString(),
  events: [],
};

function addMonitorEvent(event) {
  const entry = {
    id: `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
    time: new Date().toISOString(),
    level: event.level || 'info',
    category: event.category || 'system',
    title: event.title || 'Event',
    detail: event.detail || '',
    meta: event.meta || {},
  };
  state.events.unshift(entry);
  if (state.events.length > MAX_EVENTS) state.events.length = MAX_EVENTS;
  return entry;
}

function getMonitorSnapshot() {
  return {
    startedAt: state.startedAt,
    events: state.events,
  };
}

module.exports = { addMonitorEvent, getMonitorSnapshot };
