const fs = require('fs');
const path = require('path');

const STORE_PATH = path.resolve(__dirname, '..', '..', 'local-data.json');

const DEFAULT_STATE = {
  users: [],
  datasets: [],
  tower_records: [],
  audit_logs: [],
  suspicious_flags: [],
};

function ensureStore() {
  if (!fs.existsSync(STORE_PATH)) {
    fs.writeFileSync(STORE_PATH, JSON.stringify(DEFAULT_STATE, null, 2), 'utf8');
  }
}

function readState() {
  ensureStore();
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    return { ...DEFAULT_STATE, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_STATE };
  }
}

function writeState(state) {
  fs.writeFileSync(STORE_PATH, JSON.stringify(state, null, 2), 'utf8');
}

function updateState(mutator) {
  const state = readState();
  const nextState = mutator(state) || state;
  writeState(nextState);
  return nextState;
}

function upsertUser(user) {
  updateState((state) => {
    const users = state.users.filter((entry) => entry.uid !== user.uid);
    users.push(user);
    return { ...state, users };
  });
}

function listUsers() {
  return readState().users;
}

function addDataset(dataset) {
  updateState((state) => ({ ...state, datasets: [dataset, ...state.datasets] }));
}

function listDatasets() {
  return readState().datasets;
}

function getDataset(id) {
  return readState().datasets.find((dataset) => dataset.id === id) || null;
}

function addTowerRecords(records) {
  updateState((state) => ({ ...state, tower_records: [...state.tower_records, ...records] }));
}

function listTowerRecords(datasetId = null) {
  const records = readState().tower_records;
  return datasetId ? records.filter((record) => record.datasetId === datasetId) : records;
}

function replaceSuspiciousFlagsForDataset(datasetId, flags) {
  updateState((state) => ({
    ...state,
    suspicious_flags: [
      ...state.suspicious_flags.filter((flag) => flag.datasetId !== datasetId),
      ...flags,
    ],
  }));
}

function listSuspiciousFlags() {
  return readState().suspicious_flags;
}

function getSuspiciousFlag(id) {
  return readState().suspicious_flags.find((flag) => flag.id === id) || null;
}

function addAuditLog(entry) {
  updateState((state) => ({ ...state, audit_logs: [entry, ...state.audit_logs] }));
}

function listAuditLogs() {
  return readState().audit_logs;
}

function deleteDatasetCascade(id) {
  const state = readState();
  const dataset = state.datasets.find((entry) => entry.id === id) || null;
  const recordsDeleted = state.tower_records.filter((record) => record.datasetId === id).length;
  const flagsDeleted = state.suspicious_flags.filter((flag) => flag.datasetId === id).length;
  const nextState = {
    ...state,
    datasets: state.datasets.filter((entry) => entry.id !== id),
    tower_records: state.tower_records.filter((record) => record.datasetId !== id),
    suspicious_flags: state.suspicious_flags.filter((flag) => flag.datasetId !== id),
  };
  writeState(nextState);
  return { dataset, recordsDeleted, flagsDeleted };
}

function getCounts() {
  const state = readState();
  return {
    datasets: state.datasets.length,
    records: state.tower_records.length,
    auditLogs: state.audit_logs.length,
    suspiciousFlags: state.suspicious_flags.length,
  };
}

module.exports = {
  upsertUser,
  listUsers,
  addDataset,
  listDatasets,
  getDataset,
  addTowerRecords,
  listTowerRecords,
  replaceSuspiciousFlagsForDataset,
  listSuspiciousFlags,
  getSuspiciousFlag,
  addAuditLog,
  listAuditLogs,
  deleteDatasetCascade,
  getCounts,
};
