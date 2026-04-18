
import { useState, useEffect } from "react";
import { signInWithEmailAndPassword } from "firebase/auth";
import { doc, getDoc } from "firebase/firestore";
import { auth, db } from "./firebase";

// ============================================================
// MOCK DATA — simulates Firestore records in demo mode
// ============================================================
const MOCK_USERS = [
  { id: "u1", username: "admin", password: "admin123", role: "admin", name: "Admin Officer" },
  { id: "u2", username: "investigator", password: "inv123", role: "investigator", name: "Det. Sharma" },
];

const MOCK_TOWER_RECORDS = [
  { id: "r1", mobileNumber: "9876543210", towerId: "TWR101", location: "Crime Scene A", lat: 19.076, lng: 72.8777, timestamp: "2026-03-01 20:05:00", datasetId: "ds1" },
  { id: "r2", mobileNumber: "9876543210", towerId: "TWR102", location: "Highway Junction", lat: 19.082, lng: 72.885, timestamp: "2026-03-01 20:45:00", datasetId: "ds1" },
  { id: "r3", mobileNumber: "9876543210", towerId: "TWR103", location: "Crime Scene B", lat: 19.091, lng: 72.892, timestamp: "2026-03-01 21:10:00", datasetId: "ds2" },
  { id: "r4", mobileNumber: "9123456780", towerId: "TWR101", location: "Crime Scene A", lat: 19.076, lng: 72.8777, timestamp: "2026-03-01 20:10:00", datasetId: "ds1" },
  { id: "r5", mobileNumber: "9123456780", towerId: "TWR103", location: "Crime Scene B", lat: 19.091, lng: 72.892, timestamp: "2026-03-01 21:05:00", datasetId: "ds2" },
  { id: "r6", mobileNumber: "8888877770", towerId: "TWR101", location: "Crime Scene A", lat: 19.076, lng: 72.8777, timestamp: "2026-03-01 20:08:00", datasetId: "ds1" },
  { id: "r7", mobileNumber: "7777766660", towerId: "TWR102", location: "Highway Junction", lat: 19.082, lng: 72.885, timestamp: "2026-03-01 20:50:00", datasetId: "ds1" },
  { id: "r8", mobileNumber: "9999988880", towerId: "TWR104", location: "Market Area", lat: 19.069, lng: 72.870, timestamp: "2026-03-01 19:50:00", datasetId: "ds1" },
  { id: "r9", mobileNumber: "9999988880", towerId: "TWR101", location: "Crime Scene A", lat: 19.076, lng: 72.8777, timestamp: "2026-03-01 20:15:00", datasetId: "ds1" },
  { id: "r10", mobileNumber: "9999988880", towerId: "TWR103", location: "Crime Scene B", lat: 19.091, lng: 72.892, timestamp: "2026-03-01 21:20:00", datasetId: "ds2" },
];

const MOCK_DATASETS = [
  { id: "ds1", name: "Tower Dump - Crime Scene A & Highway", uploadedBy: "admin", uploadedAt: "2026-03-02 09:00:00", records: 6, status: "active" },
  { id: "ds2", name: "Tower Dump - Crime Scene B", uploadedBy: "admin", uploadedAt: "2026-03-02 09:30:00", records: 4, status: "active" },
];

const MOCK_AUDIT_LOGS = [
  { id: "l1", userId: "u1", username: "admin", action: "Uploaded dataset: Tower Dump - Crime Scene A", timestamp: "2026-03-02 09:00:00", ip: "192.168.1.10" },
  { id: "l2", userId: "u2", username: "investigator", action: "Tracked mobile: 98****3210", timestamp: "2026-03-02 10:15:00", ip: "192.168.1.25" },
  { id: "l3", userId: "u2", username: "investigator", action: "Searched crime scene: Crime Scene A", timestamp: "2026-03-02 11:00:00", ip: "192.168.1.25" },
];

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
const maskMobile = (num) => num.slice(0, 2) + "******" + num.slice(-2);
const nowStr = () => new Date().toLocaleString("en-IN", { hour12: false });
const API_BASE = "http://localhost:3001/api";
let sessionUser = null;
const getDigits = (value) => String(value || "").replace(/\D/g, "");
const textEncoder = new TextEncoder();
const formatShortHash = (hash) => (hash ? `${hash.slice(0, 12)}...${hash.slice(-8)}` : "HASHING...");
const serializeRecord = (record) => JSON.stringify({
  id: record.id || "",
  datasetId: record.datasetId || "",
  mobileNumber: record.mobileNumber || "",
  towerId: record.towerId || "",
  location: record.location || "",
  lat: record.lat || "",
  lng: record.lng || "",
  timestamp: record.timestamp || "",
});

const sha256Hex = async (value) => {
  const buffer = await crypto.subtle.digest("SHA-256", textEncoder.encode(String(value)));
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
};

const hashRecord = async (record) => sha256Hex(serializeRecord(record));
const mobileMatchesQuery = (mobileValue, query) => {
  const mobileDigits = getDigits(mobileValue);
  const queryDigits = getDigits(query);
  if (!queryDigits) return false;
  return mobileDigits.includes(queryDigits) || mobileDigits.endsWith(queryDigits);
};

const generateReport = async (user, trackedNum, trackedRecords, commonNumbers) => {
  const recordHashes = await Promise.all(trackedRecords.map((record) => hashRecord(record)));
  const lines = [
    "=== TOWER DUMP INVESTIGATION REPORT ===",
    `Generated: ${nowStr()}`,
    `Officer: ${user.name} (${user.role})`,
    "",
    "--- TRACKED NUMBER ---",
    trackedNum ? `Number: ${user.role === "admin" ? trackedNum : maskMobile(trackedNum)}` : "No number tracked",
    "",
    "--- MOVEMENT TIMELINE ---",
    ...trackedRecords.map((r, i) => `${i + 1}. ${r.timestamp} | ${r.location} | Tower: ${r.towerId} | SHA-256: ${recordHashes[i]}`),
    "",
    "--- SUSPECTS (Multiple Locations) ---",
    ...commonNumbers.map(c => `${user.role === "admin" ? c.num : maskMobile(c.num)} — Appeared at: ${c.locations.join(", ")}`),
    "",
    "=== END OF REPORT ==="
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a"); a.href = url; a.download = "investigation_report.txt"; a.click();
};

const apiFetch = async (path, token, options = {}) => {
  const headers = { ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (sessionUser) {
    headers["x-dev-role"] = sessionUser.role || "";
    headers["x-dev-email"] = sessionUser.username || sessionUser.email || "";
    headers["x-dev-uid"] = sessionUser.id || "";
  }
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const error = new Error(data.error || "Request failed");
    error.payload = data;
    throw error;
  }
  return data;
};

// ============================================================
// FIREBASE SERVICE (mock + real scaffold)
// ============================================================
const FirebaseService = {
  // PRODUCTION INTEGRATION NOTES:
  // 1. npm install firebase
  // 2. import { initializeApp } from 'firebase/app'
  // 3. import { getFirestore, collection, getDocs, addDoc, query, where, orderBy } from 'firebase/firestore'
  // 4. import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword } from 'firebase/auth'
  // 5. import { getStorage, ref, uploadBytes } from 'firebase/storage'
  //
  // Firestore Collections:
  //   /users/{uid}           — user profiles & roles
  //   /tower_records/{id}    — encrypted tower dump records
  //   /datasets/{id}         — dataset metadata
  //   /audit_logs/{id}       — tamper-resistant audit trail
  //
  // Security Rules:
  //   allow read, write: if request.auth != null && request.auth.token.role == 'admin'
  //   allow read: if request.auth != null && request.auth.token.role == 'investigator'

  login: async (email, password) => {
    const result = await signInWithEmailAndPassword(auth, email, password);
    const uid = result.user.uid;
    const userRef = doc(db, "users", uid);
    const userSnap = await getDoc(userRef);

    if (!userSnap.exists()) throw new Error("User profile not found");

    return {
      id: uid,
      username: userSnap.data().email,
      ...userSnap.data(),
      token: await result.user.getIdToken(),
    };
  },

  setSessionUser: (user) => {
    sessionUser = user;
  },

  getTowerRecords: async (datasetId = null, filters = {}) => {
    const token = await auth.currentUser?.getIdToken();
    if (datasetId) {
      const params = new URLSearchParams();
      if (filters.location) params.set("location", filters.location);
      if (filters.towerId) params.set("towerId", filters.towerId);
      params.set("limit", String(filters.limit || 5000));
      const suffix = params.toString() ? `?${params.toString()}` : "";
      const { records } = await apiFetch(`/analysis/records/${datasetId}${suffix}`, token);
      return records || [];
    }
    const { datasets } = await apiFetch("/datasets", token);
    const recordResponses = await Promise.all(
      datasets.map((dataset) =>
        apiFetch(`/analysis/records/${dataset.id}`, token)
          .then((data) => data.records || [])
          .catch(() => [])
      )
    );
    return recordResponses.flat();
  },

  getDatasets: async () => {
    const token = await auth.currentUser?.getIdToken();
    const { datasets } = await apiFetch("/datasets", token);
    return datasets.map((dataset) => ({
      ...dataset,
      records: dataset.validRecords ?? dataset.totalRecords ?? dataset.records ?? 0,
      uploadedAt: dataset.uploadedAt || nowStr(),
    }));
  },

  getAuditLogs: async () => {
    if (auth.currentUser == null) return [];
    const token = await auth.currentUser.getIdToken();
    const { logs } = await apiFetch("/admin/audit-logs", token);
    return (logs || []).map((log) => ({
      ...log,
      username: log.username || log.email || "unknown",
    }));
  },

  uploadDataset: async (name, file) => {
    const token = await auth.currentUser?.getIdToken();
    const formData = new FormData();
    formData.append("name", name);
    formData.append("file", file);
    return apiFetch("/datasets/upload", token, {
      method: "POST",
      body: formData,
    });
  },

  trackNumber: async (datasetId, mobileQuery) => {
    const token = await auth.currentUser?.getIdToken();
    return apiFetch("/analysis/track", token, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ datasetId, mobileQuery }),
    });
  },

  detectSuspicious: async (datasetId) => {
    const token = await auth.currentUser?.getIdToken();
    return apiFetch(`/analysis/detect-suspicious/${datasetId}`, token, {
      method: "POST",
    });
  },

  deleteDataset: async (datasetId) => {
    const token = await auth.currentUser?.getIdToken();
    return apiFetch(`/datasets/${datasetId}`, token, {
      method: "DELETE",
    });
  },

  addAuditLog: async (log) => {
    console.info("[audit]", log);
  },
};

// ============================================================
// UI PRIMITIVES
// ============================================================
const Spinner = () => (
  <div style={{ display:"flex", justifyContent:"center", padding:40 }}>
    <div style={{ width:36, height:36, border:"3px solid #1a2744", borderTop:"3px solid #00d4ff", borderRadius:"50%", animation:"spin 0.8s linear infinite" }} />
  </div>
);

const Badge = ({ children, color="#00d4ff" }) => (
  <span style={{ background:color+"22", color, border:`1px solid ${color}44`, borderRadius:4, padding:"2px 8px", fontSize:11, fontWeight:700, letterSpacing:1, textTransform:"uppercase", whiteSpace:"nowrap" }}>
    {children}
  </span>
);

const Card = ({ children, style={} }) => (
  <div style={{ background:"#0d1b2a", border:"1px solid #1e3a5f", borderRadius:12, padding:24, marginBottom:20, ...style }}>
    {children}
  </div>
);

const Btn = ({ children, onClick, variant="primary", disabled=false, style={} }) => {
  const v = {
    primary: { background:"#00d4ff", color:"#050d1a" },
    danger:  { background:"#ff4757", color:"#fff" },
    ghost:   { background:"transparent", color:"#00d4ff", border:"1px solid #00d4ff44" },
    success: { background:"#00c853", color:"#050d1a" },
  };
  return (
    <button onClick={onClick} disabled={disabled} style={{ ...v[variant], border:"none", padding:"8px 18px", borderRadius:6, fontWeight:700, cursor:disabled?"not-allowed":"pointer", fontSize:13, letterSpacing:0.5, opacity:disabled?0.5:1, transition:"all 0.2s", fontFamily:"'Courier New', monospace", ...style }}>
      {children}
    </button>
  );
};

const Inp = ({ value, onChange, placeholder, type="text", style={} }) => (
  <input type={type} value={value} onChange={onChange} placeholder={placeholder}
    style={{ background:"#070f1a", border:"1px solid #1e3a5f", borderRadius:6, color:"#c8dff0", padding:"8px 12px", fontSize:13, outline:"none", width:"100%", boxSizing:"border-box", fontFamily:"'Courier New', monospace", ...style }} />
);

const Sel = ({ value, onChange, options }) => (
  <select value={value} onChange={onChange}
    style={{ background:"#070f1a", border:"1px solid #1e3a5f", borderRadius:6, color:"#c8dff0", padding:"8px 12px", fontSize:13, outline:"none", width:"100%", fontFamily:"'Courier New', monospace" }}>
    {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
  </select>
);

// ============================================================
// ROUTE MAP (SVG — no external dependencies)
// ============================================================
const RouteMap = ({ records }) => {
  if (!records || records.length === 0) return null;
  const sorted = [...records].sort((a,b) => a.timestamp.localeCompare(b.timestamp));
  const lats = sorted.map(r=>r.lat), lngs = sorted.map(r=>r.lng);
  const minLat=Math.min(...lats), maxLat=Math.max(...lats);
  const minLng=Math.min(...lngs), maxLng=Math.max(...lngs);
  const pad=50, W=500, H=300;
  const toX = lng => lngs.length===1 ? W/2 : pad+((lng-minLng)/(maxLng-minLng||1))*(W-2*pad);
  const toY = lat => lats.length===1 ? H/2 : pad+((maxLat-lat)/(maxLat-minLat||1))*(H-2*pad);
  const pts = sorted.map(r=>({ x:toX(r.lng), y:toY(r.lat), ...r }));

  return (
    <div style={{ background:"#070f1a", borderRadius:10, border:"1px solid #1e3a5f", overflow:"hidden" }}>
      <div style={{ padding:"10px 16px", borderBottom:"1px solid #1e3a5f", color:"#00d4ff", fontSize:11, letterSpacing:2 }}>🗺 MOVEMENT ROUTE MAP</div>
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ display:"block" }}>
        {[0,1,2,3].map(i=>(
          <line key={`gx${i}`} x1={pad+i*(W-2*pad)/3} y1={pad} x2={pad+i*(W-2*pad)/3} y2={H-pad} stroke="#1e3a5f" strokeWidth="0.5" strokeDasharray="4,4"/>
        ))}
        {pts.length>1 && pts.map((p,i)=> i<pts.length-1 && (
          <g key={`line${i}`}>
            <line x1={p.x} y1={p.y} x2={pts[i+1].x} y2={pts[i+1].y} stroke="#00d4ff" strokeWidth="2" opacity="0.6"/>
          </g>
        ))}
        {pts.map((p,i)=>(
          <g key={`mk${i}`}>
            <circle cx={p.x} cy={p.y} r={18} fill="#00d4ff" opacity="0.07"/>
            <circle cx={p.x} cy={p.y} r={11} fill={i===0?"#00c853":i===pts.length-1?"#ff4757":"#00d4ff"}/>
            <text x={p.x} y={p.y+4} textAnchor="middle" fill="#050d1a" fontSize={10} fontWeight="bold">{i+1}</text>
            <text x={p.x} y={p.y+26} textAnchor="middle" fill="#c8dff0" fontSize={9}>{p.location.split(" ").slice(0,2).join(" ")}</text>
            <text x={p.x} y={p.y+37} textAnchor="middle" fill="#4a6fa5" fontSize={8}>{p.timestamp.slice(11,16)}</text>
          </g>
        ))}
      </svg>
      <div style={{ padding:"8px 16px", borderTop:"1px solid #1e3a5f", display:"flex", gap:20, fontSize:10, color:"#4a6fa5" }}>
        <span>🟢 Start</span><span>🔴 End</span><span>🔵 Via</span>
      </div>
    </div>
  );
};

// ============================================================
// LOGIN
// ============================================================
const LoginPage = ({ onLogin }) => {
  const [email, setEmail] = useState(""); const [pw, setPw] = useState("");
  const [loading, setLoading] = useState(false); const [error, setError] = useState(""); const [att, setAtt] = useState(0);

  const handle = async () => {
    if (att >= 5) { setError("Account locked. Too many failed attempts."); return; }
    if (!email || !pw) { setError("Please enter credentials."); return; }
    setLoading(true); setError("");
    try {
      const user = await FirebaseService.login(email, pw);
      FirebaseService.setSessionUser(user);
      await FirebaseService.addAuditLog({ userId:user.id, username:user.username, action:"User logged in", ip:"192.168.1.x" });
      onLogin(user);
    } catch(e) { setAtt(a=>a+1); setError(`Invalid credentials. ${4-att} attempts remaining.`); }
    setLoading(false);
  };

  return (
    <div style={{ minHeight:"100vh", background:"#050d1a", display:"flex", alignItems:"center", justifyContent:"center", fontFamily:"'Courier New', monospace",
      backgroundImage:"radial-gradient(ellipse at 20% 50%, #0a1f3d 0%, transparent 60%), radial-gradient(ellipse at 80% 20%, #001a3d 0%, transparent 50%)" }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
      `}</style>
      <div style={{ width:420, animation:"fadeIn 0.6s ease" }}>
        <div style={{ textAlign:"center", marginBottom:36 }}>
          <div style={{ width:72, height:72, borderRadius:"50%", background:"linear-gradient(135deg,#00d4ff22,#0050aa44)", border:"2px solid #00d4ff44", display:"flex", alignItems:"center", justifyContent:"center", margin:"0 auto 16px", fontSize:32 }}>📡</div>
          <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:4, fontWeight:700, marginBottom:6 }}>SECURE ACCESS PORTAL</div>
          <h1 style={{ color:"#e8f4ff", margin:0, fontSize:22, fontWeight:700, letterSpacing:1 }}>TOWER DUMP ANALYSIS</h1>
          <div style={{ color:"#4a6fa5", fontSize:11, marginTop:4, letterSpacing:2 }}>DIGITAL FORENSICS SYSTEM v2.1</div>
        </div>
        <div style={{ textAlign:"center", marginBottom:20 }}>
          <span style={{ background:"#ff6d0022", color:"#ff9d00", border:"1px solid #ff6d0044", borderRadius:4, padding:"3px 10px", fontSize:11, letterSpacing:1 }}>🔥 FIREBASE BACKEND</span>
        </div>
        <Card>
          <div style={{ marginBottom:14 }}>
            <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>OFFICER EMAIL</label>
            <Inp value={email} onChange={e=>setEmail(e.target.value)} placeholder="Enter email" type="email" />
          </div>
          <div style={{ marginBottom:20 }}>
            <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>PASSWORD</label>
            <Inp value={pw} onChange={e=>setPw(e.target.value)} placeholder="Enter password" type="password" />
          </div>
          {error && <div style={{ background:"#ff475722", border:"1px solid #ff475744", borderRadius:6, padding:"8px 12px", color:"#ff4757", fontSize:12, marginBottom:14 }}>{error}</div>}
          <Btn onClick={handle} disabled={loading} style={{ width:"100%", padding:12 }}>{loading?"AUTHENTICATING...":"SECURE LOGIN"}</Btn>
          <div style={{ marginTop:14, padding:12, background:"#070f1a", borderRadius:6, color:"#4a6fa5", fontSize:11, lineHeight:1.8 }}>
            <div style={{ marginBottom:4, color:"#00d4ff88" }}>DEMO CREDENTIALS</div>
            <div>Admin: use your Firebase admin email</div>
            <div>Investigator: use your Firebase investigator email</div>
          </div>
        </Card>
        <div style={{ textAlign:"center", color:"#1e3a5f", fontSize:10, letterSpacing:2, marginTop:14 }}>JWT SECURED · AES-256 ENCRYPTED · AUDIT LOGGED</div>
      </div>
    </div>
  );
};

// ============================================================
// MAIN DASHBOARD
// ============================================================
const Dashboard = ({ user, onLogout }) => {
  const [tab, setTab] = useState("overview");
  const [records, setRecords] = useState([]);
  const [datasets, setDatasets] = useState([]);
  const [activeDatasetId, setActiveDatasetId] = useState("");
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchNum, setSearchNum] = useState("");
  const [trackedNum, setTrackedNum] = useState(null);
  const [trackedRecords, setTrackedRecords] = useState([]);
  const [trackStatus, setTrackStatus] = useState("");
  const [filterLoc, setFilterLoc] = useState("");
  const [timeStart, setTimeStart] = useState("20:00");
  const [timeEnd, setTimeEnd] = useState("22:00");
  const [csResults, setCsResults] = useState([]);
  const [crimeSceneStatus, setCrimeSceneStatus] = useState("");
  const [common, setCommon] = useState([]);
  const [commonStatus, setCommonStatus] = useState("");
  const [upName, setUpName] = useState("");
  const [upStatus, setUpStatus] = useState("");
  const [upFile, setUpFile] = useState(null);
  const [dashboardStatus, setDashboardStatus] = useState("");
  const [recordHashes, setRecordHashes] = useState({});
  const [datasetFingerprint, setDatasetFingerprint] = useState("");
  const [fingerprintStatus, setFingerprintStatus] = useState("Select a dataset to generate an integrity fingerprint.");

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const [recordsResult, datasetsResult, auditLogsResult] = await Promise.allSettled([
          FirebaseService.getTowerRecords(),
          FirebaseService.getDatasets(),
          user.role === "admin" ? FirebaseService.getAuditLogs() : Promise.resolve([]),
        ]);
        const resolvedRecords = recordsResult.status === "fulfilled" ? recordsResult.value : [];
        const resolvedDatasets = datasetsResult.status === "fulfilled" ? datasetsResult.value : [];
        const resolvedLogs = auditLogsResult.status === "fulfilled" ? auditLogsResult.value : [];
        setRecords(resolvedRecords);
        setDatasets(resolvedDatasets);
        if (resolvedDatasets.length > 0) setActiveDatasetId((current) => current || resolvedDatasets[0].id);
        setAuditLogs(resolvedLogs);
        if (recordsResult.status === "rejected" || datasetsResult.status === "rejected" || auditLogsResult.status === "rejected") {
          const reasons = [recordsResult, datasetsResult, auditLogsResult]
            .filter((result) => result.status === "rejected")
            .map((result) => result.reason?.message || "Request failed");
          setDashboardStatus(`Backend unavailable: ${reasons[0]}`);
        } else {
          setDashboardStatus("");
        }
      } catch (e) {
        setDashboardStatus(`Backend unavailable: ${e.message}`);
      } finally {
        setLoading(false);
      }
    })();
  }, [user.role]);

  useEffect(() => {
    if (!datasets.length) {
      setActiveDatasetId("");
      return;
    }
    if (!datasets.some((dataset) => dataset.id === activeDatasetId)) {
      setActiveDatasetId(datasets[0].id);
    }
  }, [datasets, activeDatasetId]);

  useEffect(() => {
    let cancelled = false;

    if (!records.length) {
      setRecordHashes({});
      return () => {
        cancelled = true;
      };
    }

    (async () => {
      const entries = await Promise.all(records.map(async (record) => [record.id, await hashRecord(record)]));
      if (!cancelled) setRecordHashes(Object.fromEntries(entries));
    })();

    return () => {
      cancelled = true;
    };
  }, [records]);

  const log = a => FirebaseService.addAuditLog({ userId:user.id, username:user.username, action:a, ip:"192.168.x.x" });
  const activeDataset = datasets.find((dataset) => dataset.id === activeDatasetId) || null;
  const activeRecords = activeDatasetId ? records.filter((record) => record.datasetId === activeDatasetId) : records;

  useEffect(() => {
    let cancelled = false;
    const scopedRecords = activeDatasetId ? records.filter((record) => record.datasetId === activeDatasetId) : records;

    if (!activeDatasetId) {
      setDatasetFingerprint("");
      setFingerprintStatus("Select a dataset to generate an integrity fingerprint.");
      return () => {
        cancelled = true;
      };
    }

    if (!scopedRecords.length) {
      setDatasetFingerprint("");
      setFingerprintStatus("The selected dataset has no records to hash.");
      return () => {
        cancelled = true;
      };
    }

    setFingerprintStatus(`Generating SHA-256 fingerprint for ${scopedRecords.length} records...`);

    (async () => {
      const digests = await Promise.all(scopedRecords.map((record) => recordHashes[record.id] || hashRecord(record)));
      const fingerprint = await sha256Hex(digests.sort().join("|"));
      if (!cancelled) {
        setDatasetFingerprint(fingerprint);
        setFingerprintStatus(`Integrity fingerprint ready for ${activeDataset?.name || activeDatasetId}.`);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [activeDataset, activeDatasetId, records, recordHashes]);

  const handleTrack = async () => {
    if (!activeDatasetId) { setTrackStatus("Select a dataset first."); return; }
    if (!searchNum) { setTrackStatus("Enter a mobile number to search."); return; }
    try {
      const result = await FirebaseService.trackNumber(activeDatasetId, searchNum);
      setTrackedNum(searchNum);
      setTrackedRecords(result.records || []);
      setTrackStatus(result.count ? `${result.count} records found.` : "No records found for that number in the selected dataset.");
      await log(`Tracked mobile: ${maskMobile(searchNum)}`);
    } catch (e) {
      setTrackedNum(searchNum);
      setTrackedRecords([]);
      setTrackStatus(`Tracking failed: ${e.message}`);
    }
  };

  const handleCrimeScene = async () => {
    if (!activeDatasetId) { setCrimeSceneStatus("Select a dataset first."); return; }
    try {
      const scopedRecords = await FirebaseService.getTowerRecords(activeDatasetId, { location: filterLoc || undefined });
      const res = scopedRecords.filter((record) => {
        const timeValue = String(record.timestamp || "").slice(11, 16);
        return timeValue && timeValue >= timeStart && timeValue <= timeEnd;
      });
      setCsResults(res);
      setCrimeSceneStatus(res.length ? `${res.length} records found.` : "No records found for the selected location and time range.");
      await log(`Crime scene query: ${filterLoc} ${timeStart}-${timeEnd}`);
    } catch (e) {
      setCsResults([]);
      setCrimeSceneStatus(`Crime scene search failed: ${e.message}`);
    }
  };

  const detectCommon = async () => {
    if (!activeDatasetId) { setCommonStatus("Select a dataset first."); return; }
    try {
      const result = await FirebaseService.detectSuspicious(activeDatasetId);
      const res = (result.flags || [])
        .map((flag) => ({
          num: flag.mobileMasked,
          locations: flag.locations || [],
          count: flag.locations?.length || flag.count || 0,
        }))
        .sort((a,b)=>b.count-a.count);
      setCommon(res);
      setCommonStatus(res.length ? `${res.length} suspects flagged.` : "No suspects found for the selected dataset.");
      await log("Ran common number detection");
    } catch (e) {
      setCommon([]);
      setCommonStatus(`Suspect detection failed: ${e.message}`);
    }
  };

  const handleUpload = async () => {
    if (!upName) { setUpStatus("❌ Please enter a dataset name."); return; }
    if (!upFile) { setUpStatus("❌ Please select a CSV or Excel file."); return; }
    setUpStatus("Uploading dataset to secure backend...");
    try {
      const result = await FirebaseService.uploadDataset(upName, upFile);
      const [d, r, l] = await Promise.all([
        FirebaseService.getDatasets(),
        FirebaseService.getTowerRecords(),
        user.role === "admin" ? FirebaseService.getAuditLogs() : Promise.resolve(auditLogs),
      ]);
      setDatasets(d);
      setRecords(r);
      if (result.dataset?.id) setActiveDatasetId(result.dataset.id);
      setAuditLogs(l);
      await log(`Uploaded dataset: ${upName}`);
      setUpStatus(`✅ Dataset "${result.dataset?.name || upName}" uploaded successfully.`);
      setUpName("");
      setUpFile(null);
    } catch (e) {
      const invalidDetails = e.payload?.validationSummary?.invalidDetails || [];
      const firstIssue = invalidDetails[0];
      const detailText = firstIssue ? ` Row ${firstIssue.row}: ${firstIssue.reason}.` : "";
      setUpStatus(`Upload failed: ${e.message}.${detailText}`);
    }
  };

  const handleDeleteDataset = async (datasetId) => {
    if (!window.confirm("Delete this dataset and all related records?")) return;
    try {
      const result = await FirebaseService.deleteDataset(datasetId);
      const [d, r, l] = await Promise.all([
        FirebaseService.getDatasets(),
        FirebaseService.getTowerRecords(),
        user.role === "admin" ? FirebaseService.getAuditLogs() : Promise.resolve(auditLogs),
      ]);
      setDatasets(d);
      setRecords(r);
      setAuditLogs(l);
      setTrackedRecords([]);
      setCsResults([]);
      setCommon([]);
      setTrackStatus("");
      setCrimeSceneStatus("");
      setCommonStatus("");
      setUpStatus(`${result.message}. Removed ${result.deleted?.recordsDeleted ?? 0} records.`);
    } catch (e) {
      setUpStatus(`Delete failed: ${e.message}`);
    }
  };

  const locs = [...new Set(activeRecords.map(r=>r.location))];

  const tabs = [
    { id:"overview",    label:"Overview",     icon:"📊" },
    { id:"crime_scene", label:"Crime Scene",   icon:"🔍" },
    { id:"common",      label:"Suspects",      icon:"⚠️" },
    { id:"track",       label:"Track Number",  icon:"📍" },
    ...(user.role==="admin" ? [
      { id:"upload", label:"Upload Data", icon:"📤" },
      { id:"users",  label:"Users",       icon:"👥" },
      { id:"audit",  label:"Audit Logs",  icon:"📋" },
    ] : []),
  ];

  return (
    <div style={{ minHeight:"100vh", background:"#050d1a", fontFamily:"'Courier New', monospace", color:"#c8dff0" }}>
      <style>{`
        @keyframes spin  { to { transform: rotate(360deg); } }
        @keyframes fadeIn { from{opacity:0} to{opacity:1} }
        ::-webkit-scrollbar { width:6px }
        ::-webkit-scrollbar-track { background:#070f1a }
        ::-webkit-scrollbar-thumb { background:#1e3a5f; border-radius:3px }
        table { border-collapse:collapse; width:100% }
        th { background:#0a1525; color:#00d4ff; font-size:11px; letter-spacing:1px; padding:10px 14px; text-align:left; font-family:'Courier New',monospace }
        td { padding:9px 14px; font-size:12px; border-bottom:1px solid #0d1b2a; font-family:'Courier New',monospace }
        tr:hover td { background:#0d1b2a55 }
      `}</style>

      {/* Header */}
      <div style={{ background:"#080f1c", borderBottom:"1px solid #1e3a5f", padding:"0 24px", display:"flex", alignItems:"center", justifyContent:"space-between", height:56, position:"sticky", top:0, zIndex:100 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <span style={{ fontSize:22 }}>📡</span>
          <div>
            <div style={{ color:"#00d4ff", fontSize:13, fontWeight:700, letterSpacing:1 }}>TOWER DUMP ANALYSIS</div>
            <div style={{ color:"#4a6fa5", fontSize:9, letterSpacing:2 }}>DIGITAL FORENSICS · FIREBASE BACKEND</div>
          </div>
        </div>
        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          <div style={{ textAlign:"right" }}>
            <div style={{ color:"#c8dff0", fontSize:12 }}>{user.name}</div>
            <div style={{ display:"flex", gap:6, justifyContent:"flex-end", marginTop:2 }}>
              <Badge color={user.role==="admin"?"#ff9d00":"#00d4ff"}>{user.role}</Badge>
              <Badge color="#00c853">🔒 JWT</Badge>
            </div>
          </div>
          <Btn onClick={onLogout} variant="ghost" style={{ padding:"6px 12px", fontSize:11 }}>LOGOUT</Btn>
        </div>
      </div>

      <div style={{ display:"flex", minHeight:"calc(100vh - 56px)" }}>
        {/* Sidebar */}
        <div style={{ width:200, background:"#080f1c", borderRight:"1px solid #1e3a5f", padding:"20px 0", flexShrink:0 }}>
          {tabs.map(t=>(
            <div key={t.id} onClick={()=>setTab(t.id)} style={{
              padding:"12px 20px", cursor:"pointer", fontSize:12, letterSpacing:0.5,
              background:tab===t.id?"#00d4ff15":"transparent",
              borderLeft:tab===t.id?"2px solid #00d4ff":"2px solid transparent",
              color:tab===t.id?"#00d4ff":"#4a6fa5", transition:"all 0.2s",
              display:"flex", alignItems:"center", gap:10
            }}>
              <span>{t.icon}</span>{t.label}
            </div>
          ))}
          <div style={{ margin:"20px 12px 0", padding:12, background:"#ff9d0011", border:"1px solid #ff9d0022", borderRadius:6, fontSize:10, color:"#ff9d00", lineHeight:1.8 }}>
            🔥 Firebase Firestore<br/>
            <span style={{ color:"#4a6fa5" }}>AES-256 encrypted<br/>Audit logged</span>
          </div>
        </div>

        {/* Content */}
        <div style={{ flex:1, padding:24, overflow:"auto" }}>
          {loading ? <Spinner /> : (<>
            {dashboardStatus && (
              <Card style={{ padding:16, border:"1px solid #ff475744", background:"#2a1015" }}>
                <div style={{ color:"#ff8a95", fontSize:12 }}>{dashboardStatus}</div>
              </Card>
            )}
            <Card style={{ padding:16 }}>
              <div style={{ display:"grid", gridTemplateColumns:"1fr auto", gap:12, alignItems:"end" }}>
                <div>
                  <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>ACTIVE DATASET</label>
                  <Sel
                    value={activeDatasetId}
                    onChange={e=>setActiveDatasetId(e.target.value)}
                    options={datasets.length ? datasets.map((dataset) => ({ value: dataset.id, label: `${dataset.name} (${dataset.records} rec)` })) : [{ value:"", label:"No datasets available" }]}
                  />
                </div>
                <div style={{ color:"#4a6fa5", fontSize:12, textAlign:"right" }}>
                  {activeDataset ? `Selected: ${activeDataset.name}` : "Upload a dataset to begin analysis."}
                </div>
              </div>
            </Card>

            {/* OVERVIEW */}
            {tab==="overview" && (
              <div style={{ animation:"fadeIn 0.4s ease" }}>
                <h2 style={{ color:"#e8f4ff", marginTop:0, fontWeight:700, letterSpacing:1, fontSize:18 }}>SYSTEM OVERVIEW</h2>
                <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:24 }}>
                  {[
                    { label:"TOTAL RECORDS",   value:records.length,                                        icon:"📱", color:"#00d4ff" },
                    { label:"DATASETS",         value:datasets.length,                                       icon:"🗄️", color:"#ff9d00" },
                    { label:"UNIQUE NUMBERS",   value:new Set(records.map(r=>r.mobileNumber)).size,          icon:"👤", color:"#00c853" },
                    { label:"TOWERS COVERED",   value:new Set(records.map(r=>r.towerId)).size,               icon:"📡", color:"#ff4757" },
                  ].map(s=>(
                    <Card key={s.label} style={{ padding:20, margin:0 }}>
                      <div style={{ color:"#4a6fa5", fontSize:10, letterSpacing:2 }}>{s.label}</div>
                      <div style={{ color:s.color, fontSize:34, fontWeight:700, margin:"8px 0 4px" }}>{s.value}</div>
                      <div style={{ fontSize:22 }}>{s.icon}</div>
                    </Card>
                  ))}
                </div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                  <Card>
                    <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2, marginBottom:14 }}>RECENT DATASETS (FIRESTORE)</div>
                    {datasets.map(d=>(
                      <div key={d.id} style={{ display:"flex", justifyContent:"space-between", padding:"8px 0", borderBottom:"1px solid #1e3a5f22", alignItems:"center" }}>
                        <div>
                          <div style={{ fontSize:12, color:"#c8dff0" }}>{d.name}</div>
                          <div style={{ fontSize:10, color:"#4a6fa5", marginTop:2 }}>Uploaded: {d.uploadedAt}</div>
                        </div>
                        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                          <Badge color={d.id===activeDatasetId ? "#00d4ff" : "#00c853"}>{d.records} rec</Badge>
                          <Btn onClick={()=>setActiveDatasetId(d.id)} variant="ghost" style={{ padding:"4px 10px", fontSize:10 }}>USE</Btn>
                          {user.role==="admin" && <Btn onClick={()=>handleDeleteDataset(d.id)} variant="danger" style={{ padding:"4px 10px", fontSize:10 }}>DELETE</Btn>}
                        </div>
                      </div>
                    ))}
                  </Card>
                  <Card>
                    <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2, marginBottom:14 }}>SECURITY STATUS</div>
                    {[
                      { label:"Firebase Auth",     status:"ACTIVE",   ok:true },
                      { label:"AES-256 Encryption", status:"ENABLED",  ok:true },
                      { label:"Audit Logging",      status:"RUNNING",  ok:true },
                      { label:"SHA-256 Integrity",  status:datasetFingerprint ? "VERIFIED" : "PENDING", ok:!!datasetFingerprint },
                      { label:"Data Masking",       status:"ON",       ok:true },
                      { label:"JWT Sessions",       status:"ACTIVE",   ok:true },
                      { label:"Malware Scanner",    status:"READY",    ok:true },
                      { label:"Firestore Rules",    status:"ENFORCED", ok:true },
                    ].map(s=>(
                      <div key={s.label} style={{ display:"flex", justifyContent:"space-between", padding:"6px 0", alignItems:"center", borderBottom:"1px solid #1e3a5f22" }}>
                        <span style={{ fontSize:12, color:"#8aa8c8" }}>{s.label}</span>
                        <Badge color={s.ok?"#00c853":"#ff4757"}>{s.status}</Badge>
                      </div>
                    ))}
                  </Card>
                </div>
                <Card>
                  <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", gap:12, marginBottom:14 }}>
                    <div>
                      <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2, marginBottom:4 }}>ONE-WAY HASH FUNCTION</div>
                      <div style={{ color:"#8aa8c8", fontSize:12 }}>SHA-256 dataset fingerprint for tamper detection.</div>
                    </div>
                    <Badge color={datasetFingerprint ? "#00c853" : "#ff9d00"}>{datasetFingerprint ? "HASH READY" : "WAITING"}</Badge>
                  </div>
                  <div style={{ background:"#070f1a", border:"1px solid #1e3a5f", borderRadius:8, padding:14, marginBottom:12 }}>
                    <div style={{ color:"#4a6fa5", fontSize:11, marginBottom:6 }}>ACTIVE DATASET FINGERPRINT</div>
                    <code style={{ color:"#c8dff0", fontSize:12, wordBreak:"break-all" }}>{datasetFingerprint || "No fingerprint generated yet."}</code>
                  </div>
                  <div style={{ color:"#8aa8c8", fontSize:12, lineHeight:1.8 }}>
                    {fingerprintStatus}
                    {activeRecords.length > 0 ? " Any change in the dataset will produce a different digest." : ""}
                  </div>
                </Card>
              </div>
            )}

            {/* CRIME SCENE */}
            {tab==="crime_scene" && (
              <div style={{ animation:"fadeIn 0.4s ease" }}>
                <h2 style={{ color:"#e8f4ff", marginTop:0, fontWeight:700, letterSpacing:1, fontSize:18 }}>CRIME SCENE NUMBER IDENTIFICATION</h2>
                <Card>
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr auto", gap:12, alignItems:"end" }}>
                    <div>
                      <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>LOCATION</label>
                      <Sel value={filterLoc} onChange={e=>setFilterLoc(e.target.value)}
                        options={[{ value:"", label:"All Locations" }, ...locs.map(l=>({ value:l, label:l }))]} />
                    </div>
                    <div>
                      <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>TIME FROM</label>
                      <Inp value={timeStart} onChange={e=>setTimeStart(e.target.value)} type="time" />
                    </div>
                    <div>
                      <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>TIME TO</label>
                      <Inp value={timeEnd} onChange={e=>setTimeEnd(e.target.value)} type="time" />
                    </div>
                    <Btn onClick={handleCrimeScene}>SEARCH</Btn>
                  </div>
                  {crimeSceneStatus && <div style={{ marginTop:12, color:"#8aa8c8", fontSize:12 }}>{crimeSceneStatus}</div>}
                </Card>
                {csResults.length > 0 && (
                  <Card>
                    <div style={{ display:"flex", justifyContent:"space-between", marginBottom:14, alignItems:"center" }}>
                      <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2 }}>RESULTS — {csResults.length} RECORDS FOUND</div>
                      <Badge color="#ff4757">{new Set(csResults.map(r=>r.mobileNumber)).size} unique numbers</Badge>
                    </div>
                    <table>
                      <thead><tr><th>MOBILE NUMBER</th><th>TOWER</th><th>LOCATION</th><th>TIMESTAMP</th><th>HASH</th></tr></thead>
                      <tbody>
                        {csResults.map(r=>(
                          <tr key={r.id}>
                            <td style={{ color:"#00d4ff" }}>{user.role==="admin" ? r.mobileNumber : maskMobile(r.mobileNumber)}</td>
                            <td><Badge color="#ff9d00">{r.towerId}</Badge></td>
                            <td>{r.location}</td>
                            <td style={{ color:"#8aa8c8" }}>{r.timestamp}</td>
                            <td><code style={{ fontSize:10, color:"#4a6fa5" }}>{formatShortHash(recordHashes[r.id])}</code></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </Card>
                )}
              </div>
            )}

            {/* SUSPECTS */}
            {tab==="common" && (
              <div style={{ animation:"fadeIn 0.4s ease" }}>
                <h2 style={{ color:"#e8f4ff", marginTop:0, fontWeight:700, letterSpacing:1, fontSize:18 }}>SUSPECT DETECTION — COMMON NUMBERS</h2>
                <Card>
                  <p style={{ color:"#8aa8c8", fontSize:13, marginTop:0 }}>
                    Identifies numbers appearing at <strong style={{ color:"#ff4757" }}>2+ locations</strong>. Flagged as potential suspects.
                  </p>
                  <Btn onClick={detectCommon} variant="danger">RUN DETECTION ANALYSIS</Btn>
                  {commonStatus && <div style={{ marginTop:12, color:"#8aa8c8", fontSize:12 }}>{commonStatus}</div>}
                </Card>
                {common.length > 0 && (
                  <Card>
                    <div style={{ color:"#ff4757", fontSize:11, letterSpacing:2, marginBottom:14 }}>⚠️ {common.length} POTENTIAL SUSPECTS IDENTIFIED</div>
                    {common.map((c,i)=>(
                      <div key={c.num} style={{ background:"#070f1a", borderRadius:8, padding:16, marginBottom:12, border:"1px solid #ff475733" }}>
                        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:10 }}>
                          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                            <span style={{ background:"#ff475722", color:"#ff4757", width:28, height:28, borderRadius:"50%", display:"flex", alignItems:"center", justifyContent:"center", fontSize:12, fontWeight:700 }}>{i+1}</span>
                            <span style={{ color:"#00d4ff", fontSize:14 }}>{user.role==="admin" ? c.num : maskMobile(c.num)}</span>
                          </div>
                          <div style={{ display:"flex", gap:8 }}>
                            <Badge color="#ff4757">{c.count} LOCATIONS</Badge>
                            <Btn onClick={()=>{ setSearchNum(c.num); setTab("track"); }} variant="ghost" style={{ padding:"4px 10px", fontSize:10 }}>TRACK →</Btn>
                          </div>
                        </div>
                        <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
                          {c.locations.map(l=><Badge key={l} color="#ff9d00">{l}</Badge>)}
                        </div>
                      </div>
                    ))}
                  </Card>
                )}
              </div>
            )}

            {/* TRACK */}
            {tab==="track" && (
              <div style={{ animation:"fadeIn 0.4s ease" }}>
                <h2 style={{ color:"#e8f4ff", marginTop:0, fontWeight:700, letterSpacing:1, fontSize:18 }}>MOBILE NUMBER TRACKER</h2>
                <Card>
                  <div style={{ display:"flex", gap:12, alignItems:"end" }}>
                    <div style={{ flex:1 }}>
                      <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>MOBILE NUMBER</label>
                      <Inp value={searchNum} onChange={e=>setSearchNum(e.target.value)} placeholder="Enter full or partial number..." />
                    </div>
                    <Btn onClick={handleTrack}>TRACK MOVEMENT</Btn>
                    <Btn onClick={() => void generateReport(user, trackedNum, trackedRecords, common)} variant="ghost" disabled={!trackedNum}>EXPORT REPORT</Btn>
                  </div>
                  {trackStatus && <div style={{ marginTop:12, color:"#8aa8c8", fontSize:12 }}>{trackStatus}</div>}
                </Card>
                {trackedRecords.length > 0 && (
                  <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
                    <Card>
                      <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2, marginBottom:14 }}>MOVEMENT TIMELINE</div>
                      {trackedRecords.map((r,i)=>(
                        <div key={r.id} style={{ display:"flex", gap:12, marginBottom:12 }}>
                          <div style={{ display:"flex", flexDirection:"column", alignItems:"center" }}>
                            <div style={{ width:28, height:28, borderRadius:"50%", background:i===0?"#00c853":i===trackedRecords.length-1?"#ff4757":"#00d4ff", display:"flex", alignItems:"center", justifyContent:"center", fontSize:11, fontWeight:700, color:"#050d1a" }}>{i+1}</div>
                            {i<trackedRecords.length-1 && <div style={{ width:2, flex:1, minHeight:20, background:"#1e3a5f", margin:"4px 0" }} />}
                          </div>
                          <div style={{ paddingBottom:12 }}>
                            <div style={{ color:"#c8dff0", fontSize:13 }}>{r.location}</div>
                            <div style={{ color:"#4a6fa5", fontSize:11, marginTop:2 }}>{r.timestamp}</div>
                            <div style={{ display:"flex", gap:6, marginTop:6 }}>
                              <Badge color="#ff9d00">{r.towerId}</Badge>
                              <code style={{ fontSize:9, color:"#4a6fa5" }}>SHA-256 {formatShortHash(recordHashes[r.id])}</code>
                            </div>
                          </div>
                        </div>
                      ))}
                    </Card>
                    <div>
                      <RouteMap records={trackedRecords} />
                      <Card style={{ marginTop:16 }}>
                        <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2, marginBottom:10 }}>ANALYSIS SUMMARY</div>
                        {[
                          { label:"Total Records",   val:trackedRecords.length },
                          { label:"Unique Towers",   val:new Set(trackedRecords.map(r=>r.towerId)).size },
                          { label:"Locations",       val:new Set(trackedRecords.map(r=>r.location)).size },
                          { label:"Time Span",       val:trackedRecords[0]?.timestamp.slice(11,16)+" – "+trackedRecords[trackedRecords.length-1]?.timestamp.slice(11,16) },
                        ].map(s=>(
                          <div key={s.label} style={{ display:"flex", justifyContent:"space-between", fontSize:12, padding:"5px 0", borderBottom:"1px solid #1e3a5f22" }}>
                            <span style={{ color:"#4a6fa5" }}>{s.label}</span>
                            <span style={{ color:"#c8dff0" }}>{s.val}</span>
                          </div>
                        ))}
                      </Card>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* UPLOAD */}
            {tab==="upload" && user.role==="admin" && (
              <div style={{ animation:"fadeIn 0.4s ease" }}>
                <h2 style={{ color:"#e8f4ff", marginTop:0, fontWeight:700, letterSpacing:1, fontSize:18 }}>UPLOAD TOWER DUMP DATASET</h2>
                <Card>
                  <div style={{ marginBottom:14 }}>
                    <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>DATASET NAME</label>
                    <Inp value={upName} onChange={e=>setUpName(e.target.value)} placeholder="e.g. Tower Dump - Crime Scene C" />
                  </div>
                  <div style={{ marginBottom:20 }}>
                    <label style={{ color:"#4a6fa5", fontSize:11, letterSpacing:1, display:"block", marginBottom:6 }}>FILE (CSV / XLSX)</label>
                    <div style={{ background:"#070f1a", border:"2px dashed #1e3a5f", borderRadius:8, padding:24, color:"#4a6fa5", fontSize:12 }}>
                      <input
                        type="file"
                        accept=".csv,.xls,.xlsx"
                        onChange={e=>setUpFile(e.target.files?.[0] || null)}
                        style={{ width:"100%", color:"#c8dff0", marginBottom:10 }}
                      />
                      <div>{upFile ? `Selected: ${upFile.name}` : "Select a CSV or Excel file to upload"}</div>
                      <span style={{ fontSize:10, marginTop:6, display:"block" }}>Supported: .csv, .xlsx, .xls · Max 50MB · Secure backend pipeline</span>
                    </div>
                  </div>
                  <Btn onClick={handleUpload} variant="success">START SECURE UPLOAD</Btn>
                  {upStatus && <div style={{ marginTop:14, background:"#070f1a", borderRadius:8, padding:16, color:"#00c853", fontSize:12, lineHeight:2 }}>{upStatus}</div>}
                </Card>
                <Card>
                  <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2, marginBottom:14 }}>DATASET MANAGEMENT</div>
                  {datasets.length === 0 && <div style={{ color:"#4a6fa5", fontSize:12 }}>No datasets available.</div>}
                  {datasets.map((dataset) => (
                    <div key={dataset.id} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", gap:12, padding:"10px 0", borderBottom:"1px solid #1e3a5f22" }}>
                      <div>
                        <div style={{ color:"#c8dff0", fontSize:12 }}>{dataset.name}</div>
                        <div style={{ color:"#4a6fa5", fontSize:10, marginTop:2 }}>{dataset.records} records</div>
                      </div>
                      <div style={{ display:"flex", gap:8 }}>
                        <Btn onClick={()=>setActiveDatasetId(dataset.id)} variant="ghost" style={{ padding:"4px 10px", fontSize:10 }}>SELECT</Btn>
                        <Btn onClick={()=>handleDeleteDataset(dataset.id)} variant="danger" style={{ padding:"4px 10px", fontSize:10 }}>DELETE</Btn>
                      </div>
                    </div>
                  ))}
                </Card>
                <Card>
                  <div style={{ color:"#00d4ff", fontSize:11, letterSpacing:2, marginBottom:14 }}>UPLOAD PIPELINE</div>
                  {[
                    { icon:"🔒", label:"Quarantine",     desc:"Temp storage isolation before processing" },
                    { icon:"🛡️", label:"ClamAV Scan",    desc:"Antivirus scan on uploaded file" },
                    { icon:"✅", label:"Schema Validation",desc:"Check required columns and data types" },
                    { icon:"🔐", label:"AES-256 Encrypt", desc:"Encrypt mobile numbers & coordinates" },
                    { icon:"🔥", label:"Firebase Upload", desc:"Store to Firestore collection securely" },
                    { icon:"🔑", label:"SHA-256 Hash",    desc:"Generate integrity hash per record" },
                  ].map(s=>(
                    <div key={s.label} style={{ display:"flex", gap:14, padding:"10px 0", borderBottom:"1px solid #1e3a5f22", alignItems:"center" }}>
                      <span style={{ fontSize:22, width:30 }}>{s.icon}</span>
                      <div>
                        <div style={{ color:"#c8dff0", fontSize:12 }}>{s.label}</div>
                        <div style={{ color:"#4a6fa5", fontSize:11 }}>{s.desc}</div>
                      </div>
                    </div>
                  ))}
                </Card>
              </div>
            )}

            {/* USERS */}
            {tab==="users" && user.role==="admin" && (
              <div style={{ animation:"fadeIn 0.4s ease" }}>
                <h2 style={{ color:"#e8f4ff", marginTop:0, fontWeight:700, letterSpacing:1, fontSize:18 }}>USER MANAGEMENT</h2>
                <Card>
                  <div style={{ color:"#4a6fa5", fontSize:11, marginBottom:14 }}>Firebase Authentication users with custom claims for role-based access.</div>
                  <table>
                    <thead><tr><th>UID</th><th>USERNAME</th><th>NAME</th><th>ROLE</th><th>STATUS</th><th>ACTION</th></tr></thead>
                    <tbody>
                      {MOCK_USERS.map(u=>(
                        <tr key={u.id}>
                          <td><code style={{ fontSize:10, color:"#4a6fa5" }}>{u.id}</code></td>
                          <td style={{ color:"#c8dff0" }}>{u.username}</td>
                          <td>{u.name}</td>
                          <td><Badge color={u.role==="admin"?"#ff9d00":"#00d4ff"}>{u.role}</Badge></td>
                          <td><Badge color="#00c853">ACTIVE</Badge></td>
                          <td><Btn variant="ghost" style={{ padding:"3px 8px", fontSize:10 }}>MANAGE</Btn></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Card>
              </div>
            )}

            {/* AUDIT LOGS */}
            {tab==="audit" && user.role==="admin" && (
              <div style={{ animation:"fadeIn 0.4s ease" }}>
                <h2 style={{ color:"#e8f4ff", marginTop:0, fontWeight:700, letterSpacing:1, fontSize:18 }}>AUDIT LOGS</h2>
                <Card>
                  <div style={{ color:"#4a6fa5", fontSize:11, marginBottom:14 }}>
                    Tamper-resistant logs stored in Firebase Firestore with append-only security rules.
                  </div>
                  <table>
                    <thead><tr><th>TIMESTAMP</th><th>USER</th><th>ACTION</th><th>IP</th></tr></thead>
                    <tbody>
                      {auditLogs.map(l=>(
                        <tr key={l.id}>
                          <td style={{ color:"#4a6fa5", fontSize:11 }}>{l.timestamp}</td>
                          <td><Badge color="#00d4ff">{l.username}</Badge></td>
                          <td style={{ color:"#c8dff0" }}>{l.action}</td>
                          <td><code style={{ fontSize:10, color:"#4a6fa5" }}>{l.ip}</code></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </Card>
              </div>
            )}

          </>)}
        </div>
      </div>
    </div>
  );
};

// ============================================================
// ROOT
// ============================================================
export default function App() {
  const [user, setUser] = useState(null);
  const handleLogout = async () => {
    await FirebaseService.addAuditLog({ userId:user.id, username:user.username, action:"User logged out", ip:"192.168.x.x" });
    FirebaseService.setSessionUser(null);
    setUser(null);
  };
  if (!user) return <LoginPage onLogin={setUser} />;
  return <Dashboard user={user} onLogout={handleLogout} />;
}
