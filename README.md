# 🛡️ Tower Dump Investigation Platform

A secure full-stack cybersecurity application designed for law enforcement and forensic investigators to analyze telecom tower dump data while ensuring strong data protection, encryption, and auditability.

---

## 📌 Overview

The Tower Dump Investigation Platform allows investigators to securely upload, process, and analyze telecom datasets containing mobile numbers connected to specific towers.

Since this data is highly sensitive, the system implements strong cybersecurity controls including authentication, encryption, malware scanning, and audit logging.

---

## 🎯 Features

- Secure authentication using Firebase JWT  
- Role-Based Access Control (Admin / Investigator)  
- AES-256-GCM encryption for mobile numbers  
- SHA-256 hashing for data integrity  
- Secure file upload pipeline (quarantine + scanning)  
- Forensic analysis engine for suspicious activity detection  
- Mobile number masking for privacy  
- Audit logging for all critical actions  
- Protection against common attacks (rate limiting, CORS, headers)  

---

## 🏗️ Architecture

Frontend (React + Firebase)  
→ JWT Authentication  
→ Backend (Node.js + Express)  
→ Security Layer (RBAC, Helmet, Rate Limiting)  
→ Analysis Engine  
→ Encrypted Data Store (JSON)

---

## 👥 User Roles

Admin:
- Upload datasets  
- Delete datasets  
- Reveal mobile numbers  
- Manage users  
- View audit logs  

Investigator:
- View masked records  
- Run analysis  
- Track mobile numbers  

---

## 🔐 Security Implementation

Authentication:
- Firebase JWT tokens verified on every request  

Authorization:
- Role-based middleware to restrict access  

Encryption:
- AES-256-GCM encryption for sensitive data  

Integrity:
- SHA-256 hashing to detect tampering  

File Upload Security:
- Quarantine storage  
- Malware scanning (ClamAV + heuristics)  
- File validation and sanitization  

Network Protection:
- Helmet security headers  
- CORS restriction  
- Rate limiting  

Audit Logging:
- Logs all user actions including access attempts and data operations  

---

## 🔍 Forensic Analysis

The system detects suspicious patterns such as:
- Same mobile number appearing in multiple locations  
- Activity within a short time window (24 hours)  

This helps identify potential suspects in investigations.

---

## 📂 Project Structure

/server  
- app.js  
- middleware (auth, rbac, upload)  
- services (malwareScan, datasetValidator)  
- utils (crypto, auditLog, localStore)  

/frontend  
- tower-dump-app.jsx  
- firebase.js  

---

## 🔄 Data Flow

Secure Upload Process:
1. JWT authentication  
2. Role verification (admin only)  
3. File stored in quarantine  
4. Malware scanning  
5. Dataset validation  
6. Encryption of mobile numbers  
7. Audit log entry  

---

## 📡 API Endpoints

POST /api/datasets/upload → Admin → Upload dataset  
GET /api/datasets/records → Admin/Investigator → View records  
DELETE /api/datasets/:id → Admin → Delete dataset  
POST /api/analysis/track → Admin/Investigator → Track number  
POST /api/analysis/reveal/:flagId → Admin → Reveal number  
GET /api/admin/audit-logs → Admin → View logs  
GET /monitor → Dashboard  

---

## ⚙️ Setup

Clone the repository:
git clone https://github.com/vaishnavi545629/tower-dump-analysis-system.git

Install dependencies:
npm install

Create .env file:
AES_ENCRYPTION_KEY=your_key  
CORS_ORIGIN=http://localhost:1235  

Run project:
npm start  

---

## ⚠️ Security Notes

- Never upload .env or service account files  
- Always use .gitignore  
- Rotate keys if exposed  
- Use HTTPS in production  

---

## 🚀 Strengths

- Strong encryption and security layers  
- Secure file handling  
- Full audit trail  
- Privacy-preserving design  

---

## ⚠️ Future Improvements

- Use secure key vault (AWS / Vault)  
- Replace JSON with database  
- Enable HTTPS  
- Add real-time monitoring (SIEM)  

---

## 👨‍💻 Team

Vaishnavi Kidav 
Astha Patil   
Swapnil Mukherjee  

---

## 📜 Note

This project is for academic and research purposes only.
