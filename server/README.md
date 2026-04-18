# Tower Dump Analysis Backend

Secure backend for the Tower Dump Analysis System. Built with Node.js, Express, Firebase Admin SDK, and AES-256/SHA-256 utilities.

## Structure

```text
server/
|-- package.json
|-- .env.example
|-- quarantine/
`-- src/
    |-- index.js
    |-- app.js
    |-- config/firebase.js
    |-- middleware/
    |-- routes/
    |-- controllers/
    |-- services/
    `-- utils/
```

## Setup

1. Download a Firebase service account JSON and save it as `server/service-account.json`.
2. Copy `.env.example` to `.env`.
3. Set `AES_ENCRYPTION_KEY` to a 64-character hex string.
4. Set `CORS_ORIGIN=http://localhost:1235` for this Parcel frontend.
5. Run:

```bash
cd server
npm install
npm run dev
```

The backend starts on `http://localhost:3001`.

## Important Notes

- Frontend login is already real through Firebase Auth.
- Frontend datasets, records, uploads, and audit logs are still mock-driven until the frontend service layer is wired to this backend.
- Protected routes expect `Authorization: Bearer <firebase-id-token>`.
- The malware scan service currently has a simulated fallback until ClamAV is installed and enabled.

## Main Routes

- `GET /api/health`
- `POST /api/datasets/upload`
- `GET /api/datasets`
- `GET /api/datasets/:id`
- `GET /api/analysis/records/:datasetId`
- `POST /api/analysis/track`
- `POST /api/analysis/detect-suspicious/:datasetId`
- `GET /api/analysis/suspicious`
- `POST /api/analysis/reveal/:flagId`
- `GET /api/admin/audit-logs`
- `GET /api/admin/users`
- `PATCH /api/admin/users/:uid/role`
- `DELETE /api/admin/users/:uid`
