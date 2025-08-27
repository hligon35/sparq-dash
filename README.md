# SparQ Email Admin Dashboard

A Node.js/Express app for managing client email domains and accounts.

## Quick start

1) Install Node.js LTS (v18+ recommended).
2) Install deps:
   - Windows PowerShell: `npm install`
3) Run:
   - PowerShell (one-off port): `$env:PORT=4000; npm start`
   - Default port 3003: `npm start`
4) Open: http://localhost:3003/login.html (or port you choose)

Default admin users are defined in `auth.js` (e.g., `hligon`).

## Production setup

- Reverse proxy: nginx/Cloudflare; terminate TLS at the edge.
- Sessions: use Redis in production (`REDIS_URL`).
- Security:
  - `NODE_ENV=production`
  - `SESSION_SECRETS=comma,separated,secrets`
  - `SESSION_DOMAIN=.yourdomain.com`
  - `CORS_ORIGINS=https://admin.yourdomain.com,https://portal.yourdomain.com`
  - `RATE_LIMIT=300`
- SMTP for notifications:
  - `EMAIL_SMTP_HOST=smtp.yourdomain.com`
  - `EMAIL_SMTP_PORT=587`
  - `EMAIL_SMTP_SECURE=false`
  - `EMAIL_SMTP_USER=...`
  - `EMAIL_SMTP_PASS=...`
  - `EMAIL_FROM="SparQ Email Admin" <no-reply@yourdomain.com>`
- Data persistence:
  - `CONFIG_PATH=/var/lib/sparq/email-admin-config.json`\r
- SparQ Plug proxy (optional):
  - `SPARQ_PLUG_URL=https://sparqplug.yourdomain.com`
  - `SPARQ_PLUG_SSO_SECRET=...`

## Windows compatibility

Native `bcrypt` can fail on Windows. This app uses `bcrypt-compat.js` to fall back to `bcryptjs` automatically.

## Healthcheck

- `GET /healthz` -> `{ ok: true }`

## Scripts

- `npm start` – start server
- `npm run dev` – nodemon (auto-reload)

## Example .env

See `.env.example`.
