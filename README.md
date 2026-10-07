# Rebel Ink — Full client portal (Render Web Service + PostgreSQL)

Persistent tattoo studio portal with admin panel, member accounts, and appointments.

## Features included

1. **Admin alerts** — optional webhook (`NOTIFY_WEBHOOK_URL`) fires on every new registration and appointment (Discord / Slack / Telegram-compatible JSON).
2. **Clear client status messages** — pending / approved / suspended; appointments show "Approved — you are good to go".
3. **Admin search & filters** — search by name/email/phone; filter by member status and booking status.
4. **Appointment calendar list** — all appointments by date at the top of the admin panel; approve/reject from there.
5. **Photo limits** — max 5 images per booking, size-capped.
6. **Admin notes** — internal notes per member + notes visible to the client on appointments.
7. **CSV export** — download all members and appointments.
8. **Password reset** — intentionally disabled until you add real email delivery (no insecure reset).
9. **Custom domain** — point your domain at the Render service (Render → Settings → Custom Domains).
10. **Keep-alive + Postgres** — use a free uptime bot so the site stays warm; Postgres keeps data forever across devices and redeploys.
11. **10-second auto-refresh** — admin panel and member dashboard both poll for updates.
12. **No default admin login** — first admin is created once via `/admin-setup?token=...`.

## Deploy on Render

### 1. Push code
Repo root must contain: `server.js`, `package.json`, `public/`.

### 2. Create PostgreSQL
Render → **New → PostgreSQL** → Free → Create → copy **Internal Database URL**.

### 3. Create Web Service
Render → **New → Web Service**
- Build: `npm install`
- Start: `npm start`
- Plan: Free

### 4. Environment variables

| Key | Required | Value |
|-----|----------|--------|
| `DATABASE_URL` | **Yes** | Internal Database URL from Postgres |
| `JWT_SECRET` | Recommended | `openssl rand -hex 32` |
| `ADMIN_SETUP_TOKEN` | Recommended | `openssl rand -hex 24` |
| `NOTIFY_WEBHOOK_URL` | Optional | Discord/Slack/Telegram webhook URL for new sign-ups & bookings |

### 5. First admin
Logs → `FIRST ADMIN SETUP REQUIRED. Open /admin-setup?token=...` → open URL → choose your email/password.

### 6. Optional keep-alive
Point UptimeRobot / cron-job.org / similar at `https://your-service.onrender.com/api/health` every 5 minutes.

### 7. Optional custom domain
Render Web Service → Settings → Custom Domains → add your domain → set DNS as shown.

## Free Postgres note
Free databases expire after **30 days**. Upgrade the database plan before then if you need the data longer.

## Health
`GET /api/health`
