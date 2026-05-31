# LinkGuardian Pro — Koyeb + Vercel Deploy Guide

## Project Structure

```
linkguardian-pro/
├── backend/               ← Deploy this folder to Koyeb
│   ├── app.py
│   ├── monitor.py
│   ├── alerts.py
│   ├── requirements.txt
│   ├── Procfile
│   └── runtime.txt
│
└── frontend/              ← Deploy this folder to Vercel
    ├── index.html
    ├── dashboard.html
    ├── login.html
    ├── signup.html
    ├── forgot-password.html
    ├── reset-password.html
    ├── help.html
    ├── about.html
    ├── contact.html
    ├── terms.html
    └── privacy.html
    vercel.json            ← Vercel config (root of repo)
```

---

## Step 1 — Supabase Setup

1. Go to [supabase.com](https://supabase.com) → New project
2. SQL Editor → New Query → paste entire `schema.sql` → Run
3. Settings → API → Copy:
   - **Project URL** → `SUPABASE_URL`
   - **service_role** key → `SUPABASE_SERVICE_KEY`

---

## Step 2 — Koyeb Backend Deploy

### 2a. Push to GitHub
```bash
git init
git add .
git commit -m "initial commit"
git remote add origin https://github.com/YOUR/REPO.git
git push -u origin main
```

### 2b. Create Koyeb Service
1. [koyeb.com](https://koyeb.com) → Deploy → GitHub
2. Select your repo, branch: `main`
3. **Build:** Buildpack (auto-detected from `Procfile` + `runtime.txt`)
4. **Root directory:** `backend` (or `.` if no subdirectory)
5. **Run command:** auto-detected from Procfile
6. **Port:** `8000` (Koyeb default) — OR set `PORT=8000` in env

### 2c. Set Environment Variables in Koyeb
Go to: Service → Settings → Environment variables

```
FLASK_SECRET_KEY     = <64-char random hex>
FLASK_ENV            = production
SUPABASE_URL         = https://xxx.supabase.co
SUPABASE_SERVICE_KEY = <service role key>
CRON_API_KEY         = <random secret>
ADMIN_SECRET         = <random secret>
TELEGRAM_BOT_TOKEN   = <bot token from @BotFather>
FRONTEND_URL         = https://your-app.vercel.app   ← fill after Step 3
SMTP_HOST            = smtp.gmail.com
SMTP_PORT            = 587
SMTP_USER            = your@gmail.com
SMTP_PASS            = <gmail app password>
FROM_EMAIL           = your@gmail.com
SCRAPER_API_KEY      =   ← leave empty initially
ENABLE_PLAYWRIGHT    = false   ← KEEP FALSE on free tier
FREE_CHECKER_LIMIT   = 10
```

### 2d. Note your Koyeb URL
Format: `https://YOUR-APP-NAME-RANDOM.koyeb.app`
You'll need this in Step 3.

---

## Step 3 — Vercel Frontend Deploy

### 3a. Update vercel.json
Open `vercel.json`, replace:
```
"https://YOUR_APP_NAME.koyeb.app/api/:path*"
```
with your actual Koyeb URL:
```
"https://linkguardian-pro-abc123.koyeb.app/api/:path*"
```

### 3b. Deploy to Vercel
```bash
npm i -g vercel
vercel --prod
```
OR connect GitHub repo at [vercel.com](https://vercel.com)

### 3c. Update FRONTEND_URL in Koyeb
After Vercel gives you a URL (e.g. `https://linkguardian-pro.vercel.app`):
- Go back to Koyeb → Environment variables
- Set `FRONTEND_URL = https://linkguardian-pro.vercel.app`
- Redeploy Koyeb service

---

## Step 4 — Cron Job Setup (cron-job.org — FREE)

Koyeb free tier has no built-in cron. Use [cron-job.org](https://cron-job.org):

1. Sign up free at cron-job.org
2. Create new cronjob:
   - **URL:** `https://YOUR-APP.koyeb.app/api/cron/daily-check`
   - **Method:** `POST`
   - **Schedule:** Every 1 hour (`0 * * * *`)
   - **Headers:** Add custom header:
     - Key: `X-Cron-Key`
     - Value: `<your CRON_API_KEY>`
3. Save and enable

---

## Step 5 — Telegram Bot Setup

1. Open Telegram → search `@BotFather` → `/newbot`
2. Name: `LinkGuardian Pro` / Username: `LinkGuardianProBot` (or any available)
3. Copy the bot token → set as `TELEGRAM_BOT_TOKEN` in Koyeb
4. Users need to: start the bot first, then get their Chat ID from `@userinfobot`

---

## Step 6 — Verify Everything Works

```bash
# 1. Health check
curl https://YOUR-APP.koyeb.app/api/health
# → {"status": "ok", "service": "LinkGuardian Pro"}

# 2. Manual cron test
curl -X POST https://YOUR-APP.koyeb.app/api/cron/daily-check \
  -H "X-Cron-Key: YOUR_CRON_API_KEY"
# → {"message": "Daily check complete", ...}

# 3. Free checker
curl -X POST https://YOUR-APP.koyeb.app/api/check-single \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com", "platform": "generic"}'
# → {"status": "active", ...}
```

---

## Important Notes

| Topic | Detail |
|-------|--------|
| **RAM** | Koyeb free = 512 MB. Never enable `ENABLE_PLAYWRIGHT=true` |
| **Sleep** | Koyeb free services sleep after inactivity. Cron job keeps it awake |
| **Workers** | `--workers 1 --threads 4` in Procfile — safe for 512 MB |
| **Cookies** | `SameSite=None; Secure` required for cross-origin (Vercel ↔ Koyeb) |
| **CORS** | `FRONTEND_URL` must exactly match your Vercel URL (no trailing slash) |
| **Playwright** | Layer 3 disabled. Layer 1 + 2 (ScraperAPI) work fine |
| **APScheduler** | Removed — external cron (cron-job.org) is more reliable |

---

## Troubleshooting

**Cookies not sent / 401 errors:**
- Verify `FRONTEND_URL` in Koyeb matches Vercel URL exactly
- Browser must support `SameSite=None` (all modern browsers do)
- Vercel must serve over HTTPS (it always does)

**CORS errors:**
- Check Koyeb logs: `FRONTEND_URL not set` warning?
- Add `https://www.your-domain.com` too if using custom domain

**Cron not working:**
- Check cron-job.org execution log
- Verify `X-Cron-Key` header value matches `CRON_API_KEY` exactly

**OOM / Memory crash:**
- Make sure `ENABLE_PLAYWRIGHT=false`
- Keep `--workers 1` in Procfile
