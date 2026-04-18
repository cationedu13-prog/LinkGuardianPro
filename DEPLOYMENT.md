# LinkGuardian Pro – Complete Deployment Guide

## Overview of Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Users → Vercel (Frontend: HTML/CSS/JS static files)        │
│       ↕ API calls                                           │
│  Railway (Backend: Flask + Python)                          │
│       ↕ Database                                            │
│  Supabase (PostgreSQL)                                      │
│                                                             │
│  GitHub Actions → Railway backend (cron: 6AM + 6PM UTC)    │
│  Railway backend → Telegram Bot API (alerts)                │
└─────────────────────────────────────────────────────────────┘
```

---

## STEP 1 — Supabase Setup

### 1.1 Create Supabase Project
1. Go to https://supabase.com and create a free account
2. Click **New Project**
3. Enter project name: `linkguardian-pro`
4. Set a strong database password (save it!)
5. Choose region closest to your users (e.g., `ap-south-1` for India)
6. Click **Create new project** and wait ~2 minutes

### 1.2 Run the Database Schema
1. In Supabase dashboard → **SQL Editor** → **New Query**
2. Paste the full contents of `database/schema.sql`
3. Click **Run** (green play button)
4. You should see "Success. No rows returned." for each statement
5. Go to **Table Editor** to verify all 7 tables were created:
   - `users`, `links`, `check_history`, `alerts`, `payments`, `sessions`, `rate_limits`

### 1.3 Get Your API Keys
1. Go to **Project Settings** → **API**
2. Copy these values (you'll need them for .env):
   - **Project URL** → `SUPABASE_URL`  (e.g., `https://abcdef.supabase.co`)
   - **anon public** key → `SUPABASE_KEY`
   - **service_role** key → `SUPABASE_SERVICE_KEY` ⚠️ **KEEP SECRET — never expose in frontend**

---

## STEP 2 — Telegram Bot Setup

### 2.1 Create Bot via BotFather
1. Open Telegram and search for **@BotFather**
2. Send `/newbot`
3. Choose a name: e.g., `LinkGuardian Alerts`
4. Choose a username: e.g., `linkguardian_alerts_bot`
5. BotFather will reply with your **bot token** — looks like `123456789:ABCDefGhIJKlmNoPQRstuVwXyz`
6. Copy this token → `TELEGRAM_BOT_TOKEN` in `.env`

### 2.2 Test Your Bot
1. Search for your bot username in Telegram
2. Click **Start**
3. Send any message
4. To get your chat ID, message **@userinfobot** on Telegram

---

## STEP 3 — Railway Backend Deployment

### 3.1 Prepare Repository
```bash
# Clone or create your project
git init linkguardian-pro
cd linkguardian-pro

# Copy all project files into this directory
# Your structure should be:
# linkguardian-pro/
#   backend/
#     app.py, monitor.py, alerts.py
#     requirements.txt, railway.json
#     nixpacks.toml, Procfile, .env.example
#   frontend/
#     index.html, dashboard.html, login.html, signup.html
#     style.css, terms.html, privacy.html, help.html
#     about.html, contact.html
#   database/
#     schema.sql
#   .github/workflows/scheduler.yml
#   vercel.json

git add .
git commit -m "Initial LinkGuardian Pro"
```

### 3.2 Push to GitHub
```bash
# Create repo on github.com first, then:
git remote add origin https://github.com/YOUR_USERNAME/linkguardian-pro.git
git push -u origin main
```

### 3.3 Deploy on Railway
1. Go to https://railway.app and sign up/login
2. Click **New Project** → **Deploy from GitHub repo**
3. Connect your GitHub account and select `linkguardian-pro`
4. Railway will auto-detect Python and start building

### 3.4 Set Root Directory (Important!)
1. In Railway dashboard → your service → **Settings**
2. Under **Source** → set **Root Directory** to `backend`
3. Click **Save** → Railway will redeploy

### 3.5 Configure Environment Variables on Railway
1. In Railway → your service → **Variables** tab
2. Click **Raw Editor** and paste (fill in your values):

```
FLASK_SECRET_KEY=generate-a-64-char-random-string-here
FLASK_ENV=production
SUPABASE_URL=https://your-project-ref.supabase.co
SUPABASE_KEY=your-supabase-anon-key
SUPABASE_SERVICE_KEY=your-supabase-service-role-key
CRON_API_KEY=generate-another-random-string-here
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
SCRAPER_API_KEY=your-scraperapi-key-optional
ENABLE_PLAYWRIGHT=false
FREE_CHECKER_LIMIT=10
FRONTEND_URL=https://your-app.vercel.app
```

**Generate random keys:**
```python
import secrets
print(secrets.token_hex(32))  # Run this twice for FLASK_SECRET_KEY and CRON_API_KEY
```

### 3.6 Get Your Railway URL
1. Railway → your service → **Settings** → **Networking**
2. Click **Generate Domain** to get a public URL
3. Note this URL: `https://your-app.up.railway.app` — you'll need it for:
   - `FRONTEND_URL` environment variable
   - GitHub Actions `BACKEND_URL` secret
   - The API base URL in frontend files (see Step 4.4)

### 3.7 Verify Deployment
```bash
curl https://your-app.up.railway.app/api/health
# Should return: {"status":"ok","service":"LinkGuardian Pro"}
```

---

## STEP 4 — Vercel Frontend Deployment

### 4.1 Update API Base URL in Frontend
Before deploying frontend, update all `const API = '';` references in HTML files to point to your Railway backend URL.

In `frontend/index.html`, `dashboard.html`, `login.html`, `signup.html`:
```javascript
// Change this:
const API = '';
// To this:
const API = 'https://your-app.up.railway.app';
```

**Or** keep `const API = ''` if you configure Vercel rewrites to proxy `/api/*` to Railway (recommended for CORS simplicity — see Step 4.3).

### 4.2 Deploy to Vercel
1. Go to https://vercel.com and sign up/login
2. Click **Add New** → **Project**
3. Import your GitHub repository
4. In **Configure Project**:
   - Framework Preset: **Other**
   - Root Directory: leave blank (project root)
   - Build Command: leave blank
   - Output Directory: `frontend`
5. Click **Deploy**

### 4.3 Configure Vercel Rewrites (Recommended)
Add this to `vercel.json` to proxy API calls through Vercel to Railway (avoids CORS issues):

```json
{
  "rewrites": [
    {
      "source": "/api/:path*",
      "destination": "https://your-railway-app.up.railway.app/api/:path*"
    }
  ]
}
```

Then you can keep `const API = ''` in all HTML files.

### 4.4 Get Your Vercel URL
- After deployment: `https://your-project.vercel.app`
- Set this as `FRONTEND_URL` in Railway environment variables
- Optional: Add a custom domain in Vercel → Settings → Domains

---

## STEP 5 — GitHub Actions Cron Setup

### 5.1 Add GitHub Secrets
1. Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret** and add:

| Secret Name   | Value                                          |
|---------------|------------------------------------------------|
| `BACKEND_URL` | `https://your-app.up.railway.app`              |
| `CRON_API_KEY`| Same value as your Railway `CRON_API_KEY` env  |

### 5.2 Enable GitHub Actions
1. Go to your repo → **Actions** tab
2. If prompted, click **Enable GitHub Actions**
3. The workflow file at `.github/workflows/scheduler.yml` will auto-activate
4. It runs at 6:00 AM and 6:00 PM UTC every day

### 5.3 Test the Cron Manually
1. Go to **Actions** → **LinkGuardian – Scheduled Link Checks**
2. Click **Run workflow** → **Run workflow** button
3. Check the logs to confirm it calls your backend successfully

### 5.4 Verify Cron Runs (first scheduled run)
```bash
# Check Railway logs after 6 AM UTC
# Should see: "=== Cron: daily-check started ==="
# And: "=== Cron done: X links checked, Y alerts sent ==="
```

---

## STEP 6 — ScraperAPI Setup (Optional — Layer 2)

ScraperAPI improves accuracy for Amazon/Flipkart by rendering JavaScript:

1. Sign up at https://www.scraperapi.com (free tier: 1,000 credits/month)
2. Copy your API key from the dashboard
3. Add to Railway env vars: `SCRAPER_API_KEY=your-key`
4. Cost estimate: Each Layer 2 check uses ~1–5 credits. 1,000 credits/month ≈ 200–1,000 Layer 2 checks

---

## STEP 7 — Playwright Setup (Optional — Layer 3)

Playwright (headless Chromium) is the most powerful but resource-intensive:

1. In Railway env vars, set: `ENABLE_PLAYWRIGHT=true`
2. The `nixpacks.toml` already installs Chromium dependencies
3. Note: Railway free tier may not have enough RAM for Playwright. Upgrade to Starter plan ($5/month) for reliable Layer 3 checks
4. Recommended: Only enable if Layers 1 & 2 are insufficient for your use case

---

## STEP 8 — Configure Telegram Chat IDs

For each user to receive alerts:

1. User opens Telegram → searches for your bot username (e.g., `@linkguardian_alerts_bot`)
2. User clicks **Start** to initialize the chat
3. User messages **@userinfobot** to get their Chat ID
4. User goes to Dashboard → Settings → pastes their Chat ID → Save

**Test alert manually (from server console):**
```python
from alerts import send_telegram_message
send_telegram_message("USER_CHAT_ID", "🧪 Test alert from LinkGuardian Pro!")
```

---

## STEP 9 — Custom Domain (Optional)

### Vercel (Frontend)
1. Vercel → your project → **Settings** → **Domains**
2. Add your domain (e.g., `linkguardian.pro`)
3. Add the DNS records shown at your domain registrar

### Railway (Backend)
1. Railway → service → **Settings** → **Networking** → **Custom Domain**
2. Add `api.linkguardian.pro` (or `backend.linkguardian.pro`)
3. Update DNS with the CNAME record provided
4. Update `FRONTEND_URL` and all `const API` references accordingly

---

## STEP 10 — Post-Deployment Checklist

- [ ] Supabase schema created (all 7 tables visible in Table Editor)
- [ ] Railway backend live and `/api/health` returns 200
- [ ] Vercel frontend deployed and accessible
- [ ] Test free checker on homepage — returns status/response_time
- [ ] Test signup → creates user in Supabase `users` table
- [ ] Test login → session cookie set, redirects to dashboard
- [ ] Add a test link → appears in dashboard
- [ ] "Check Now" button returns a status result
- [ ] Telegram alert: set chat ID in settings, trigger a manual check on a known broken URL
- [ ] GitHub Actions: manually trigger workflow, verify it calls backend
- [ ] Verify environment variables don't have typos (common failure point)

---

## Troubleshooting

### "Module not found" on Railway
```bash
# Check root directory is set to /backend in Railway settings
# Verify requirements.txt has all packages
```

### CORS errors in browser console
```bash
# Option 1: Add Vercel rewrite to proxy /api/* → Railway (recommended)
# Option 2: Set FRONTEND_URL in Railway to your exact Vercel URL
# Option 3: In app.py, change origins=["*"] temporarily to debug
```

### Supabase connection error
```bash
# Verify SUPABASE_URL starts with https://
# Verify SUPABASE_SERVICE_KEY is the service_role key (not anon key)
# service_role key starts with "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### GitHub Actions fails with 403
```bash
# Verify CRON_API_KEY in GitHub Secrets matches exactly the Railway env var
# No trailing spaces or newlines in the secret value
```

### Telegram alerts not arriving
```bash
# 1. Verify TELEGRAM_BOT_TOKEN is correct (test: curl https://api.telegram.org/botTOKEN/getMe)
# 2. User must have started a chat with the bot first
# 3. Chat ID must be numeric string, no spaces
# 4. Check Railway logs for "Telegram API error" messages
```

### Playwright crashes on Railway
```bash
# Add to Railway env vars:
# ENABLE_PLAYWRIGHT=false  (disable until you upgrade to paid plan)
# Layer 1 + ScraperAPI is sufficient for most use cases
```

---

## Environment Variables Quick Reference

| Variable              | Where to set  | Description                              |
|-----------------------|---------------|------------------------------------------|
| `FLASK_SECRET_KEY`    | Railway       | Random 32+ char string for sessions      |
| `SUPABASE_URL`        | Railway       | Your Supabase project URL                |
| `SUPABASE_KEY`        | Railway       | Supabase anon/public key                 |
| `SUPABASE_SERVICE_KEY`| Railway       | Supabase service role key (keep secret!) |
| `CRON_API_KEY`        | Railway + GH  | Random key protecting cron endpoint      |
| `TELEGRAM_BOT_TOKEN`  | Railway       | From @BotFather on Telegram              |
| `SCRAPER_API_KEY`     | Railway       | Optional: scraperapi.com API key         |
| `ENABLE_PLAYWRIGHT`   | Railway       | `true`/`false` — Layer 3 toggle          |
| `FRONTEND_URL`        | Railway       | Your Vercel URL (for CORS)               |
| `FREE_CHECKER_LIMIT`  | Railway       | Checks/hour per IP (default: 10)         |
| `BACKEND_URL`         | GitHub Secret | Your Railway URL (for cron job)          |

---

## Cost Breakdown (Free Tier Possible!)

| Service        | Free Tier                            | Paid Starts At     |
|----------------|--------------------------------------|--------------------|
| Supabase       | 500MB DB, 2GB bandwidth              | $25/month          |
| Railway        | $5 free credit/month (≈ hobby use)   | $5/month           |
| Vercel         | 100GB bandwidth, unlimited projects  | $20/month          |
| GitHub Actions | 2,000 min/month (plenty for 60 runs) | Free for public    |
| ScraperAPI     | 1,000 credits/month                  | $49/month          |
| Telegram Bot   | Free forever                         | —                  |
| **Total**      | **$0 to get started**                | ~$30/month for pro |

---

## File Structure Summary

```
linkguardian-pro/
├── backend/
│   ├── app.py              # Flask application (main)
│   ├── monitor.py          # Multi-layer link checker
│   ├── alerts.py           # Telegram/WhatsApp alerts
│   ├── requirements.txt    # Python dependencies
│   ├── railway.json        # Railway deployment config
│   ├── nixpacks.toml       # Railway build config (Playwright)
│   ├── Procfile            # Gunicorn start command
│   └── .env.example        # Environment variables template
├── frontend/
│   ├── index.html          # Landing page + free checker
│   ├── dashboard.html      # User dashboard (protected)
│   ├── login.html          # Login page
│   ├── signup.html         # Signup page
│   ├── style.css           # All styles (mobile-first)
│   ├── terms.html          # Terms of Service
│   ├── privacy.html        # Privacy Policy
│   ├── help.html           # FAQ / Help
│   ├── about.html          # About page
│   └── contact.html        # Contact page
├── database/
│   └── schema.sql          # Supabase PostgreSQL schema
├── .github/
│   └── workflows/
│       └── scheduler.yml   # GitHub Actions cron (twice daily)
├── vercel.json             # Vercel deployment config
└── .gitignore
```
