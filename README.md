# AffiGuard

Automated affiliate link monitoring with multi-layer detection and Telegram alerts.

## Architecture

| Layer     | Service                        |
|-----------|--------------------------------|
| Frontend  | Vercel (`/frontend`)           |
| Backend   | Render (`/backend`)            |
| Database  | Supabase (PostgreSQL)          |
| Alerts    | Telegram Bot API               |
| Cron      | cron-job.org                   |

## File Structure

```
affiguard-pro/
├── backend/
│   ├── app.py
│   ├── monitor.py
│   ├── alerts.py
│   ├── requirements.txt
│   ├── Procfile
│   ├── render.yaml
│   ├── runtime.txt
│   └── env.example
├── frontend/
│   ├── index.html
│   ├── dashboard.html
│   ├── login.html
│   ├── signup.html
│   ├── forgot-password.html
│   ├── reset-password.html
│   ├── about.html
│   ├── contact.html
│   ├── help.html
│   ├── privacy.html
│   ├── terms.html
│   ├── config.js          ← Set your Render URL here before deploying
│   └── vercel.json
├── database/
│   └── schema.sql
├── .gitignore
└── README.md
```

## Deploy Steps

### 1. Database — Supabase
Run `database/schema.sql` in Supabase → SQL Editor → New Query.

### 2. Backend — Render
1. Push repo to GitHub
2. Render Dashboard → New → Blueprint → connect repo
3. Set root directory to `backend/`
4. Add all env vars from `backend/env.example` in Render Dashboard → Environment

### 3. Frontend — Vercel
1. Vercel Dashboard → New Project → connect same repo
2. Set root directory to `frontend/`
3. **Before deploying:** update `frontend/config.js`:
   ```js
   window.__BACKEND_URL = 'https://your-app.onrender.com';
   ```
4. Deploy

### 4. Cron — cron-job.org
| Setting  | Value                                                      |
|----------|------------------------------------------------------------|
| URL      | `https://your-app.onrender.com/api/cron/daily-check`       |
| Method   | POST                                                       |
| Header   | `X-Cron-Key: <your CRON_API_KEY>`                         |
| Schedule | Every 1 hour                                               |
| Timeout  | **60 seconds** (Render free tier ~30s cold start)          |

## Local Development

```bash
cd backend
pip install -r requirements.txt
cp env.example .env    # Fill in your values
python app.py
# Open http://localhost:5000
```

## Environment Variables

See `backend/env.example` for all required variables with descriptions.
