# PCAP Demo

Full-stack web app for K-12 network threat hunting. Upload PCAPs, auto-analyze
across attack categories, with SSO authentication and async processing.

## Stack

- **Backend:** Python 3.12 / FastAPI, SQLAlchemy, Alembic, Celery
- **Frontend:** React 18, Vite, Tailwind CSS, Chart.js
- **Database:** PostgreSQL 16
- **Queue:** Redis + Celery workers
- **Proxy:** Nginx
- **Auth:** OAuth2 (Microsoft, Google) via Authlib
- **Containerization:** Docker Compose

## Project Layout

```
backend/
  app/
    main.py          # FastAPI application
    config.py        # Settings from env vars
    database.py      # SQLAlchemy setup
    models.py        # ORM models
    auth/            # OAuth middleware
    routers/         # API endpoints (auth, uploads)
    analyzers/       # Threat detection modules
    tasks/           # Celery background tasks
    demo_data.py     # Sample captures for demo mode
frontend/
  src/               # React components + pages
  vite.config.js     # Build config
nginx/
  nginx.conf         # Reverse proxy (API + static)
```

## Dev Setup

```bash
cp .env.example .env                          # configure env vars
docker compose up -d                          # full stack

# Or run services individually:
cd backend && pip install -r requirements.txt
uvicorn app.main:app --reload                 # API server
celery -A app.tasks.celery_app worker -Q pcap # analysis worker

cd frontend && npm install && npm run dev     # React dev server
```

## Architecture

```
nginx (80) ─┬─ /api, /auth → FastAPI (backend)
            └─ /            → React (frontend)
FastAPI ── PostgreSQL (captures, users)
        ── Redis (Celery broker)
        ── Celery (background PCAP analysis)
```

## Key Patterns

- Demo mode (`DEMO_MODE=true`) disables login, pre-loads sample captures
- OAuth → JWT session tokens signed with SECRET_KEY
- Celery processes PCAP analysis asynchronously
- Email domain restriction via `ALLOWED_DOMAINS` env var
- NTLM hashes/cleartext creds masked in UI, available in JSON export
- Uploads stored in Docker volume, never in web root

## Environment Variables

See `.env.example` for full list. Key ones:
- `MICROSOFT_CLIENT_ID/SECRET/TENANT_ID` — Microsoft OAuth
- `GOOGLE_CLIENT_ID/SECRET` — Google OAuth
- `ALLOWED_DOMAINS` — restrict login by email domain
- `DEMO_MODE` — enable demo mode (no auth)
- `SECRET_KEY` — JWT signing key
