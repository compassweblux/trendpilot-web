# TrendPilot – Website (FastAPI)

Registrieren / Login / Konto mit Neon-Datenbank. Deploybar auf **Vercel** (Serverless-Python).

## Auf Vercel live bringen (über GitHub-Import)
1. Dieses Repo mit **GitHub Desktop** veröffentlichen (Publish repository).
2. In Vercel: **Add New… → Project → Import** dieses Repo.
3. Framework: *Other* (die `vercel.json` regelt den Python-Build automatisch). **Deploy** klicken.
4. In **Project → Settings → Environment Variables** zwei Variablen anlegen
   (für *Production*):
   - `DATABASE_URL`  = dein Neon-Connection-String (aus deiner lokalen `.env`)
   - `SESSION_SECRET` = (siehe unten, fertig erzeugt)
5. **Redeploy** (Deployments → … → Redeploy), damit die Variablen greifen.

Danach funktionieren Registrieren + Login auf der öffentlichen Vercel-URL,
und die Kundennummern landen in derselben Neon-Datenbank.

## Struktur
- `api/index.py` – Vercel-Einstiegspunkt (ASGI)
- `web_app.py` – FastAPI-App
- `templates/` – Seiten (Landing, Register, Login, Konto)
- `vercel.json` – Python-Build + Routing
