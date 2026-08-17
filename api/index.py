"""
Vercel-Einstiegspunkt (Serverless-Python). Vercel bedient die FastAPI-App als
ASGI-Anwendung. Alle Routen werden per vercel.json hierher geleitet.

Auf Vercel kommen die Geheimnisse aus Environment-Variablen (NICHT aus .env):
  DATABASE_URL    -> Neon-Postgres-Connection-String
  SESSION_SECRET  -> fester Schluessel fuer die Login-Cookies (sonst wird bei
                     jedem Cold-Start ausgeloggt)
"""
import sys
from pathlib import Path

# web_app.py liegt eine Ebene hoeher (website/)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web_app import app  # noqa: E402  (ASGI-App, die Vercel bedient)
