"""
US100 Bot - Verkaufs-Website mit Konto-System (FastAPI).

Ablauf:
  * Besucher sieht eine moderne Landingpage mit Preisen (regt zum Abo an).
  * Er MUSS ein Konto erstellen (E-Mail + Passwort), bevor er herunterladen kann.
  * Beim Registrieren wird automatisch eine KUNDENNUMMER (KND-XXXXXX) erzeugt und
    zusammen mit dem Passwort-Hash in dieselbe Neon-Tabelle 'customers' geschrieben,
    die auch der Lizenz-Server abfragt.
  * Im Konto sieht der Kunde seine Kundennummer + Abo-Status + Download-Button.
  * Diese Kundennummer traegt er spaeter im Bot-Dashboard ein -> der Lizenz-Server
    prueft ueber genau diesen Datensatz, ob das Abo aktiv (paid=TRUE) ist.

Wichtig: Passwoerter werden NUR als PBKDF2-Hash gespeichert (nie im Klartext).
Der Download ist an ein Konto gebunden (Login), das Ausfuehren/Traden an ein
aktives Abo (paid) - beides getrennt.

Start (lokal):
  cd website
  python -m uvicorn web_app:app --host 127.0.0.1 --port 8080 --reload
Dann http://127.0.0.1:8080 im Browser oeffnen.
"""
from __future__ import annotations

import os
import hmac
import random
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

HERE = Path(__file__).resolve().parent

# ---- .env laden (DATABASE_URL teilt sich mit dem Lizenz-Server) ------------- #
try:
    from dotenv import load_dotenv
    load_dotenv(HERE / ".env")                       # website-eigene .env
    load_dotenv(HERE.parent / "licensing" / ".env")  # geteilte Server-.env
    load_dotenv(HERE.parent / ".env")                # Fallback: Haupt-.env
except Exception:
    pass

try:
    import psycopg
except ImportError:
    psycopg = None

DATABASE_URL = os.getenv("DATABASE_URL")
PRODUCT_NAME = "TrendPilot"
DOWNLOAD_ZIP = HERE / "downloads" / "US100-Bot.zip"
# Grosse App-Datei liegt als oeffentliches GitHub-Release (Serverless-Funktionen
# koennen 200+ MB nicht ausliefern). Per Env ueberschreibbar.
DOWNLOAD_URL = os.getenv(
    "DOWNLOAD_URL",
    "https://github.com/compassweblux/trendpilot-app/releases/download/v1.0.0/US100-Bot.zip")

# Session-Secret dauerhaft ablegen (sonst wird bei jedem Neustart ausgeloggt).
_secret_file = HERE / ".session_secret"
SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    if _secret_file.exists():
        SESSION_SECRET = _secret_file.read_text().strip()
    else:
        SESSION_SECRET = secrets.token_hex(32)
        try:
            _secret_file.write_text(SESSION_SECRET)
        except Exception:
            pass

app = FastAPI(title=f"{PRODUCT_NAME} - Website")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET, max_age=60 * 60 * 24 * 14)

templates = Jinja2Templates(directory=str(HERE / "templates"))
templates.env.cache = None   # umgeht einen jinja2/Py3.14-Cache-Bug (unhashable key)
_static = HERE / "static"
_static.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static)), name="static")


# ------------------------------------------------------------------ #
# Passwort-Hashing (PBKDF2-HMAC-SHA256, Standardbibliothek)
# ------------------------------------------------------------------ #
def hash_pw(pw: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return f"{salt.hex()}:{dk.hex()}"


def verify_pw(pw: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), 200_000)
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# ------------------------------------------------------------------ #
# Datenbank-Helfer
# ------------------------------------------------------------------ #
def db():
    if not (DATABASE_URL and psycopg):
        raise RuntimeError("DATABASE_URL nicht gesetzt (licensing/.env pruefen).")
    return psycopg.connect(DATABASE_URL, connect_timeout=8)


def gen_customer_id(cur) -> str:
    for _ in range(30):
        cid = "KND-" + "".join(random.choices("0123456789", k=6))
        cur.execute("SELECT 1 FROM customers WHERE customer_id = %s", (cid,))
        if not cur.fetchone():
            return cid
    raise RuntimeError("Konnte keine freie Kundennummer erzeugen.")


def find_by_email(cur, email: str):
    cur.execute(
        "SELECT customer_id, email, password_hash, paid, expires, name "
        "FROM customers WHERE lower(email) = lower(%s)", (email,))
    row = cur.fetchone()
    if not row:
        return None
    return {"customer_id": row[0], "email": row[1], "password_hash": row[2],
            "paid": bool(row[3]), "expires": row[4], "name": row[5]}


def sub_status(rec: dict) -> tuple[bool, str]:
    """Gibt (aktiv, Klartext-Status)."""
    if not rec.get("paid"):
        return False, "Kein aktives Abo"
    exp = rec.get("expires")
    if exp:
        e = exp if isinstance(exp, datetime) else datetime.fromisoformat(str(exp))
        if e.tzinfo is None:
            e = e.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > e:
            return False, "Abo abgelaufen"
        return True, f"Aktiv bis {e.date().isoformat()}"
    return True, "Aktiv"


def ctx(request: Request, **kw):
    kw.update({"request": request, "user": request.session.get("email"),
               "product": PRODUCT_NAME})
    return kw


# ------------------------------------------------------------------ #
# Seiten
# ------------------------------------------------------------------ #
@app.get("/", response_class=HTMLResponse)
def landing(request: Request):
    return templates.TemplateResponse(request, "landing.html", ctx(request))


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    if request.session.get("email"):
        return RedirectResponse("/account", status_code=303)
    return templates.TemplateResponse(request, "register.html", ctx(request, error=None))


@app.post("/register", response_class=HTMLResponse)
def register(request: Request, name: str = Form(""), email: str = Form(...),
             password: str = Form(...), password2: str = Form("")):
    email = email.strip().lower()
    err = None
    if "@" not in email or "." not in email:
        err = "Bitte eine gueltige E-Mail-Adresse angeben."
    elif len(password) < 8:
        err = "Das Passwort muss mindestens 8 Zeichen haben."
    elif password2 and password != password2:
        err = "Die Passwoerter stimmen nicht ueberein."
    if err:
        return templates.TemplateResponse(request, "register.html", ctx(request, error=err), status_code=400)
    try:
        with db() as conn, conn.cursor() as cur:
            if find_by_email(cur, email):
                return templates.TemplateResponse(
                    request, "register.html",
                    ctx(request, error="Fuer diese E-Mail besteht bereits ein Konto. Bitte anmelden."),
                    status_code=400)
            cid = gen_customer_id(cur)
            cur.execute(
                "INSERT INTO customers (customer_id, paid, name, email, password_hash) "
                "VALUES (%s, FALSE, %s, %s, %s)",
                (cid, name.strip() or None, email, hash_pw(password)))
            conn.commit()
    except Exception as e:
        return templates.TemplateResponse(
            request, "register.html", ctx(request, error=f"Serverfehler: {e}"), status_code=500)
    request.session["email"] = email
    request.session["customer_id"] = cid
    return RedirectResponse("/account?willkommen=1", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    if request.session.get("email"):
        return RedirectResponse("/account", status_code=303)
    return templates.TemplateResponse(request, "login.html", ctx(request, error=None))


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    try:
        with db() as conn, conn.cursor() as cur:
            rec = find_by_email(cur, email.strip().lower())
    except Exception as e:
        return templates.TemplateResponse(
            request, "login.html", ctx(request, error=f"Serverfehler: {e}"), status_code=500)
    if not rec or not rec.get("password_hash") or not verify_pw(password, rec["password_hash"]):
        return templates.TemplateResponse(
            request, "login.html", ctx(request, error="E-Mail oder Passwort ist falsch."), status_code=401)
    request.session["email"] = rec["email"]
    request.session["customer_id"] = rec["customer_id"]
    return RedirectResponse("/account", status_code=303)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/account", response_class=HTMLResponse)
def account(request: Request, willkommen: int = 0):
    email = request.session.get("email")
    if not email:
        return RedirectResponse("/login", status_code=303)
    try:
        with db() as conn, conn.cursor() as cur:
            rec = find_by_email(cur, email)
    except Exception as e:
        return PlainTextResponse(f"Serverfehler: {e}", status_code=500)
    if not rec:
        request.session.clear()
        return RedirectResponse("/register", status_code=303)
    active, status = sub_status(rec)
    return templates.TemplateResponse(request, "account.html", ctx(
        request, rec=rec, active=active, status_text=status,
        willkommen=bool(willkommen), download_ready=DOWNLOAD_ZIP.exists()))


@app.get("/download")
def download(request: Request):
    if not request.session.get("email"):
        return RedirectResponse("/login", status_code=303)
    # Bevorzugt Weiterleitung zum gehosteten Release; lokal Fallback auf die Datei.
    if DOWNLOAD_URL:
        return RedirectResponse(DOWNLOAD_URL, status_code=307)
    if DOWNLOAD_ZIP.exists():
        return FileResponse(str(DOWNLOAD_ZIP), filename="US100-Bot.zip",
                            media_type="application/zip")
    return PlainTextResponse(
        "Der Download wird gerade vorbereitet. Bitte spaeter erneut versuchen.",
        status_code=503)


@app.get("/health")
def health():
    return {"status": "ok", "db": "neon" if (DATABASE_URL and psycopg) else "keine-db"}
