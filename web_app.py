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
import json
import hmac
import base64
import random
import hashlib
import secrets
from pathlib import Path
from datetime import datetime, timezone, timedelta

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel

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

# ---- Lizenz-Signatur fuer die Abo-Pruefung (/check) ------------------------ #
# Ed25519-Privatschluessel als Base64 der server_private.pem in der Env
# LICENSE_PRIVATE_KEY_B64. Der Bot verifiziert die Antwort mit dem in der .exe
# eingebetteten server_public.pem -> gefaelschte "bezahlt"-Antworten unmoeglich.
try:
    from cryptography.hazmat.primitives import serialization
    _lic_b64 = os.getenv("LICENSE_PRIVATE_KEY_B64")
    _LIC_PRIV = (serialization.load_pem_private_key(base64.b64decode(_lic_b64), password=None)
                 if _lic_b64 else None)
except Exception:
    _LIC_PRIV = None
_PRODUCT_KEY = os.getenv("PRODUCT_KEY", "")
LICENSE_TTL_MIN = 65

# ---- Stripe (Bezahlung) ---------------------------------------------------- #
# Alle Werte als Vercel-Env-Variablen (Secret-Key NIE im Code):
#   STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET,
#   STRIPE_PRICE_MONTHLY, STRIPE_PRICE_YEARLY, STRIPE_PRICE_LIFETIME
try:
    import stripe
except ImportError:
    stripe = None
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
if stripe and STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY
PLANS = {
    "monthly":  {"price": os.getenv("STRIPE_PRICE_MONTHLY"),  "mode": "subscription", "days": 31},
    "yearly":   {"price": os.getenv("STRIPE_PRICE_YEARLY"),   "mode": "subscription", "days": 366},
    "lifetime": {"price": os.getenv("STRIPE_PRICE_LIFETIME"), "mode": "payment",      "days": 36500},
}


def stripe_ready() -> bool:
    return bool(stripe and STRIPE_SECRET_KEY)


def _set_paid(customer_id: str, days: int):
    """Setzt eine Kundennummer in Neon auf bezahlt (+ Ablaufdatum)."""
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE customers SET paid = TRUE, expires = now() + (%s * interval '1 day') "
            "WHERE customer_id = %s", (int(days), customer_id))
        conn.commit()

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
def account(request: Request, willkommen: int = 0, bezahlt: int = 0):
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
        willkommen=bool(willkommen), bezahlt=bool(bezahlt),
        download_ready=bool(DOWNLOAD_URL) or DOWNLOAD_ZIP.exists()))


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


# ------------------------------------------------------------------ #
# Abo-Pruefung fuer den Bot (Kundennummer -> signierte Antwort)
# ------------------------------------------------------------------ #
class CheckReq(BaseModel):
    customer_id: str
    machine_id: str = ""


def _customer_paid_by_id(customer_id: str):
    """(paid: bool, expires: datetime|None) fuer eine Kundennummer aus Neon."""
    try:
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT paid, expires FROM customers WHERE customer_id = %s",
                        (customer_id,))
            row = cur.fetchone()
        if not row:
            return False, None
        return bool(row[0]), row[1]
    except Exception:
        return False, None


@app.post("/check")
def license_check(req: CheckReq):
    """Prueft die Kundennummer und liefert eine SIGNIERTE Antwort. Der Bot
    verifiziert die Signatur mit dem eingebetteten Public-Key."""
    if _LIC_PRIV is None:
        return {"error": "license signing not configured"}
    paid, expires = _customer_paid_by_id(req.customer_id.strip())
    now = datetime.now(timezone.utc)
    valid = bool(paid)
    reason = "bezahlt" if paid else "kein aktives Abo fuer diese Kundennummer"
    if valid and expires:
        exp = expires if isinstance(expires, datetime) else datetime.fromisoformat(str(expires))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            valid, reason = False, "Abo abgelaufen"
    payload = {
        "customer_id": req.customer_id, "machine_id": req.machine_id,
        "paid": valid, "valid": valid, "reason": reason,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(minutes=LICENSE_TTL_MIN)).isoformat(),
        "strategy_key": _PRODUCT_KEY if valid else "",
    }
    s = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    return {"payload": s, "signature": _LIC_PRIV.sign(s.encode()).hex()}


# ------------------------------------------------------------------ #
# Stripe: Checkout starten + Zahlungs-Webhook
# ------------------------------------------------------------------ #
@app.post("/subscribe")
def subscribe(request: Request, plan: str = Form(...)):
    email = request.session.get("email")
    cid = request.session.get("customer_id")
    if not email or not cid:
        return RedirectResponse("/login", status_code=303)
    p = PLANS.get(plan)
    if not stripe_ready() or not p or not p["price"]:
        return PlainTextResponse("Bezahlung ist noch nicht konfiguriert.", status_code=503)
    base = str(request.base_url).rstrip("/")
    try:
        session = stripe.checkout.Session.create(
            mode=p["mode"],
            line_items=[{"price": p["price"], "quantity": 1}],
            customer_email=email,
            client_reference_id=cid,
            metadata={"customer_id": cid, "plan": plan, "days": p["days"]},
            subscription_data=({"metadata": {"customer_id": cid, "days": p["days"]}}
                               if p["mode"] == "subscription" else None),
            success_url=f"{base}/account?bezahlt=1",
            cancel_url=f"{base}/account",
        )
    except Exception as e:
        return PlainTextResponse(f"Stripe-Fehler: {e}", status_code=502)
    return RedirectResponse(session.url, status_code=303)


@app.post("/billing")
def billing(request: Request):
    """Oeffnet das Stripe-Kundenportal: Abo kuendigen, Zahlungsmittel/Rechnungen."""
    email = request.session.get("email")
    if not email:
        return RedirectResponse("/login", status_code=303)
    if not stripe_ready():
        return PlainTextResponse("Bezahlung ist nicht konfiguriert.", status_code=503)
    try:
        with db() as conn, conn.cursor() as cur:
            cur.execute("SELECT stripe_customer_id FROM customers WHERE lower(email) = lower(%s)",
                        (email,))
            row = cur.fetchone()
    except Exception as e:
        return PlainTextResponse(f"Serverfehler: {e}", status_code=500)
    scust = row[0] if row else None
    if not scust:
        return PlainTextResponse(
            "Noch kein Stripe-Abo vorhanden. Schliesse zuerst ein Abo ab.", status_code=400)
    base = str(request.base_url).rstrip("/")
    try:
        sess = stripe.billing_portal.Session.create(customer=scust, return_url=f"{base}/account")
    except Exception as e:
        return PlainTextResponse(f"Stripe-Portal-Fehler: {e}", status_code=502)
    return RedirectResponse(sess.url, status_code=303)


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not stripe_ready():
        return PlainTextResponse("stripe off", status_code=503)
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)
    except Exception:
        return PlainTextResponse("invalid signature", status_code=400)
    typ = event.get("type", "")
    obj = event["data"]["object"]
    try:
        if typ == "checkout.session.completed":
            meta = obj.get("metadata") or {}
            cid = meta.get("customer_id") or obj.get("client_reference_id")
            days = int(meta.get("days") or 31)
            if cid:
                _set_paid(cid, days)
                scust = obj.get("customer")          # Stripe-Kundennummer merken
                if scust:
                    with db() as conn, conn.cursor() as cur:
                        cur.execute("UPDATE customers SET stripe_customer_id = %s "
                                    "WHERE customer_id = %s", (scust, cid))
                        conn.commit()
        elif typ == "invoice.paid":                       # Abo-Verlaengerung
            sub_id = obj.get("subscription")
            if sub_id:
                sub = stripe.Subscription.retrieve(sub_id)
                m = sub.get("metadata") or {}
                if m.get("customer_id"):
                    _set_paid(m["customer_id"], int(m.get("days") or 31))
        elif typ == "customer.subscription.deleted":      # gekuendigt -> sperren
            m = obj.get("metadata") or {}
            if m.get("customer_id"):
                with db() as conn, conn.cursor() as cur:
                    cur.execute("UPDATE customers SET paid = FALSE WHERE customer_id = %s",
                                (m["customer_id"],))
                    conn.commit()
    except Exception:
        pass
    return {"received": True}


@app.get("/health")
def health():
    return {"status": "ok",
            "db": "neon" if (DATABASE_URL and psycopg) else "keine-db",
            "license": "ready" if _LIC_PRIV else "off",
            "stripe": "ready" if stripe_ready() else "off"}
