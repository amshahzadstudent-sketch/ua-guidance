"""
UA Guidance Office - Online Appointment System (Flask backend)

Security design (Information Assurance):
  Confidentiality : student details are encrypted with the IDEA cipher (CBC mode) before
                    they are saved (see encrypt() / decrypt()).
  Integrity       : an HMAC-SHA256 seal detects tampering; every change is audit-logged.
  Availability    : SQLite database, simple backups (copy the data folder).
  Access control  : roles are checked on the SERVER for every request
                    (staff_required). Students never get a staff page.
  Authentication  : counselor passwords are hashed, accounts lock after 5
                    wrong tries, sessions expire after 15 minutes idle.
  Verification    : students must confirm a one-time email code (5 minutes).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

import idea_crypto
from flask import (Flask, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Asia/Manila")
except Exception:  # tzdata missing: fall back to the computer's clock
    TZ = None

BASE = os.path.dirname(os.path.abspath(__file__))
ON_VERCEL = bool(os.environ.get("VERCEL"))
# Vercel's project folder is read-only; /tmp is the only writable place there.
DEFAULT_DATA = "/tmp/data" if ON_VERCEL else os.path.join(BASE, "data")
DATA = os.environ.get("DATA_DIR", DEFAULT_DATA)
DB_PATH = os.environ.get("DB_PATH", os.path.join(DATA, "guidance.db"))
os.makedirs(DATA, exist_ok=True)


# --------------------------------------------------------------------------
# KEYS: one for signing sessions, one master key for IDEA encryption of student details.
# Created once and saved in data/. KEEP THEM SECRET AND BACKED UP: without
# enc.key the encrypted student details can never be read again.
# On Vercel, set SECRET_KEY and ENC_KEY as environment variables (base64),
# otherwise new random keys are made on every cold start.
# --------------------------------------------------------------------------
def _key(name: str, env: str) -> bytes:
    if os.environ.get(env):
        return base64.b64decode(os.environ[env])
    if ON_VERCEL:
        # DEMO FALLBACK: every Vercel instance must use the SAME key, so derive
        # one from the project id. For real use, set SECRET_KEY / ENC_KEY.
        seed_txt = os.environ.get("VERCEL_PROJECT_ID", "ua-guidance-demo")
        return hashlib.sha256(f"{name}:{seed_txt}".encode()).digest()
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(secrets.token_bytes(32))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    with open(path, "rb") as f:
        return f.read()


SECRET = _key("secret.key", "SECRET_KEY")
ENC_KEY = _key("enc.key", "ENC_KEY")
ALLOWED_DOMAIN = os.environ.get("ALLOWED_EMAIL_DOMAIN", "").lower().lstrip("@")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("PRODUCTION") == "1",  # HTTPS only
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),  # idle timeout
    MAX_CONTENT_LENGTH=32 * 1024,
)

# --------------------------------------------------------------------------
# OFFICE SETTINGS (edit here if counselors, programs or hours change)
# --------------------------------------------------------------------------
COUNSELORS = {
    "lorna": ("Ms. Lorna Basmayor", [
        "Bachelor of Secondary Education major in Values Education, Religious Education",
        "Bachelor of Science in Accountancy",
        "Bachelor of Science in Accounting Information System",
        "Bachelor of Science in Business Administration",
    ]),
    "paige": ("Ms. Paige Tayag", [
        "Bachelor of Science in Nursing"
    ]),
    "maria": ("Ms. Maria Assunta Elia Evaristo", [
        "Bachelor of Science in Hospitality Management",
        "Bachelor of Science in Tourism Management",
        "Bachelor of Science in Pharmacy",
        "Bachelor of Science in Architecture",
        "Bachelor Of Science in Civil Engineering",
        "Bachelor of Science in Industrial Engineering",
        "Bachelor of Science in Computer Engineering"
    ]),
    "mica": ("Ms. Mica Manaloto", [
    "Bachelor of Science in Human Services",
    "Bachelor of Arts in Communication",
    "Bachelor of Science in Psychology",
    "Bachelor of Science in Criminology",
    "Bachelor of Science in Information Technology"
]),
}
PROGRAM_TO_COUNSELOR = {p: u for u, (_, progs) in COUNSELORS.items() for p in progs}
SERVICES = {"Counseling": 30, "Initial interview": 15, "Routine interview": 15}
WORK_BLOCKS = [(540, 720), (780, 1020)]  # 9:00-12:00 and 1:00-5:00 (minutes)
MAX_ACTIVE_PER_STUDENT = 2
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


# --------------------------------------------------------------------------
# DATABASE
# --------------------------------------------------------------------------
def connect():
    db = sqlite3.connect(DB_PATH, isolation_level=None)  # manual transactions
    db.row_factory = sqlite3.Row
    return db


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = connect()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS counselors(
        username TEXT PRIMARY KEY, name TEXT NOT NULL, pw_hash TEXT NOT NULL,
        failed INTEGER DEFAULT 0, locked_until REAL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS appointments(
        ref TEXT PRIMARY KEY, counselor TEXT NOT NULL, day TEXT NOT NULL,
        start INTEGER NOT NULL, dur INTEGER NOT NULL, service TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        id_hash TEXT NOT NULL, enc TEXT NOT NULL, created REAL NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_slot ON appointments(counselor, day);
    CREATE TABLE IF NOT EXISTS email_codes(
        id INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT, email TEXT, ip TEXT,
        code_hash TEXT, created REAL, expires REAL, tries INTEGER DEFAULT 0,
        verified INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS audit(
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, actor TEXT,
        action TEXT, detail TEXT);
    """)
    db.close()

def update_counselor_names():
    db = connect()

    try:
        for username, (name, _) in COUNSELORS.items():
            db.execute(
                "UPDATE counselors SET name=? WHERE username=?",
                (name, username)
            )

        db.commit()
        print("Counselor names successfully updated!")

    finally:
        db.close()

def seed():
    """Create the counselor accounts. Passwords are random and shown ONCE.
    On Vercel, set COUNSELOR_PW_LORNA, COUNSELOR_PW_PAIGE, COUNSELOR_PW_MARIA
    and COUNSELOR_PW_MICA as environment variables so you know the passwords."""
    db = connect()
    for user, (name, _) in COUNSELORS.items():
        if db.execute("SELECT 1 FROM counselors WHERE username=?", (user,)).fetchone():
            continue
        env_pw = os.environ.get(f"COUNSELOR_PW_{user.upper()}")
        pw = env_pw or secrets.token_urlsafe(9)
        db.execute("INSERT INTO counselors(username,name,pw_hash) VALUES(?,?,?)",
                   (user, name, generate_password_hash(pw)))
        if env_pw:
            print(f"  {user:8} {name:36} password: (from environment variable)")
        else:
            print(f"  {user:8} {name:36} password: {pw}")
    db.close()


def audit(actor, action, detail=""):
    get_db().execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
                     (now().isoformat(timespec="seconds"), actor, action, detail))


# --------------------------------------------------------------------------
# ENCRYPTION  (IDEA-CBC + HMAC-SHA256, see idea_crypto.py)
# --------------------------------------------------------------------------
def encrypt(record: dict, ref: str) -> str:
    """Encrypt private details with IDEA. The reference code is 'associated
    data': a record cannot be moved onto another appointment unnoticed."""
    blob = idea_crypto.seal(ENC_KEY, json.dumps(record).encode(), ref.encode())
    return base64.b64encode(blob).decode()


def decrypt(blob: str, ref: str) -> dict:
    """Raises ValueError if the data was changed or the key is wrong."""
    return json.loads(idea_crypto.unseal(ENC_KEY, base64.b64decode(blob), ref.encode()))


def id_hash(student_no: str) -> str:
    """Keyed one-way fingerprint: lets us count a student's bookings
    without storing the student number in readable form."""
    return hmac.new(SECRET, student_no.encode(), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# HELPERS
# --------------------------------------------------------------------------
def now():
    return datetime.now(TZ) if TZ else datetime.now()


def fmt_time(m):
    return f"{(m // 60) % 12 or 12}:{m % 60:02d} {'PM' if m >= 720 else 'AM'}"


def pretty(day):
    return datetime.strptime(day, "%Y-%m-%d").strftime("%a, %b %d, %Y")


app.jinja_env.filters["fmt_time"] = fmt_time
app.jinja_env.filters["pretty"] = pretty


def open_days():
    """Next 10 weekdays, starting tomorrow."""
    d, out = now().date(), []
    while len(out) < 10:
        d += timedelta(days=1)
        if d.weekday() < 5:
            out.append(d.isoformat())
    return out


def free_slots(db, counselor, day, dur):
    busy = db.execute("SELECT start,dur FROM appointments WHERE counselor=? "
                      "AND day=? AND status!='Cancelled'", (counselor, day)).fetchall()
    out = []
    for a, b in WORK_BLOCKS:
        for s in range(a, b - dur + 1, 15):
            clash = any(s < x["start"] + x["dur"] and x["start"] < s + dur for x in busy)
            out.append({"start": s, "label": fmt_time(s), "free": not clash})
    return out


def send_mail(to, subject, body):
    """Send through the school's SMTP server. Without SMTP settings the email
    is printed in the terminal (development mode)."""
    host = os.environ.get("SMTP_HOST")
    if not host:
        print(f"\n[DEV EMAIL] To: {to}\nSubject: {subject}\n{body}\n")
        return
    msg = EmailMessage()
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", ""))
    msg["To"], msg["Subject"] = to, subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=15) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASS", ""))
            s.send_message(msg)
    except Exception as exc:  # never crash a booking because email failed
        app.logger.error("email failed: %s", exc)


# --------------------------------------------------------------------------
# SECURITY: CSRF, headers, role checks
# --------------------------------------------------------------------------
def csrf_token():
    session.permanent = True
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def csrf_check():
    if request.method == "POST":
        sent = request.headers.get("X-CSRF-Token") or request.form.get("_csrf", "")
        if not hmac.compare_digest(sent, session.get("csrf", "x")):
            abort(400)


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; frame-ancestors 'none'")
    return resp


@app.context_processor
def inject():
    return {"csrf_token": csrf_token, "staff_name": session.get("staff_name")}


def staff_required(view):
    """ROLE GUARD: only a logged-in counselor gets through. Checked on the
    server for every request, so a student cannot reach staff pages."""
    @wraps(view)
    def wrapper(*a, **kw):
        if not session.get("staff"):
            audit("anonymous", "denied", request.path)
            abort(403)
        return view(*a, **kw)
    return wrapper


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def error(e):
    msgs = {400: "Bad request. Your session may have expired. Please go back and try again.",
            403: "Access denied. You are not allowed to open this page.",
            404: "Page not found.", 413: "Request too large."}
    return render_template("error.html", code=e.code, msg=msgs.get(e.code, "Error")), e.code


# --------------------------------------------------------------------------
# STUDENT PAGES AND API  (no login: students verify by email code instead)
# --------------------------------------------------------------------------
@app.get("/")
def home():
    return render_template("landing.html", counselors=COUNSELORS, services=SERVICES)


@app.get("/book")
def book_page():
    cfg = {"days": [{"iso": d, "label": pretty(d)} for d in open_days()],
           "programs": {p: COUNSELORS[u][0] for p, u in PROGRAM_TO_COUNSELOR.items()},
           "services": SERVICES, "domain": ALLOWED_DOMAIN}
    return render_template("book.html", cfg=json.dumps(cfg), domain=ALLOWED_DOMAIN)


@app.get("/api/slots")
def api_slots():
    prog, svc, day = (request.args.get(k, "") for k in ("program", "service", "day"))
    if prog not in PROGRAM_TO_COUNSELOR or svc not in SERVICES or day not in open_days():
        return jsonify(error="Invalid choice."), 400
    return jsonify(slots=free_slots(get_db(), PROGRAM_TO_COUNSELOR[prog], day, SERVICES[svc]))


def clean_email(raw):
    email = (raw or "").strip().lower()
    if not EMAIL_RE.match(email) or len(email) > 80:
        return None, "Enter a valid email address."
    if ALLOWED_DOMAIN and not email.endswith("@" + ALLOWED_DOMAIN):
        return None, f"Use your school email (@{ALLOWED_DOMAIN})."
    return email, None


@app.post("/api/send-code")
def api_send_code():
    email, err = clean_email((request.get_json(silent=True) or {}).get("email"))
    if err:
        return jsonify(error=err), 400
    t = time.time()
    sid = session.setdefault("sid", secrets.token_hex(8))
    recent = [x for x in session.get("code_log", []) if x > t - 600]
    if len(recent) >= 3:  # stops email flooding
        return jsonify(error="Too many codes requested. Try again in 10 minutes."), 429
    code = str(secrets.randbelow(900000) + 100000)
    # The pending code lives in the signed session cookie, so it works even
    # when Vercel runs each request on a different server instance.
    session["code_log"] = recent + [t]
    session["vc"] = {"email": email, "h": code_hash(sid, email, code),
                     "exp": t + 300, "tries": 0}
    session.pop("vok", None)
    send_mail(email, "UA Guidance Office verification code",
              f"Your verification code is {code}. It expires in 5 minutes.\n"
              "If you did not request it, ignore this email.")
    return jsonify(ok=True)


def code_hash(sid, email, code):
    return hmac.new(SECRET, f"{sid}:{email}:{code}".encode(), hashlib.sha256).hexdigest()


@app.post("/api/verify-code")
def api_verify_code():
    data = request.get_json(silent=True) or {}
    email, err = clean_email(data.get("email"))
    sid, t = session.get("sid"), time.time()
    vc = session.get("vc")
    if not (sid and email and vc) or vc["email"] != email or vc["exp"] < t or vc["tries"] >= 5:
        return jsonify(error="Code expired or too many tries. Send a new code."), 400
    vc["tries"] += 1
    session["vc"] = vc
    ok = hmac.compare_digest(vc["h"], code_hash(sid, email, str(data.get("code", "")).strip()))
    if not ok:
        return jsonify(error="Wrong code."), 400
    session["vok"] = {"email": email, "t": t}
    return jsonify(ok=True)


@app.post("/api/book")
def api_book():
    d = request.get_json(silent=True) or {}
    name, sno = str(d.get("name", "")).strip(), str(d.get("student_no", "")).strip()
    section, prog = str(d.get("section", "")).strip(), d.get("program")
    phone = re.sub(r"[\s-]", "", str(d.get("phone", "")))
    svc, day, note = d.get("service"), d.get("day"), str(d.get("note", "")).strip()
    email, eerr = clean_email(d.get("email"))
    start = d.get("start")
    problems = []
    if not 2 <= len(name) <= 60: problems.append("name")
    if not re.fullmatch(r"[0-9-]{4,15}", sno): problems.append("student number")
    if not 1 <= len(section) <= 12: problems.append("section")
    if prog not in PROGRAM_TO_COUNSELOR: problems.append("program")
    if eerr: problems.append("email")
    if not re.fullmatch(r"(09|\+639)\d{9}", phone): problems.append("phone")
    if svc not in SERVICES: problems.append("service")
    if day not in open_days(): problems.append("date")
    if len(note) > 300: problems.append("note")
    if d.get("consent") is not True: problems.append("privacy consent")
    if problems:
        return jsonify(error="Please check: " + ", ".join(problems) + "."), 400

    db, t, dur = get_db(), time.time(), SERVICES[svc]
    counselor = PROGRAM_TO_COUNSELOR[prog]
    vok = session.get("vok") or {}
    ok_email = vok.get("email") == email and vok.get("t", 0) > t - 1800
    if not ok_email:
        return jsonify(error="Please verify your email first."), 400
    if not isinstance(start, int) or not any(
            s["start"] == start for s in free_slots(db, counselor, day, dur)):
        return jsonify(error="Invalid time."), 400

    ref = "GO-" + "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(5))
    record = {"name": name, "student_no": sno, "program": prog, "section": section,
              "email": email, "phone": phone, "note": note}
    db.execute("BEGIN IMMEDIATE")  # lock so two students cannot take one slot
    try:
        clash = db.execute("SELECT 1 FROM appointments WHERE counselor=? AND day=? "
                           "AND status!='Cancelled' AND start<? AND start+dur>?",
                           (counselor, day, start + dur, start)).fetchone()
        active = db.execute("SELECT COUNT(*) c FROM appointments WHERE id_hash=? "
                            "AND status IN ('Pending','Confirmed') AND day>=?",
                            (id_hash(sno), now().date().isoformat())).fetchone()["c"]
        if clash:
            db.execute("ROLLBACK")
            return jsonify(error="That time was just taken. Choose another."), 409
        if active >= MAX_ACTIVE_PER_STUDENT:
            db.execute("ROLLBACK")
            return jsonify(error="You already have the maximum number of upcoming appointments."), 400
        db.execute("INSERT INTO appointments(ref,counselor,day,start,dur,service,id_hash,enc,created) "
                   "VALUES(?,?,?,?,?,?,?,?,?)",
                   (ref, counselor, day, start, dur, svc, id_hash(sno), encrypt(record, ref), t))
        db.execute("COMMIT")
    except sqlite3.Error:
        db.execute("ROLLBACK")
        raise
    audit("student", "book", ref)
    session["refs"] = (session.get("refs", []) + [ref])[-10:]
    send_mail(email, f"Appointment received ({ref})",
              f"Hi {name},\n\nYour {svc} with {COUNSELORS[counselor][0]} on {pretty(day)} "
              f"at {fmt_time(start)} was received. Reference code: {ref}.\n"
              "It is valid once your counselor confirms it.")
    return jsonify(ok=True, ref=ref)


@app.get("/receipt/<ref>")
def receipt(ref):
    """Only the browser session that made the booking can open its receipt."""
    if ref not in session.get("refs", []):
        audit("anonymous", "denied", request.path)
        abort(403)
    row = get_db().execute("SELECT * FROM appointments WHERE ref=?", (ref,)).fetchone()
    if not row:
        abort(404)
    rec = decrypt(row["enc"], ref)
    return render_template("receipt.html", a=row, r=rec, cname=COUNSELORS[row["counselor"]][0],
                           masked="*****" + rec["student_no"][-3:], issued=now().strftime("%b %d, %Y %I:%M %p"))


@app.get("/check")
def check():
    """Public status check. Shows NO personal details, only the slot."""
    ref = request.args.get("ref", "").strip().upper()
    row = get_db().execute("SELECT * FROM appointments WHERE ref=?", (ref,)).fetchone() if ref else None
    return render_template("check.html", ref=ref, a=row, searched=bool(ref),
                           cname=COUNSELORS[row["counselor"]][0] if row else "")


# --------------------------------------------------------------------------
# COUNSELOR PAGES  (login required; each counselor sees only their own)
# --------------------------------------------------------------------------
DUMMY_HASH = generate_password_hash("not-a-real-password")


@app.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    error = ""
    if request.method == "POST":
        user = request.form.get("username", "").strip().lower()
        pw = request.form.get("password", "")
        db, t = get_db(), time.time()
        row = db.execute("SELECT * FROM counselors WHERE username=?", (user,)).fetchone()
        if row and row["locked_until"] > t:
            error = "Account locked for 10 minutes after too many wrong attempts."
        else:
            good = check_password_hash(row["pw_hash"] if row else DUMMY_HASH, pw)
            if row and good:
                db.execute("UPDATE counselors SET failed=0 WHERE username=?", (user,))
                session.clear()
                session.permanent = True
                session["staff"], session["staff_name"] = user, row["name"]
                audit(user, "login")
                return redirect(url_for("dashboard"))
            if row:
                fails = row["failed"] + 1
                lock = t + 600 if fails >= 5 else 0
                db.execute("UPDATE counselors SET failed=?, locked_until=? WHERE username=?",
                           (0 if lock else fails, lock, user))
            audit(user or "unknown", "login_failed")
            error = "Incorrect username or password."
    return render_template("login.html", error=error)


@app.get("/staff")
@staff_required
def dashboard():
    user = session["staff"]
    rows, items = get_db().execute("SELECT * FROM appointments WHERE counselor=? "
                                   "ORDER BY day, start", (user,)).fetchall(), []
    for r in rows:
        try:
            items.append({"a": r, "r": decrypt(r["enc"], r["ref"]), "bad": False})
        except Exception:  # InvalidTag: stored data was altered
            items.append({"a": r, "r": {}, "bad": True})
    audit(user, "view_dashboard")
    return render_template("dashboard.html", items=items)


@app.post("/staff/appointments/<ref>/<action>")
@staff_required
def change_status(ref, action):
    if action not in ("confirm", "cancel"):
        abort(404)
    db, user = get_db(), session["staff"]
    row = db.execute("SELECT * FROM appointments WHERE ref=?", (ref,)).fetchone()
    if not row or row["counselor"] != user:  # cannot touch other counselors' students
        audit(user, "denied", f"{action} {ref}")
        abort(403)
    status = "Confirmed" if action == "confirm" else "Cancelled"
    db.execute("UPDATE appointments SET status=? WHERE ref=?", (status, ref))
    audit(user, action, ref)
    try:
        rec = decrypt(row["enc"], ref)
        send_mail(rec["email"], f"Appointment {status.lower()} ({ref})",
                  f"Hi {rec['name']},\n\nYour {row['service']} on {pretty(row['day'])} at "
                  f"{fmt_time(row['start'])} is now {status.upper()}.\nReference code: {ref}.")
    except Exception:
        pass
    return redirect(url_for("dashboard"))


@app.get("/staff/appointments/<ref>/delete")
@staff_required
def confirm_delete(ref):
    db = get_db()
    user = session["staff"]

    appointment = db.execute(
        "SELECT * FROM appointments WHERE ref=?",
        (ref,)
    ).fetchone()

    if not appointment or appointment["counselor"] != user:
        abort(404)

    return render_template(
        "confirm_delete.html",
        appointment=appointment
    )


@app.post("/staff/appointments/<ref>/delete")
@staff_required
def delete_appointment(ref):
    db = get_db()
    user = session["staff"]

    appointment = db.execute(
        "SELECT * FROM appointments WHERE ref=?",
        (ref,)
    ).fetchone()

    if not appointment or appointment["counselor"] != user:
        abort(404)

    db.execute(
        "DELETE FROM appointments WHERE ref=? AND counselor=?",
        (ref, user)
    )

    audit(user, "delete_appointment", ref)

    return redirect(url_for("dashboard"))



@app.post("/staff/logout")
def staff_logout():
    audit(session.get("staff", "unknown"), "logout")
    session.clear()
    return redirect(url_for("home"))


# On Vercel the app is imported (not run), so the database and counselor
# accounts must be created here, at startup, inside /tmp.
if ON_VERCEL:
    init_db()
    seed()


if __name__ == "__main__":
    init_db()
    update_counselor_names()
    seed()

    print("===================================")
    print("UA GUIDANCE OFFICE SYSTEM")
    print("Server running successfully!")
    print("===================================")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )