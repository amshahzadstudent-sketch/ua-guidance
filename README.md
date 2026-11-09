# UA Guidance Office - Online Appointment System

Flask + SQLite web app for the University of the Assumption Guidance Office.
Students book online (no student account), counselors log in to manage their own students.

## Run it in VS Code (Windows / Mac / Linux)
1. Install Python 3.10 or newer and open this folder in VS Code (File > Open Folder).
2. Open a terminal (Terminal > New Terminal) and run:
   ```
   python -m venv .venv
   .venv\Scripts\activate          (Mac/Linux: source .venv/bin/activate)
   pip install -r requirements.txt
   python manage.py init           <- creates the database and counselor accounts
   python app.py
   ```
3. Write down the counselor passwords printed by `init` (shown only once).
4. Open http://127.0.0.1:5000 in your browser.

Verification codes and notification emails are printed in the terminal until you
set up real email (below). Counselor usernames: lorna, paige, maria, mica.

## Check that the security works
`python tests.py` runs 9 automatic tests (including the official IDEA test vector): staff pages blocked for students, data
encrypted in the database, email verification, double-booking, each counselor sees
only their own students, account lockout, tamper detection, CSRF protection.

## Settings (environment variables)
| Variable | Purpose |
|---|---|
| `ALLOWED_EMAIL_DOMAIN` | Only accept school emails, e.g. `ua.edu.ph` (set the real domain) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | Real email sending through the school's mail server |
| `PRODUCTION=1` | Cookies only over HTTPS (set this once the site uses HTTPS) |
| `SECRET_KEY`, `ENC_KEY` | Optional. Base64 of 32 bytes. Otherwise created in `data/` |

## Security features
- IDEA encryption (CBC mode + HMAC-SHA256 tamper seal, written from scratch in `idea_crypto.py`) of name, student number, program, section, email, phone and note
- Roles checked on the server for every request (students can never reach staff pages)
- Hashed counselor passwords, lockout after 5 wrong tries, 15-minute idle timeout
- Email one-time code (5 minutes, 5 tries, rate-limited), at most 2 active bookings per student
- Double-booking prevented with a database lock; CSRF protection; strict security headers
- Audit log: `python manage.py audit`

## IMPORTANT before real use
- **Back up the `data/` folder** (especially `enc.key`). Without it, stored student details cannot be decrypted. Never share or upload it.
- Run behind **HTTPS** (school IT: reverse proxy such as nginx, or a hosting service). Use a production server (for example `waitress` or `gunicorn`), not `python app.py`.
- Get approval from the school's IT office and Data Protection Officer (RA 10173).
- Confirm counselor names, program assignments, office hours and holidays. Holidays are not blocked yet.
- Forgot a password: `python manage.py reset-password lorna`

## Files
`app.py` backend | `idea_crypto.py` IDEA cipher | `manage.py` admin commands | `tests.py` tests | `templates/` pages | `static/` CSS, JS, seal
