"""Run the existing Flask app using Gmail SMTP; credentials stay in memory."""
import argparse
import getpass
import os
from pathlib import Path
import runpy
import smtplib
import ssl
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Check Gmail login only; send no email')
    args = parser.parse_args()
    folder = Path(__file__).resolve().parent
    if not (folder / 'app.py').is_file():
        print('Place start_gmail.py in the same folder as app.py.')
        return 1
    sender = input('Sender Gmail / UA email address: ').strip()
    if sender.count('@') != 1 or any(c.isspace() for c in sender):
        print('Enter a valid sender email address.')
        return 1
    password = getpass.getpass('Google App Password (hidden, NOT your normal password): ')
    password = password.replace(' ', '')
    if not password:
        print('App Password is required.')
        return 1
    try:
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            smtp.login(sender, password)
    except smtplib.SMTPAuthenticationError:
        print('Gmail rejected the login. Check the App Password and school account policy.')
        return 1
    except (OSError, smtplib.SMTPException) as exc:
        print(f'Cannot connect to Gmail SMTP ({type(exc).__name__}). Check your connection/account settings.')
        return 1
    print('Gmail SMTP login successful. No test email was sent.')
    if args.check:
        return 0
    settings = {'SMTP_HOST': 'smtp.gmail.com', 'SMTP_PORT': '587',
                'SMTP_USER': sender, 'SMTP_FROM': sender, 'SMTP_PASS': password}
    previous = {key: os.environ.get(key) for key in settings}
    os.environ.update(settings)
    sys.path.insert(0, str(folder))
    print('Starting website. Verification and booking notifications will use this sender.')
    try:
        runpy.run_path(str(folder / 'app.py'), run_name='__main__')
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
