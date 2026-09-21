from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import smtplib
import random
import time
import os
import re
import socket
from email.message import EmailMessage

# The frontend HTML file (index.html) should sit in the SAME folder as this
# backend_app.py file when you deploy both together as one service.
FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
# CORS is still enabled here in case you ever split the frontend out again,
# but when both are served from this same Flask app you don't need it —
# same-origin requests never hit CORS rules at all.
CORS(app)

SMTP_EMAIL = os.environ.get("SMTP_EMAIL")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")

# Demo/server memory store. For production, use a database or Redis.
otp_storage = {}

OTP_VALID_SECONDS = 30
MAX_RESENDS = 5
COOLDOWN_AFTER_LIMIT = 24 * 60 * 60


def valid_email(email):
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", str(email or "").strip()))


def email_domain_has_mx(email):
    """Best-effort domain check. It cannot prove an individual mailbox exists."""
    domain = email.rsplit("@", 1)[1].lower()
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return len(list(answers)) > 0
    except Exception:
        try:
            socket.gethostbyname(domain)
            return True
        except Exception:
            return False


def smtp_recipient_check(email):
    """Best-effort SMTP mailbox check. Some providers intentionally hide mailbox status."""
    domain = email.rsplit("@", 1)[1].lower()
    hosts = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        hosts = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]
    except Exception:
        hosts = []

    if not hosts:
        return False

    for host in hosts[:3]:
        try:
            with smtplib.SMTP(host, 25, timeout=8) as server:
                server.ehlo_or_helo_if_needed()
                code, _ = server.mail(SMTP_EMAIL)
                if code >= 400:
                    continue
                code, _ = server.rcpt(email)
                if code in (250, 251):
                    return True
                if code in (550, 551, 552, 553):
                    return False
        except Exception:
            continue
    return None


def email_appears_valid(email):
    """Return True/False/None. None means the provider did not expose mailbox status."""
    if not email_domain_has_mx(email):
        return False
    return smtp_recipient_check(email)


def generate_otp():
    return f"{random.SystemRandom().randint(0, 999999):06d}"


def send_email_otp(receiver_email, otp):
    message = EmailMessage()
    message["Subject"] = "Your Online Banking System OTP"
    message["From"] = SMTP_EMAIL
    message["To"] = receiver_email
    message.set_content(
        f"Your OTP is {otp}\n\n"
        f"This OTP is valid for {OTP_VALID_SECONDS} seconds.\n\n"
        "If you did not request this OTP, please ignore this email.\n"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.send_message(message)


@app.get("/")
def home():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return send_from_directory(FRONTEND_DIR, "index.html")
    return "Gmail OTP Backend Running (index.html not found next to backend_app.py)"


@app.get("/health")
def health():
    return jsonify({"ok": True, "service": "gmail-otp", "smtp_configured": bool(SMTP_EMAIL and SMTP_PASSWORD)})


@app.post("/send-otp")
def send_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    is_resend = bool(data.get("resend", False))

    if not valid_email(email):
        return jsonify({"success": False, "message": "Invalid Email ID."}), 400

    mailbox_check = email_appears_valid(email)
    if mailbox_check is False:
        return jsonify({"success": False, "message": "Invalid Email ID."}), 400

    now = time.time()
    record = otp_storage.get(email)

    if record and now < record.get("locked_until", 0):
        hours = max(1, int((record["locked_until"] - now) / 3600))
        return jsonify({
            "success": False,
            "message": f"You have reached the limit try after 24 hours"
        }), 429

    if record and record.get("locked_until", 0) and now >= record["locked_until"]:
        record = None
        otp_storage.pop(email, None)

    if is_resend:
        if not record:
            return jsonify({"success": False, "message": "OTP session not found. Click Send OTP to Gmail."}), 400
        if record.get("locked_until", 0) and now < record["locked_until"]:
            return jsonify({"success": False, "message": "You have reached the limit try after 24 hours"}), 429
        if record.get("resend_count", 0) >= MAX_RESENDS:
            record["locked_until"] = now + COOLDOWN_AFTER_LIMIT
            return jsonify({"success": False, "message": "You have reached the limit try after 24 hours"}), 429
        resend_count = record.get("resend_count", 0) + 1
        window_started = record.get("window_started", now)
    else:
        if record:
            window_started = record.get("window_started", now)
            if now - window_started < COOLDOWN_AFTER_LIMIT and record.get("resend_count", 0) >= MAX_RESENDS:
                return jsonify({"success": False, "message": "You have reached the limit try after 24 hours"}), 429
            if now - window_started >= COOLDOWN_AFTER_LIMIT:
                resend_count = 0
                window_started = now
            else:
                resend_count = record.get("resend_count", 0)
        else:
            resend_count = 0
            window_started = now

    otp = generate_otp()
    record = {
        "otp": otp,
        "expires": now + OTP_VALID_SECONDS,
        "resend_count": resend_count,
        "window_started": window_started,
        "locked_until": 0,
    }
    otp_storage[email] = record

    try:
        send_email_otp(email, otp)
        return jsonify({
            "success": True,
            "message": "OTP sent successfully",
            "expires_in": OTP_VALID_SECONDS,
            "resend_count": resend_count,
            "max_resends": MAX_RESENDS,
        })
    except smtplib.SMTPAuthenticationError:
        otp_storage.pop(email, None)
        print("Email error: Gmail SMTP authentication failed")
        return jsonify({"success": False, "message": "Gmail SMTP authentication failed. Use a Gmail App Password and check SMTP_EMAIL/SMTP_PASSWORD on the backend."}), 500
    except (smtplib.SMTPException, OSError) as exc:
        otp_storage.pop(email, None)
        print("Email error:", repr(exc))
        return jsonify({"success": False, "message": "Gmail could not send the OTP. Check SMTP_EMAIL, Gmail App Password, and backend logs."}), 500
    except Exception as exc:
        otp_storage.pop(email, None)
        print("Email error:", repr(exc))
        return jsonify({"success": False, "message": "Unexpected backend error while sending OTP. Check backend logs."}), 500


@app.post("/verify-otp")
def verify_otp():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email") or "").strip().lower()
    entered_otp = str(data.get("otp") or "").strip()

    if not valid_email(email):
        return jsonify({"success": False, "message": "Invalid email ID."}), 400
    if not re.fullmatch(r"\d{6}", entered_otp):
        return jsonify({"success": False, "message": "OTP must contain 6 digits."}), 400

    record = otp_storage.get(email)
    if not record:
        return jsonify({"success": False, "message": "OTP not found. Click Resend OTP."}), 400

    now = time.time()
    if now > record["expires"]:
        # Keep resend_count so the 5-resend limit cannot be bypassed by expiration.
        return jsonify({"success": False, "message": "Invalid OTP. OTP expired after 30 seconds. Click Resend OTP."}), 400

    if entered_otp != record["otp"]:
        return jsonify({"success": False, "message": "Invalid OTP"}), 400

    del otp_storage[email]
    return jsonify({"success": True, "message": "OTP verified successfully"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
