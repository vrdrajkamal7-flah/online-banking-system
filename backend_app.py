from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import smtplib
import random
import time
import os
import re
from email.message import EmailMessage

APP_VERSION = "gmail-otp-fix-2026-09-21-v2"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
CORS(app)

OTP_VALID_SECONDS = 30
MAX_RESENDS = 5
COOLDOWN_AFTER_LIMIT = 24 * 60 * 60
otp_storage = {}

def smtp_settings():
    email = (os.environ.get("SMTP_EMAIL") or "").strip().lower()
    password = (os.environ.get("SMTP_PASSWORD") or "").strip().replace(" ", "")
    return email, password

def valid_email(email):
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", str(email or "").strip()))

def generate_otp():
    return f"{random.SystemRandom().randint(0, 999999):06d}"

def send_email_otp(receiver_email, otp):
    smtp_email, smtp_password = smtp_settings()
    message = EmailMessage()
    message["Subject"] = "Your Online Banking System OTP"
    message["From"] = smtp_email
    message["To"] = receiver_email
    message.set_content(
        f"Your OTP is {otp}\n\n"
        f"This OTP is valid for {OTP_VALID_SECONDS} seconds.\n\n"
        "If you did not request this OTP, please ignore this email."
    )
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as server:
        server.login(smtp_email, smtp_password)
        server.send_message(message)

@app.after_request
def add_headers(response):
    response.headers["X-Online-Banking-Version"] = APP_VERSION
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/")
def home():
    index_path = os.path.join(BASE_DIR, "index.html")
    if os.path.exists(index_path):
        return send_from_directory(BASE_DIR, "index.html")
    return "Gmail OTP Backend Running"

@app.get("/health")
def health():
    smtp_email, smtp_password = smtp_settings()
    return jsonify({
        "ok": True,
        "service": "gmail-otp",
        "version": APP_VERSION,
        "smtp_configured": bool(smtp_email and smtp_password),
        "smtp_email_configured": bool(smtp_email),
        "smtp_password_configured": bool(smtp_password)
    })

@app.post("/send-otp")
def send_otp():
    try:
        data = request.get_json(silent=True) or {}
        email = str(data.get("email") or "").strip().lower()
        is_resend = bool(data.get("resend", False))

        if not valid_email(email):
            return jsonify({"success": False, "message": "Invalid Email ID."}), 400

        smtp_email, smtp_password = smtp_settings()
        if not smtp_email or not smtp_password:
            return jsonify({
                "success": False,
                "message": "Gmail OTP is not configured on Render. Set SMTP_EMAIL and SMTP_PASSWORD."
            }), 500

        now = time.time()
        record = otp_storage.get(email)

        if record and now < record.get("locked_until", 0):
            return jsonify({
                "success": False,
                "message": "You have reached the limit try after 24 hours"
            }), 429

        if record and record.get("locked_until", 0) and now >= record["locked_until"]:
            otp_storage.pop(email, None)
            record = None

        if is_resend:
            if not record:
                return jsonify({
                    "success": False,
                    "message": "OTP session not found. Click Send OTP to Gmail."
                }), 400
            if record.get("resend_count", 0) >= MAX_RESENDS:
                record["locked_until"] = now + COOLDOWN_AFTER_LIMIT
                return jsonify({
                    "success": False,
                    "message": "You have reached the limit try after 24 hours"
                }), 429
            resend_count = record.get("resend_count", 0) + 1
            window_started = record.get("window_started", now)
        else:
            if record:
                window_started = record.get("window_started", now)
                if now - window_started < COOLDOWN_AFTER_LIMIT and record.get("resend_count", 0) >= MAX_RESENDS:
                    return jsonify({
                        "success": False,
                        "message": "You have reached the limit try after 24 hours"
                    }), 429
                if now - window_started >= COOLDOWN_AFTER_LIMIT:
                    resend_count = 0
                    window_started = now
                else:
                    resend_count = record.get("resend_count", 0)
            else:
                resend_count = 0
                window_started = now

        otp = generate_otp()
        otp_storage[email] = {
            "otp": otp,
            "expires": now + OTP_VALID_SECONDS,
            "resend_count": resend_count,
            "window_started": window_started,
            "locked_until": 0
        }

        try:
            send_email_otp(email, otp)
        except smtplib.SMTPAuthenticationError as exc:
            otp_storage.pop(email, None)
            print("GMAIL SMTP AUTH ERROR:", repr(exc), flush=True)
            return jsonify({
                "success": False,
                "message": "Gmail authentication failed. Use a Gmail App Password (not your normal Gmail password) and check SMTP_EMAIL/SMTP_PASSWORD."
            }), 500
        except smtplib.SMTPException as exc:
            otp_storage.pop(email, None)
            print("GMAIL SMTP ERROR:", repr(exc), flush=True)
            return jsonify({
                "success": False,
                "message": "Gmail SMTP rejected the message. Check the Gmail App Password and Render environment variables."
            }), 500
        except OSError as exc:
            otp_storage.pop(email, None)
            print("GMAIL NETWORK ERROR:", repr(exc), flush=True)
            return jsonify({
                "success": False,
                "message": "Render could not connect to Gmail SMTP. Check the Render service logs."
            }), 500
        except Exception as exc:
            otp_storage.pop(email, None)
            print("GMAIL SEND ERROR:", repr(exc), flush=True)
            return jsonify({
                "success": False,
                "message": "Unexpected Gmail sending error. Check the Render service logs."
            }), 500

        return jsonify({
            "success": True,
            "message": "OTP sent successfully",
            "expires_in": OTP_VALID_SECONDS,
            "resend_count": resend_count,
            "max_resends": MAX_RESENDS
        })

    except Exception as exc:
        print("SEND OTP ROUTE ERROR:", repr(exc), flush=True)
        return jsonify({
            "success": False,
            "message": "Backend error while processing OTP request. Check Render logs."
        }), 500

@app.post("/verify-otp")
def verify_otp():
    try:
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

        if time.time() > record["expires"]:
            return jsonify({
                "success": False,
                "message": "Invalid OTP. OTP expired after 30 seconds. Click Resend OTP."
            }), 400

        if entered_otp != record["otp"]:
            return jsonify({"success": False, "message": "Invalid OTP"}), 400

        del otp_storage[email]
        return jsonify({"success": True, "message": "OTP verified successfully"})

    except Exception as exc:
        print("VERIFY OTP ERROR:", repr(exc), flush=True)
        return jsonify({"success": False, "message": "Backend error while verifying OTP."}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
