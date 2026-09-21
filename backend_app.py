from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import smtplib
import random
import time
import os
import re
from email.message import EmailMessage

# The frontend HTML file (index.html) should sit in the SAME folder as this
# backend_app.py file when you deploy both together as one service.
FRONTEND_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
# CORS is still enabled here in case you ever split the frontend out again,
# but when both are served from this same Flask app you don't need it —
# same-origin requests never hit CORS rules at all.
CORS(app)

SMTP_EMAIL = (os.environ.get("SMTP_EMAIL") or "").strip()
SMTP_PASSWORD = (os.environ.get("SMTP_PASSWORD") or "").strip()

# Demo/server memory store. For production, use a database or Redis.
otp_storage = {}

OTP_VALID_SECONDS = 30
MAX_RESENDS = 5
COOLDOWN_AFTER_LIMIT = 24 * 60 * 60


def valid_email(email):
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", str(email or "").strip()))


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
    try:
        data = request.get_json(silent=True) or {}
        email = str(data.get("email") or "").strip().lower()
        is_resend = bool(data.get("resend", False))

        if not valid_email(email):
            return jsonify({"success": False, "message": "Invalid Email ID."}), 400

        if not SMTP_EMAIL or not SMTP_PASSWORD:
            return jsonify({
                "success": False,
                "message": "SMTP_EMAIL or SMTP_PASSWORD is missing in Render Environment Variables."
            }), 500

        now = time.time()
        record = otp_storage.get(email)

        if record and now < record.get("locked_until", 0):
            return jsonify({
                "success": False,
                "message": "You have reached the limit try after 24 hours"
            }), 429

        if record and record.get("locked_until", 0) and now >= record["locked_until"]:
            record = None
            otp_storage.pop(email, None)

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
                if (
                    now - window_started < COOLDOWN_AFTER_LIMIT
                    and record.get("resend_count", 0) >= MAX_RESENDS
                ):
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
        except smtplib.SMTPAuthenticationError as exc:
            otp_storage.pop(email, None)
            print("GMAIL SMTP AUTHENTICATION ERROR:", repr(exc), flush=True)
            return jsonify({
                "success": False,
                "message": "Gmail SMTP authentication failed. Use a Gmail App Password and check SMTP_EMAIL/SMTP_PASSWORD in Render."
            }), 500
        except (smtplib.SMTPException, OSError) as exc:
            otp_storage.pop(email, None)
            print("GMAIL SMTP ERROR:", repr(exc), flush=True)
            return jsonify({
                "success": False,
                "message": "Gmail could not send the OTP. Check Gmail App Password and Render settings."
            }), 500
        except Exception as exc:
            otp_storage.pop(email, None)
            print("GMAIL SEND ERROR:", repr(exc), flush=True)
            return jsonify({
                "success": False,
                "message": "Unexpected Gmail error while sending OTP. Check Render Logs."
            }), 500

        return jsonify({
            "success": True,
            "message": "OTP sent successfully",
            "expires_in": OTP_VALID_SECONDS,
            "resend_count": resend_count,
            "max_resends": MAX_RESENDS,
        }), 200

    except Exception as exc:
        print("SEND OTP ROUTE ERROR:", repr(exc), flush=True)
        return jsonify({
            "success": False,
            "message": "Backend error while processing OTP request. Check Render Logs."
        }), 500


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
