from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
import re
import time
import random
import urllib.request
import urllib.error

APP_VERSION = "resend-otp-fix-2026-09-22-v1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=BASE_DIR, static_url_path="")
CORS(app)

OTP_VALID_SECONDS = 30
MAX_RESENDS = 5
COOLDOWN_AFTER_LIMIT = 24 * 60 * 60
otp_storage = {}


def resend_settings():
    api_key = (os.environ.get("RESEND_API_KEY") or "").strip()
    from_email = (os.environ.get("RESEND_FROM_EMAIL") or "onboarding@resend.dev").strip()
    return api_key, from_email


def valid_email(email):
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", str(email or "").strip()))


def generate_otp():
    return f"{random.SystemRandom().randint(0, 999999):06d}"


def send_email_otp(receiver_email, otp):
    api_key, from_email = resend_settings()
    if not api_key:
        raise RuntimeError("RESEND_API_KEY is not configured on Render.")

    payload = {
        "from": from_email,
        "to": [receiver_email],
        "subject": "Your Online Banking System OTP",
        "html": (
            "<div style='font-family:Arial,sans-serif;line-height:1.6'>"
            "<h2>Online Banking System</h2>"
            f"<p>Your OTP is:</p><p style='font-size:30px;font-weight:bold;letter-spacing:6px'>{otp}</p>"
            f"<p>This OTP is valid for <b>{OTP_VALID_SECONDS} seconds</b>.</p>"
            "<p>If you did not request this OTP, please ignore this email.</p>"
            "</div>"
        ),
        "text": (
            f"Your Online Banking System OTP is {otp}. "
            f"This OTP is valid for {OTP_VALID_SECONDS} seconds."
        )
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://api.resend.com/emails",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "online-banking-system/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            return json.loads(response_body or "{}")
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        try:
            details = json.loads(error_body)
        except Exception:
            details = {"message": error_body or str(exc)}
        message = details.get("message") or details.get("error") or error_body or str(exc)
        raise RuntimeError(f"Resend API error ({exc.code}): {message}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not connect to Resend API: {exc.reason}") from exc


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
    return "Resend Gmail OTP Backend Running"


@app.get("/health")
def health():
    api_key, from_email = resend_settings()
    return jsonify({
        "ok": True,
        "service": "resend-gmail-otp",
        "version": APP_VERSION,
        "resend_api_key_configured": bool(api_key),
        "resend_from_configured": bool(from_email),
        "resend_from": from_email
    })


@app.post("/send-otp")
def send_otp():
    try:
        data = request.get_json(silent=True) or {}
        email = str(data.get("email") or "").strip().lower()
        is_resend = bool(data.get("resend", False))

        if not valid_email(email):
            return jsonify({"success": False, "message": "Invalid Email ID."}), 400

        api_key, from_email = resend_settings()
        if not api_key:
            return jsonify({
                "success": False,
                "message": "Resend is not configured on Render. Add RESEND_API_KEY in Environment Variables."
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
            resend_result = send_email_otp(email, otp)
        except Exception as exc:
            otp_storage.pop(email, None)
            print("RESEND SEND ERROR:", repr(exc), flush=True)
            error_text = str(exc)
            if "403" in error_text and "resend.dev" in from_email:
                message = (
                    "Resend rejected this recipient because onboarding@resend.dev is a test sender. "
                    "It can only send to the email address associated with your Resend account. "
                    "Verify your own domain in Resend and set RESEND_FROM_EMAIL to an address on that domain."
                )
            else:
                message = f"Unable to send OTP email: {error_text}"
            return jsonify({"success": False, "message": message}), 502

        return jsonify({
            "success": True,
            "message": "OTP sent successfully",
            "expires_in": OTP_VALID_SECONDS,
            "resend_count": resend_count,
            "max_resends": MAX_RESENDS,
            "email_id": resend_result.get("id")
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
