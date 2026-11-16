import os
import re
import logging
from datetime import timedelta
from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
security_logger = logging.getLogger("security_audit")

app = Flask(__name__)
# Fix 1: Load secret key from environment with strong fallback (no hardcoded prod secret)
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY", os.urandom(32))

# Fix 2: Enforce hardened session cookie attributes and 15-minute expiry
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
)

USERS = {
    "alice@example.local": generate_password_hash("TestPass123!")
}

EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

@app.after_request
def apply_security_headers(response):
    # Fix 3: Add defensive HTTP security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    # Fix 4: Server-side input validation & length bounds
    if not EMAIL_PATTERN.match(email) or not (8 <= len(password) <= 128):
        security_logger.warning("LOGIN_VALIDATION_FAILED ip=%s", request.remote_addr)
        return jsonify({"error": "Invalid credentials"}), 401

    if email in USERS and check_password_hash(USERS[email], password):
        session.clear()
        session.permanent = True
        session["user"] = email
        security_logger.info("LOGIN_SUCCESS user=%s ip=%s", email, request.remote_addr)
        return jsonify({"status": "authenticated"}), 200

    # Fix 5: Structured security logging without logging plaintext passwords
    security_logger.warning("LOGIN_FAILED user=%s ip=%s", email, request.remote_addr)
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/note", methods=["POST"])
def create_note():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    content = str(data.get("content", "")).strip()

    # Fix 6: Strict length and character validation
    if not content or len(content) > 500 or "<" in content or ">" in content:
        security_logger.warning("INVALID_NOTE_INPUT user=%s", session["user"])
        return jsonify({"error": "Invalid note content"}), 400

    return jsonify({"saved_note": content}), 201

if __name__ == "__main__":
    # Fix 7: Explicitly disable debug mode
    app.run(debug=False)
