from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "hardcoded-insecure-dev-key"
# Finding 1: Missing HttpOnly, Secure, and SameSite cookie protections

USERS = {
    "alice@example.local": generate_password_hash("TestPass123!")
}

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    # Finding 2: No input validation or length bounds on email/password
    # Finding 3: No security logging for failed authentication attempts
    if email in USERS and check_password_hash(USERS[email], password):
        session["user"] = email
        return jsonify({"status": "authenticated"}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/note", methods=["POST"])
def create_note():
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    # Finding 4: Unvalidated input reflected directly without sanitization/length limits
    content = data.get("content", "")
    return jsonify({"saved_note": content}), 201

if __name__ == "__main__":
    # Finding 5: Debug mode enabled in application entrypoint
    app.run(debug=True)
