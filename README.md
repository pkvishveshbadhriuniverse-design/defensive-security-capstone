# Defensive Security Assessment Capstone Report

## 1. Scope, Authorization & Rules of Engagement
* **Target System:** Local Python/Flask Web Application (`app.py`, running on `127.0.0.1:5000`).
* **Authorization Statement:** Assessment conducted exclusively against a self-hosted local lab application owned by the assessor. No external networks, third-party infrastructure, or production systems were targeted.
* **Rules of Engagement:**
  * Non-destructive testing only (configuration review, dependency audit, HTTP header inspection, boundary input testing, and log review).
  * **Sanitization Policy:** All test accounts (`alice@example.local`), tokens, and IP addresses (`127.0.0.1`) used in this report are synthetic lab placeholders; zero real credentials or PII are stored or exposed.
* **Assessment Domains Covered:** Configuration, Authentication & Session Management, Input Validation, Dependencies, and Security Logging.

---

## 2. Summary of Reproducible Findings & Risk Ratings

| ID | Domain | Finding Title | Severity | Status |
| :--- | :--- | :--- | :---: | :---: |
| **F-01** | Configuration / Auth | Missing `HttpOnly`, `Secure`, and `SameSite` Session Cookie Flags | **High** | **Remediated & Verified** |
| **F-02** | Configuration | Flask Debug Mode Enabled & Hardcoded Secret Key | **High** | **Remediated & Verified** |
| **F-03** | Input Validation | Lack of Server-Side Input Bounds & HTML/Script Character Filtering | **Medium** | **Remediated & Verified** |
| **F-04** | Logging | Absence of Structured Security Audit Logging for Auth Failures | **Medium** | **Remediated & Verified** |
| **F-05** | Configuration | Missing Defensive HTTP Response Headers (`CSP`, `X-Frame-Options`, `nosniff`) | **Low** | **Remediated & Verified** |
| **F-06** | Dependencies | Dependency Version Review (`Flask 3.1.0`, `Werkzeug 3.1.3`) | **Info** | **Verified Up-to-Date** |

---

## 3. Detailed Reproducible Findings & Remediation Evidence

### F-01: Insecure Session Cookie Configuration (High)
* **Reproduction Steps:** Send `POST /login` with valid synthetic lab credentials (`alice@example.local`) and inspect the `Set-Cookie` HTTP response header.
* **Initial Evidence:** Cookie lacked `HttpOnly`, `Secure`, and `SameSite=Strict` attributes, leaving sessions vulnerable to XSS theft and CSRF.
* **Remediation:** Configured `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_SAMESITE="Strict"`, and a 15-minute `PERMANENT_SESSION_LIFETIME`.
* **Retest Result:** Confirmed `HttpOnly; Secure; SameSite=Strict` flags appear on every authenticated `Set-Cookie` header (`test_security_headers_and_cookie_flags` PASSED).

### F-02: Debug Mode Enabled & Static Secret Key (High)
* **Reproduction Steps:** Inspect `app.py` configuration and startup entrypoint.
* **Initial Evidence:** `app.run(debug=True)` exposed interactive stack traces/debugger risk, and `SECRET_KEY` was hardcoded.
* **Remediation:** Set `debug=False` and loaded `APP_SECRET_KEY` from environment variables with `os.urandom(32)` runtime fallback.
* **Retest Result:** Confirmed `app.debug is False` (`test_debug_mode_disabled` PASSED).

### F-03: Unvalidated Input on `/login` and `/note` Endpoints (Medium)
* **Reproduction Steps:** Send `POST /note` with JSON payload `{"content": "<script>alert(1)</script>"}` while authenticated.
* **Initial Evidence:** Server accepted arbitrary-length strings containing HTML/script tags without validation (`HTTP 201`).
* **Remediation:** Added regex email validation on `/login` and enforced 1–500 character length limits plus `<` / `>` rejection on `/note`.
* **Retest Result:** Malicious payload rejected with `HTTP 400 Bad Request` (`test_input_validation_blocks_oversized_and_xss_payloads` PASSED).

### F-04: Missing Security Event Logging (Medium)
* **Reproduction Steps:** Trigger repeated failed logins on `POST /login` and inspect application logs.
* **Initial Evidence:** Failed authentication and invalid input attempts produced no structured security audit trail.
* **Remediation:** Added structured `security_audit` logger recording `LOGIN_SUCCESS`, `LOGIN_FAILED`, and `INVALID_NOTE_INPUT` events with actor/IP metadata while redacting passwords.
* **Retest Result:** Verified structured `[WARNING]` and `[INFO]` audit entries appear with zero credential exposure.

### F-05 & F-06: HTTP Security Headers & Dependency Audit (Low / Info)
* **Remediation & Verification:** Added `@app.after_request` middleware injecting `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Content-Security-Policy: default-src 'self'`. Pinned `Flask==3.1.0` and `Werkzeug==3.1.3` in `requirements.txt` with zero known unpatched vulnerabilities.

---

## 4. Repository Artifacts
* `README.md` — Sanitized Security Assessment Report (Scope, Rules of Engagement, Findings, Remediation & Retest Summary).
* `app.py` — Local web application (view **History** on `app.py` to inspect the baseline vs. remediation commit diff).
* `test_security.py` — Automated `pytest` verification suite.
* `retest-results.txt` — Recorded post-remediation retest output.
* `requirements.txt` — Pinned project dependencies.
