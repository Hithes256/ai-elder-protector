# backend/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timezone
import uuid
import os
from twilio.rest import Client

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# -------------------------
# Twilio config (use env vars)
# -------------------------
TWILIO_SID = os.environ.get("TWILIO_SID", "")
TWILIO_AUTH = os.environ.get("TWILIO_AUTH", "")
TWILIO_NUMBER = os.environ.get("TWILIO_NUMBER", "")  # e.g. "+15017122661"

if TWILIO_SID and TWILIO_AUTH:
    twilio_client = Client(TWILIO_SID, TWILIO_AUTH)
else:
    twilio_client = None

# -------------------------
# In-memory DB (demo)
# In production, use real DB (sqlite/postgres)
# -------------------------
USERS_DB = {}   # { email: { profile: {...}, family: [...], history: [...] } }
ALERTS_DB = []  # global alert log
FAMILY_LOG_DB = []  # SMS send logs


# -------------------------
# Utilities
# -------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def gen_id():
    return "id_" + uuid.uuid4().hex[:12]

def clean_and_e164(phone_raw, default_country="91"):
    """
    Convert a variety of phone formats into E.164 string for Twilio.
    - Accepts: "9876543210", "919876543210", "+919876543210", "09876543210"
    - Returns: "+919876543210" or None if invalid
    """
    if not phone_raw:
        return None
    s = str(phone_raw).strip()
    # remove spaces, dashes, brackets
    for ch in [" ", "-", "(", ")", "."]:
        s = s.replace(ch, "")
    # remove leading plus for checks
    if s.startswith("+"):
        s_noplus = s[1:]
    else:
        s_noplus = s

    # If exactly 10 digits -> assume local Indian -> prefix default_country
    if s_noplus.isdigit():
        if len(s_noplus) == 10:
            return f"+{default_country}{s_noplus}"
        if len(s_noplus) == 12 and s_noplus.startswith(default_country):
            return f"+{s_noplus}"
        if len(s_noplus) == 11 and s_noplus.startswith("0") and s_noplus[1:].isdigit() and len(s_noplus[1:]) == 10:
            return f"+{default_country}{s_noplus[1:]}"
    # If s started with country code and digits
    if s.startswith("+") and s[1:].isdigit():
        return s
    # fallback: return None for invalid
    return None


# -------------------------
# SMS sending via Twilio
# -------------------------
def send_sms_twilio_single(to_e164, body_text):
    if not twilio_client:
        # Twilio not configured; return simulated result
        return {"ok": False, "error": "Twilio not configured (env missing)."}
    try:
        msg = twilio_client.messages.create(
            body=body_text,
            from_=TWILIO_NUMBER,
            to=to_e164
        )
        return {"ok": True, "sid": msg.sid}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# -------------------------
# Simple message analyzer (rule-based)
# Replace with HuggingFace model if you want
# -------------------------
def analyze_message(message_text):
    try:
        keywords = ["otp", "urgent", "bank", "blocked", "verify", "password", "transfer", "account", "click", "wire"]
        lower = (message_text or "").lower()
        is_scam = any(k in lower for k in keywords)
        elder_warning = "⚠ This message looks suspicious. Do NOT share OTP/passwords." if is_scam else "✔ This message appears safe."
        explanation = "Detected using keyword rules (demo)."
        return {"is_scam": is_scam, "elder_warning": elder_warning, "explanation": explanation}
    except Exception as e:
        return {"is_scam": None, "elder_warning": "AI could not analyze this message.", "explanation": str(e)}


# -------------------------
# Save alert
# -------------------------
def save_alert(sender, message, analysis, user_email=None):
    alert = {
        "id": gen_id(),
        "sender": sender,
        "message": message,
        "is_scam": analysis.get("is_scam"),
        "elder_warning": analysis.get("elder_warning"),
        "explanation": analysis.get("explanation"),
        "created_at": now_iso(),
        "user_email": user_email
    }
    ALERTS_DB.insert(0, alert)
    # also store in user history if user exists
    if user_email:
        user = USERS_DB.setdefault(user_email, {"profile": {"email": user_email, "name": "", "phone": ""}, "family": [], "history": []})
        user["history"].insert(0, alert)
    return alert


# -------------------------
# Routes
# -------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    email = (data.get("email") or "").lower()
    if not email:
        return jsonify({"success": False, "error": "email required"}), 400
    # create user record if missing
    USERS_DB.setdefault(email, {"profile": {"email": email, "name": "", "phone": ""}, "family": [], "history": []})
    return jsonify({"success": True, "user": USERS_DB[email]})


@app.route("/save-profile", methods=["POST"])
def save_profile():
    data = request.json or {}
    email = (data.get("email") or "").lower()
    profile = data.get("profile") or {}
    if not email:
        return jsonify({"success": False, "error": "email required"}), 400
    USERS_DB.setdefault(email, {"profile": {"email": email, "name": "", "phone": ""}, "family": [], "history": []})
    USERS_DB[email]["profile"] = profile
    return jsonify({"success": True})


@app.route("/save-family", methods=["POST"])
def save_family():
    data = request.json or {}
    email = (data.get("email") or "").lower()
    family = data.get("family") or []
    if not email:
        return jsonify({"success": False, "error": "email required"}), 400
    USERS_DB.setdefault(email, {"profile": {"email": email, "name": "", "phone": ""}, "family": [], "history": []})
    USERS_DB[email]["family"] = family
    return jsonify({"success": True})


@app.route("/alerts", methods=["GET"])
def get_alerts():
    # query param filter by email optional
    email = request.args.get("email")
    if email:
        user = USERS_DB.get(email.lower())
        return jsonify({"alerts": user.get("history", []) if user else []})
    return jsonify({"alerts": ALERTS_DB})


@app.route("/test-message", methods=["POST"])
def test_message():
    data = request.json or {}
    email = (data.get("email") or "").lower()
    sender = data.get("sender") or "User"
    message = data.get("message") or ""

    # analyze and save
    analysis = analyze_message(message)
    alert = save_alert(sender, message, analysis, user_email=email if email else None)

    # If scam -> send SMS to user and family
    if analysis.get("is_scam") is True:
        recipients = set()
        # user's phone
        if email and USERS_DB.get(email) and USERS_DB[email]["profile"].get("phone"):
            recipients.add(USERS_DB[email]["profile"]["phone"])
        # family phones
        if email and USERS_DB.get(email):
            for m in USERS_DB[email].get("family", []):
                phone = m.get("phone")
                if phone:
                    recipients.add(phone)
        # Clean & convert to e164
        cleaned = []
        for ph in recipients:
            e = clean_and_e164(ph)
            if e:
                cleaned.append(e)
            else:
                print("Invalid phone skipped:", ph)

        sms_body = f"⚠ Scam alert for {sender}: {analysis.get('elder_warning')}"

        sms_results = []
        for e164 in cleaned:
            res = send_sms_twilio_single(e164, sms_body)
            log_entry = {
                "id": gen_id(),
                "to": e164,
                "body": sms_body,
                "result": res,
                "created_at": now_iso()
            }
            FAMILY_LOG_DB.insert(0, log_entry)
            sms_results.append(log_entry)

        return jsonify({"success": True, "alert": alert, "sms_sent": sms_results})

    return jsonify({"success": True, "alert": alert})


@app.route("/send-family-alert", methods=["POST"])
def send_family_alert():
    data = request.json or {}
    phones = data.get("phones", [])  # raw list from frontend
    message_text = data.get("message", "")
    details = data.get("details", {})

    if not isinstance(phones, list) or not phones:
        return jsonify({"success": False, "error": "phones must be a non-empty list"}), 400

    # clean & e164
    cleaned = []
    for p in phones:
        e = clean_and_e164(p)
        if e:
            cleaned.append(e)
        else:
            print("Invalid phone skipped (send-family-alert):", p)

    if not cleaned:
        return jsonify({"success": False, "error": "no valid phone numbers after cleaning"}), 400

    sms_results = []
    for e164 in cleaned:
        res = send_sms_twilio_single(e164, message_text)
        entry = {
            "id": gen_id(),
            "to": e164,
            "message_sent": message_text,
            "details": details,
            "result": res,
            "created_at": now_iso()
        }
        FAMILY_LOG_DB.insert(0, entry)
        sms_results.append(entry)

    return jsonify({"success": True, "sent": cleaned, "logs": sms_results})


@app.route("/family-logs", methods=["GET"])
def family_logs():
    return jsonify({"logs": FAMILY_LOG_DB})


# -------------------------
# Run app
# -------------------------
if __name__ == "__main__":
    print("Twilio configured:", bool(twilio_client))
    app.run(host="0.0.0.0", port=5000, debug=True)
