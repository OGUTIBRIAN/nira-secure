"""
NIRA Secure — NIN Consent Gateway
Blocks third-party NIN usage without citizen's biometric approval.
Solves: betting sites, SIM cards, loans registered without permission.
"""
from datetime import datetime, timedelta
import uuid

# Third party services that MUST request consent before using a NIN
REQUIRES_CONSENT = [
    "betting",        # BetPawa, SportPesa etc
    "sim_registration",  # Telecom companies
    "loan",           # Microfinance, mobile loans
    "bank_account",   # Bank registrations
    "insurance",      # Insurance companies
    "employment",     # Background checks
]

# In-memory store for pending consent requests
# In production this would be in the database
pending_consents = {}

def create_consent_request(citizen_id, nin, service_name, service_type, purpose):
    """
    Called when a third party wants to use a citizen's NIN.
    Creates a pending request and notifies the citizen.
    Returns a consent_token the service must wait for.
    """
    consent_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    pending_consents[consent_id] = {
        "consent_id":   consent_id,
        "citizen_id":   citizen_id,
        "nin":          nin,
        "service_name": service_name,
        "service_type": service_type,
        "purpose":      purpose,
        "status":       "pending",
        "created_at":   datetime.utcnow(),
        "expires_at":   expires_at,
        "iris_verified": False,
        "decision":     None,
    }

    # In production: send SMS + push notification to citizen
    notification = {
        "to":      citizen_id,
        "title":   f"⚠️ NIN Usage Request",
        "message": f"{service_name} wants to use your NIN for: {purpose}. "
                   f"Open NIRA Secure to APPROVE or BLOCK this request.",
        "action":  f"consent/{consent_id}",
        "urgent":  service_type in ["betting", "loan"],
    }

    print(f"📱 NOTIFICATION → Citizen {citizen_id[:8]}...")
    print(f"   {service_name} wants to use NIN for: {purpose}")
    print(f"   Consent ID: {consent_id}")

    return {
        "consent_id":  consent_id,
        "status":      "pending",
        "expires_at":  expires_at.isoformat(),
        "message":     f"Consent request sent to citizen. Waiting for iris approval.",
        "notification": notification,
    }

def citizen_respond(consent_id, decision, iris_hash_provided, stored_iris_hash):
    """
    Called when citizen approves or denies the request.
    Requires iris verification to approve — blocks without it.
    """
    if consent_id not in pending_consents:
        return {"error": "Consent request not found or expired"}, 404

    request = pending_consents[consent_id]

    if datetime.utcnow() > request["expires_at"]:
        request["status"] = "expired"
        return {"error": "Consent request expired — request was auto-blocked"}, 400

    if decision == "approve":
        # MUST verify iris before approving
        if iris_hash_provided != stored_iris_hash:
            return {
                "error":   "Iris verification failed — cannot approve without biometric match",
                "blocked": True
            }, 403
        request["status"]       = "approved"
        request["iris_verified"] = True
        request["decision"]     = "approved"
        request["decided_at"]   = datetime.utcnow()

        return {
            "status":        "approved",
            "iris_verified": True,
            "service":       request["service_name"],
            "message":       "NIN use approved with iris verification",
            "valid_for":     "one-time use only"
        }, 200

    else:
        # Deny — no iris needed to block
        request["status"]   = "denied"
        request["decision"] = "denied"

        # Log as potential fraud attempt
        fraud_log = {
            "event":        "NIN_USE_DENIED",
            "service":      request["service_name"],
            "service_type": request["service_type"],
            "citizen_id":   request["citizen_id"],
            "blocked_at":   datetime.utcnow().isoformat(),
            "alert":        "Consider reporting this to police if you did not initiate this request"
        }
        print(f"🚨 FRAUD LOG: {fraud_log}")

        return {
            "status":  "denied",
            "service": request["service_name"],
            "message": "NIN use blocked by citizen",
            "advice":  "If you did not initiate this request, report to police immediately"
        }, 200

def check_consent_status(consent_id):
    """
    Called by third party service to check if citizen approved.
    Service CANNOT proceed without approved status.
    """
    if consent_id not in pending_consents:
        return {"status": "not_found", "can_proceed": False}

    request = pending_consents[consent_id]

    if datetime.utcnow() > request["expires_at"] and request["status"] == "pending":
        request["status"] = "expired"

    return {
        "status":       request["status"],
        "can_proceed":  request["status"] == "approved" and request["iris_verified"],
        "iris_verified": request["iris_verified"],
        "service":      request["service_name"],
    }

def get_nin_usage_history(citizen_id):
    """
    Returns all consent requests for a citizen —
    shows them everywhere their NIN has been used or attempted.
    """
    history = [
        {
            "service":      r["service_name"],
            "service_type": r["service_type"],
            "purpose":      r["purpose"],
            "status":       r["status"],
            "iris_verified": r["iris_verified"],
            "date":         r["created_at"].isoformat(),
        }
        for r in pending_consents.values()
        if r["citizen_id"] == citizen_id
    ]
    return sorted(history, key=lambda x: x["date"], reverse=True)
