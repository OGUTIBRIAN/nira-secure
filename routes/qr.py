from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import hashlib, hmac, json, time
from app import db
from models.db_models import Citizen, QRToken

qr_bp = Blueprint("qr", __name__)
SECRET = "nira-qr-secret-2026"

@qr_bp.route("/generate", methods=["POST"])
@jwt_required()
def generate_qr():
    citizen_id = get_jwt_identity()
    citizen = Citizen.query.get(citizen_id)
    if not citizen:
        return jsonify({"error": "Citizen not found"}), 404
    expires_at = datetime.utcnow() + timedelta(seconds=60)
    payload = {
        "nin":       citizen.nin,
        "name":      f"{citizen.surname} {citizen.given_name}",
        "face":      citizen.face_hash,
        "iris":      citizen.iris_hash,
        "issued_at": time.time(),
        "expires":   expires_at.isoformat(),
    }
    payload_json = json.dumps(payload, sort_keys=True)
    token_hash = hmac.new(
        SECRET.encode(), payload_json.encode(), hashlib.sha256
    ).hexdigest()
    qr = QRToken(
        citizen_id     = citizen_id,
        token_hash     = token_hash,
        face_hash_used = citizen.face_hash,
        iris_hash_used = citizen.iris_hash,
        expires_at     = expires_at
    )
    db.session.add(qr)
    db.session.commit()
    return jsonify({
        "qr_id":      qr.id,
        "token_hash": token_hash,
        "expires_at": expires_at.isoformat(),
        "expires_in": 60,
        "citizen":    citizen.to_dict()
    }), 200

@qr_bp.route("/verify/<token_hash>", methods=["GET"])
def verify_qr(token_hash):
    qr = QRToken.query.filter_by(token_hash=token_hash).first()
    if not qr:
        return jsonify({"valid": False, "reason": "QR not found"}), 404
    if not qr.is_valid():
        return jsonify({"valid": False, "reason": "QR expired or used"}), 400
    citizen = Citizen.query.get(qr.citizen_id)
    return jsonify({
        "valid":   True,
        "citizen": citizen.to_dict(),
        "issued":  qr.created_at.isoformat()
    }), 200
