import os
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid, hashlib, hmac, json, time

app = Flask(__name__)
app.config["SECRET_KEY"]                     = "nira-secure-2026"
app.config["SQLALCHEMY_DATABASE_URI"]        = "sqlite:///nira.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"]                 = "jwt-nira-2026"
app.config["JWT_ACCESS_TOKEN_EXPIRES"]       = timedelta(hours=8)

db  = SQLAlchemy(app)
jwt = JWTManager(app)

# ── Models ────────────────────────────────────────────────────────────────────
def new_uuid():
    return str(uuid.uuid4())

class Citizen(db.Model):
    __tablename__ = "citizens"
    id            = db.Column(db.String(36), primary_key=True, default=new_uuid)
    nin           = db.Column(db.String(20), unique=True, nullable=False)
    surname       = db.Column(db.String(80), nullable=False)
    given_name    = db.Column(db.String(80), nullable=False)
    date_of_birth = db.Column(db.String(12), nullable=False)
    sex           = db.Column(db.String(1),  nullable=False)
    district      = db.Column(db.String(60))
    phone         = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    face_hash     = db.Column(db.String(64))
    iris_hash     = db.Column(db.String(64))
    is_verified   = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":            self.id,
            "nin":           self.nin[:4] + "****" + self.nin[-2:],
            "name":          f"{self.surname} {self.given_name}",
            "date_of_birth": self.date_of_birth,
            "district":      self.district,
            "is_verified":   self.is_verified,
        }

class QRToken(db.Model):
    __tablename__ = "qr_tokens"
    id             = db.Column(db.String(36), primary_key=True, default=new_uuid)
    citizen_id     = db.Column(db.String(36), db.ForeignKey("citizens.id"), nullable=False)
    token_hash     = db.Column(db.String(128), nullable=False)
    face_hash_used = db.Column(db.String(64))
    iris_hash_used = db.Column(db.String(64))
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at     = db.Column(db.DateTime, nullable=False)
    is_used        = db.Column(db.Boolean, default=False)
    is_revoked     = db.Column(db.Boolean, default=False)

    def is_valid(self):
        return (not self.is_revoked and
                not self.is_used and
                datetime.utcnow() < self.expires_at)

class ScanEvent(db.Model):
    __tablename__    = "scan_events"
    id               = db.Column(db.String(36), primary_key=True, default=new_uuid)
    citizen_id       = db.Column(db.String(36), db.ForeignKey("citizens.id"), nullable=False)
    scanner_location = db.Column(db.String(120))
    scanner_type     = db.Column(db.String(30))
    scan_result      = db.Column(db.String(20))
    ai_risk_score    = db.Column(db.Float, default=0.0)
    ai_flags         = db.Column(db.Text)
    scanned_at       = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    __tablename__ = "alerts"
    id            = db.Column(db.String(36), primary_key=True, default=new_uuid)
    citizen_id    = db.Column(db.String(36), db.ForeignKey("citizens.id"), nullable=False)
    alert_type    = db.Column(db.String(30))
    severity      = db.Column(db.String(10))
    title         = db.Column(db.String(120))
    message       = db.Column(db.Text)
    is_read       = db.Column(db.Boolean, default=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()
    print("✅ Database ready")

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    if Citizen.query.filter_by(nin=data["nin"]).first():
        return jsonify({"error": "NIN already registered"}), 400
    citizen = Citizen(
        nin           = data["nin"],
        surname       = data["surname"],
        given_name    = data["given_name"],
        date_of_birth = data["date_of_birth"],
        sex           = data["sex"],
        district      = data.get("district", ""),
        phone         = data["phone"],
        password_hash = generate_password_hash(data["password"]),
        face_hash     = "face_hash_demo",
        iris_hash     = "iris_hash_demo",
        is_verified   = True
    )
    db.session.add(citizen)
    db.session.commit()
    return jsonify({"message": "Registered successfully", "id": citizen.id}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data    = request.get_json()
    citizen = Citizen.query.filter_by(nin=data["nin"]).first()
    if not citizen or not check_password_hash(citizen.password_hash, data["password"]):
        return jsonify({"error": "Invalid NIN or password"}), 401
    token = create_access_token(identity=citizen.id)
    return jsonify({"token": token, "citizen": citizen.to_dict()}), 200

# ── QR routes ─────────────────────────────────────────────────────────────────
QR_SECRET = "nira-qr-secret-2026"

@app.route("/api/qr/generate", methods=["POST"])
@jwt_required()
def generate_qr():
    citizen_id = get_jwt_identity()
    citizen    = Citizen.query.get(citizen_id)
    if not citizen:
        return jsonify({"error": "Citizen not found"}), 404
    expires_at   = datetime.utcnow() + timedelta(seconds=60)
    payload      = {
        "nin":       citizen.nin,
        "name":      f"{citizen.surname} {citizen.given_name}",
        "face":      citizen.face_hash,
        "iris":      citizen.iris_hash,
        "issued_at": time.time(),
        "expires":   expires_at.isoformat(),
    }
    payload_json = json.dumps(payload, sort_keys=True)
    token_hash   = hmac.new(
        QR_SECRET.encode(), payload_json.encode(), hashlib.sha256
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

@app.route("/api/qr/verify/<token_hash>", methods=["GET"])
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

# ── Monitor route ─────────────────────────────────────────────────────────────
@app.route("/api/monitor/activity", methods=["GET"])
@jwt_required()
def activity():
    citizen_id = get_jwt_identity()
    scans = ScanEvent.query.filter_by(citizen_id=citizen_id)\
                           .order_by(ScanEvent.scanned_at.desc()).limit(10).all()
    alerts = Alert.query.filter_by(citizen_id=citizen_id)\
                        .order_by(Alert.created_at.desc()).limit(10).all()
    return jsonify({
        "scans":  [s.scanned_at.isoformat() for s in scans],
        "alerts": [{"title": a.title, "severity": a.severity} for a in alerts]
    }), 200

@app.route("/")
def index():
    return jsonify({"system": "NIRA Secure", "status": "running", "version": "1.0"})

# ── Consent routes ────────────────────────────────────────────────────────────
from ai.consent import (create_consent_request, citizen_respond,
                        check_consent_status, get_nin_usage_history)

@app.route("/api/consent/request", methods=["POST"])
def request_consent():
    data = request.get_json()
    citizen = Citizen.query.filter_by(nin=data.get("nin")).first()
    if not citizen:
        return jsonify({"error": "NIN not found"}), 404
    result = create_consent_request(
        citizen_id   = citizen.id,
        nin          = data.get("nin"),
        service_name = data.get("service_name"),
        service_type = data.get("service_type"),
        purpose      = data.get("purpose")
    )
    return jsonify(result), 200

@app.route("/api/consent/respond", methods=["POST"])
@jwt_required()
def respond_consent():
    citizen_id = get_jwt_identity()
    citizen    = Citizen.query.get(citizen_id)
    data       = request.get_json()
    result, status = citizen_respond(
        consent_id         = data.get("consent_id"),
        decision           = data.get("decision"),
        iris_hash_provided = data.get("iris_hash", "demo_iris_hash"),
        stored_iris_hash   = citizen.iris_hash
    )
    return jsonify(result), status

@app.route("/api/consent/status/<consent_id>", methods=["GET"])
def consent_status(consent_id):
    return jsonify(check_consent_status(consent_id)), 200

@app.route("/api/consent/history", methods=["GET"])
@jwt_required()
def consent_history():
    citizen_id = get_jwt_identity()
    return jsonify(get_nin_usage_history(citizen_id)), 200

# ── Start server ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
