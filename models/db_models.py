from datetime import datetime
import uuid
from app import db

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
            "nin":           self.nin[:4] + "••••" + self.nin[-2:],
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
        return (
            not self.is_revoked and
            not self.is_used and
            datetime.utcnow() < self.expires_at
        )

class ScanEvent(db.Model):
    __tablename__ = "scan_events"
    id               = db.Column(db.String(36), primary_key=True, default=new_uuid)
    citizen_id       = db.Column(db.String(36), db.ForeignKey("citizens.id"), nullable=False)
    qr_token_id      = db.Column(db.String(36), db.ForeignKey("qr_tokens.id"))
    scanner_location = db.Column(db.String(120))
    scanner_type     = db.Column(db.String(30))
    scanner_ip       = db.Column(db.String(45))
    scan_result      = db.Column(db.String(20))
    biometric_match  = db.Column(db.Boolean)
    ai_risk_score    = db.Column(db.Float, default=0.0)
    ai_flags         = db.Column(db.Text)
    scanned_at       = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    __tablename__ = "alerts"
    id             = db.Column(db.String(36), primary_key=True, default=new_uuid)
    citizen_id     = db.Column(db.String(36), db.ForeignKey("citizens.id"), nullable=False)
    alert_type     = db.Column(db.String(30))
    severity       = db.Column(db.String(10))
    title          = db.Column(db.String(120))
    message        = db.Column(db.Text)
    is_read        = db.Column(db.Boolean, default=False)
    sent_to_police = db.Column(db.Boolean, default=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
