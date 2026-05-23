from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from models.db_models import Citizen

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
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
        face_hash     = "demo_face_hash",
        iris_hash     = "demo_iris_hash",
        is_verified   = True
    )
    db.session.add(citizen)
    db.session.commit()
    return jsonify({"message": "Registered successfully", "id": citizen.id}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    citizen = Citizen.query.filter_by(nin=data["nin"]).first()
    if not citizen or not check_password_hash(citizen.password_hash, data["password"]):
        return jsonify({"error": "Invalid NIN or password"}), 401
    token = create_access_token(identity=citizen.id)
    return jsonify({"token": token, "citizen": citizen.to_dict()}), 200
