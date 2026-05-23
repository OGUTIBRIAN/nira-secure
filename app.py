from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from datetime import timedelta

db  = SQLAlchemy()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"]                     = "nira-secure-2026"
    app.config["SQLALCHEMY_DATABASE_URI"]        = "sqlite:///nira.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"]                 = "jwt-nira-2026"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"]       = timedelta(hours=8)

    db.init_app(app)
    jwt.init_app(app)

    with app.app_context():
        from models.db_models import Citizen, QRToken, ScanEvent, Alert
        db.create_all()
        print("✅ Database ready")

    from routes.auth import auth_bp
    from routes.qr   import qr_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(qr_bp,   url_prefix="/api/qr")

    @app.route("/")
    def index():
        return {"system": "NIRA Secure", "status": "running"}

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)
