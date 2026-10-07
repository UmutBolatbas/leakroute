from flask import Flask, abort
from flask_httpauth import HTTPBasicAuth
from flask_jwt_extended import jwt_required
from flask_login import current_user, login_required

from api import api_bp
from decorators import staff_only

app = Flask(__name__)
auth = HTTPBasicAuth()


@app.route("/login", methods=["GET", "POST"])
def login():
    return "login"


@app.route("/dashboard")
@login_required
def dashboard():
    return "dashboard"


@app.post("/api/tokens")
@jwt_required()
def tokens():
    return {}


@app.route("/api/stats")
@auth.login_required
def stats():
    return {}


@app.delete("/api/admin/users/<int:user_id>")
@staff_only
def delete_user(user_id):
    return "", 204


@app.route("/settings", methods=["POST"])
def settings():
    if not current_user.is_authenticated:
        abort(401)
    return "saved"


app.register_blueprint(api_bp, url_prefix="/api/v2")
