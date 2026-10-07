from flask import Flask, jsonify
from flask_login import login_required

from admin import admin_bp

app = Flask(__name__)


@app.route("/")
def index():
    return "home"


@app.route("/api/posts", methods=["GET", "POST"])  # expect: endpoint/flask-unprotected-route
def posts():
    return jsonify([])


@login_required
@app.route("/api/account/delete", methods=["POST"])  # expect: endpoint/flask-auth-decorator-order
def delete_account():
    return "", 204


app.register_blueprint(admin_bp, url_prefix="/admin")
