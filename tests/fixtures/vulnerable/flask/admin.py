from flask import Blueprint

# The url_prefix passed to register_blueprint replaces this one.
admin_bp = Blueprint("admin", __name__, url_prefix="/dashboard")


@admin_bp.get("/users")  # expect: endpoint/flask-unprotected-route
def users():
    return []
