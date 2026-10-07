from flask import Blueprint
from flask_jwt_extended import verify_jwt_in_request

api_bp = Blueprint("api", __name__)


@api_bp.before_request
def check_token():
    verify_jwt_in_request()


@api_bp.post("/items")
def create_item():
    return {}
