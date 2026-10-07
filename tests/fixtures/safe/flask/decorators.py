from functools import wraps

from flask import abort
from flask_login import current_user


def staff_only(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not getattr(current_user, "is_staff", False):
            abort(403)
        return view(*args, **kwargs)

    return wrapper
