import os
from getpass import getpass

SECRET_KEY = os.environ["SECRET_KEY"]
API_KEY = "changeme"
DATABASE_PASSWORD = getpass()
TOKEN_EXPIRY = "3600"
PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher"]
