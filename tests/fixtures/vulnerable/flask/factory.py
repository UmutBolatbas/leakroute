from flask import Flask


def create_app():
    app = Flask(__name__)

    @app.post("/api/reports")  # expect: endpoint/flask-unprotected-route
    def reports():
        return {}

    return app
