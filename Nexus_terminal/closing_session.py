# closing_session.py
from flask import Blueprint, jsonify, render_template, session, current_app
from datetime import datetime

session_bp = Blueprint("session_bp", __name__)

# default: 15 minutes (in seconds)
INACTIVITY_TIMEOUT_DEFAULT = 15 * 60

@session_bp.before_app_request
def check_activity():
    # use the same keys your app actually sets
    if session.get("authenticated"):
        last = session.get("last_activity")
        now = datetime.utcnow().timestamp()
        timeout = current_app.config.get("INACTIVITY_TIMEOUT", INACTIVITY_TIMEOUT_DEFAULT)
        if last and (now - last > timeout):
            session.clear()
            # show login with an error
            return render_template("index.html", error="Session has expired due to inactivity")

@session_bp.route("/activity", methods=["POST"])
def update_activity():
    if not session.get("authenticated"):
        return jsonify({"status": "not_logged"}), 401
    session["last_activity"] = datetime.utcnow().timestamp()
    return jsonify({"status": "ok"}), 200
