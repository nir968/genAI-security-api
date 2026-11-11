#frontend
from flask import Flask, render_template, jsonify, request
import os

import requests

app = Flask(__name__)

# Gateway base URL. docker-compose sets http://gateway:8000; the default is for
# running locally without Docker. Single source of truth for all routes below.
FASTAPI_BASE = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000")

# Active endpoint for the backend API running within the Docker network
FASTAPI_URL = FASTAPI_BASE + "/stats"

@app.route('/')
def dashboard():
    """
    Renders the main security dashboard.
    Fetches real-time statistics from the backend API,
    and falls back to an offline state if the service is unreachable.
    """
    try:
        response = requests.get(FASTAPI_URL, timeout=5)
        response.raise_for_status()
        stats = response.json()
    except (requests.RequestException, ValueError):
        # Fallback dictionary for degraded/offline state presentation
        stats = {
            "total_requests": "error",
            "blocked_injections": "error",
            "data_leaks_prevented": "error",
            "status": "API Offline"
        }
        
    return render_template('index.html', stats=stats)


@app.route('/api/activity')
def activity():
    """
    Relays the backend's request history to the browser.

    The dashboard JS cannot call the gateway directly -- the gateway
    hostname only resolves inside the Docker network, not from the user's
    machine -- so this route proxies it same-origin. Errors are passed through
    as a non-200 so the chart shows its empty state instead of stale figures.
    """
    # Widen with /api/activity?hours=N to look further back than a day.
    hours = request.args.get("hours", default=24, type=int) or 24

    try:
        response = requests.get(
            FASTAPI_BASE + "/history", params={"hours": hours}, timeout=5
        )
        response.raise_for_status()
        return jsonify(response.json())
    except requests.RequestException as exc:
        return jsonify({"error": "Backend unreachable", "detail": str(exc)}), 502


if __name__ == '__main__':
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=5001, debug=debug)