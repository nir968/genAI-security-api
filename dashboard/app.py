#frontend
from flask import Flask, render_template, jsonify, request
import os
import requests

app = Flask(__name__)

# Container name from the deploy cheat sheet: `--name genai-api-container`.
# Single source of truth so the routes below can't drift apart.
FASTAPI_BASE = os.environ.get("GATEWAY_URL", "http://genai-api-container:8000")

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
        response = requests.get(FASTAPI_URL)
        stats = response.json() 
    except:
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

    The dashboard JS cannot call the gateway directly -- `genai-api-container`
    only resolves inside the app-net Docker network, not from the user's
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
    app.run(host="0.0.0.0",port=5001, debug=True)