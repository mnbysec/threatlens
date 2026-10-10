"""ThreatLens — standalone Flask application.

Run with: python app.py
Or:       gunicorn app:app -b 0.0.0.0:8080
"""

import datetime
import os
import time

from flask import Flask, jsonify, request, send_from_directory

from threatlens import engine, bookmarks, assets, news, notify, monitor, settings

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "threatlens-dev-key-change-me")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# User identity — simple API-key or no-auth mode for self-hosted
# ---------------------------------------------------------------------------

def _user_key():
    """Derive a user key from the API key header, or fall back to 'default'."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return "key:" + auth[7:].strip()[:32]
    return "default"


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.route("/api/health")
def health():
    return jsonify({"ok": True, "service": "threatlens", "version": "1.0"})


# ---------------------------------------------------------------------------
# Advisory feed
# ---------------------------------------------------------------------------

def _valid_date(date):
    try:
        return datetime.datetime.strptime(date, "%Y-%m-%d").strftime("%Y-%m-%d")
    except ValueError:
        return None


@app.route("/api/feed")
def feed():
    date = _valid_date(request.args.get("date") or "")
    if not date:
        date = datetime.date.today().isoformat()
    force = request.args.get("refresh") == "1"
    feed = engine.get_feed(date, force=force)

    bmarks = bookmarks.get(_user_key())
    asset_list = assets.get(_user_key())
    if bmarks or asset_list:
        for a in feed["advisories"]:
            a["_bookmarked"] = bool(bmarks) and any(
                engine.match_bookmark(a, t) for t in bmarks)
            a["_asset_match"] = bool(asset_list) and any(
                engine.match_asset(a, t["name"]) for t in asset_list)
    return jsonify(feed)


@app.route("/api/stats")
def stats():
    today = datetime.date.today().isoformat()
    feed = engine.get_feed(today)
    return jsonify({
        "trend": engine.get_trend(7),
        "by_source": feed.get("by_source", {}),
        "by_severity": feed.get("by_severity", {}),
    })


# ---------------------------------------------------------------------------
# News
# ---------------------------------------------------------------------------

_news_cache = {"at": 0, "items": []}


def _cached_news():
    now = time.time()
    if _news_cache["items"] and now - _news_cache["at"] < 600:
        return _news_cache["items"]
    items = news.fetch_news()
    _news_cache["at"] = now
    _news_cache["items"] = items
    return items


@app.route("/api/news")
def news_route():
    return jsonify({"items": _cached_news()})


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

@app.route("/api/bookmarks", methods=["GET"])
def bookmarks_get():
    uk = _user_key()
    return jsonify({
        "bookmarks": bookmarks.get(uk),
        "slack_configured": notify.is_configured(uk),
    })


@app.route("/api/bookmarks", methods=["POST"])
def bookmarks_add():
    data = request.get_json(silent=True) or {}
    tech = (data.get("tech") or "").strip()
    if not tech:
        return jsonify({"error": "tech required"}), 400
    return jsonify({"bookmarks": bookmarks.add(_user_key(), tech)})


@app.route("/api/bookmarks", methods=["DELETE"])
def bookmarks_remove():
    data = request.get_json(silent=True) or {}
    tech = (data.get("tech") or "").strip()
    if not tech:
        return jsonify({"error": "tech required"}), 400
    return jsonify({"bookmarks": bookmarks.remove(_user_key(), tech)})


# ---------------------------------------------------------------------------
# Slack test
# ---------------------------------------------------------------------------

@app.route("/api/test-webhook", methods=["POST"])
def test_webhook():
    uk = _user_key()
    if not notify.is_configured(uk):
        return jsonify({"ok": False, "detail": "No Slack webhook configured. Paste your webhook URL in Settings below."})
    ok = notify.send_slack(
        "ThreatLens test notification — your webhook is working.",
        [{"type": "section", "text": {"type": "mrkdwn",
                                      "text": ":white_check_mark: *ThreatLens* webhook test — advisories for your bookmarks will arrive here."}}],
        user_key=uk)
    return jsonify({"ok": ok})


# ---------------------------------------------------------------------------
# Monitor status
# ---------------------------------------------------------------------------

@app.route("/api/status")
def monitor_status():
    uk = _user_key()
    return jsonify({
        "monitor": monitor.status(),
        "slack_configured": notify.is_configured(uk),
    })


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@app.route("/api/settings", methods=["GET"])
def settings_get():
    s = settings.get(_user_key())
    return jsonify({"slack_webhook": s.get("slack_webhook", "")})


@app.route("/api/settings", methods=["POST"])
def settings_update():
    data = request.get_json(silent=True) or {}
    webhook = (data.get("slack_webhook") or "").strip()
    if webhook and not webhook.startswith("https://hooks.slack.com/"):
        return jsonify({"error": "Invalid Slack webhook URL"}), 400
    settings.update(_user_key(), slack_webhook=webhook)
    return jsonify({"ok": True, "slack_webhook": webhook})


# ---------------------------------------------------------------------------
# Assets / SBOM
# ---------------------------------------------------------------------------

def _assets_payload():
    uk = _user_key()
    return jsonify({
        "sources": assets.get_sources(uk),
        "assets": assets.get(uk),
        "count": len(assets.get(uk)),
    })


@app.route("/api/assets", methods=["GET"])
def assets_get():
    return _assets_payload()


@app.route("/api/assets", methods=["POST"])
def assets_upload():
    uk = _user_key()

    # 1) SBOM file upload
    if request.files and "file" in request.files:
        f = request.files["file"]
        data = f.read(10 * 1024 * 1024)
        parsed = assets.parse_sbom(data, f.filename or "")
        if not parsed:
            return jsonify({"error": "Could not parse any assets from that file."}), 400
        assets.add_source(uk, {
            "name": (f.filename or "Uploaded SBOM").split(".")[0][:40] or "Uploaded SBOM",
            "type": "sbom",
            "assets": parsed,
        })
        return _assets_payload()

    data = request.get_json(silent=True) or {}

    # 2) API source
    source = data.get("source")
    if isinstance(source, dict):
        stype = source.get("type") or "api"
        src = {
            "name": (source.get("name") or "API source")[:40],
            "type": stype,
            "provider": source.get("provider") or "",
            "config": source.get("config") or {},
            "assets": [],
        }
        if stype == "api":
            src["status"] = "pending"
            assets.add_source(uk, src)
            created = max(
                (s for s in assets.get_sources(uk) if s.get("type") == "api"),
                key=lambda s: s.get("updated_at") or 0, default=None)
            if created:
                assets.resync_source(uk, created.get("id"))
            return _assets_payload()
        assets.add_source(uk, src)
        return _assets_payload()

    # 3) Manual list
    provided = data.get("assets")
    if isinstance(provided, list):
        cleaned = []
        for item in provided:
            name = item.get("name") if isinstance(item, dict) else str(item)
            n = assets._clean_name(name)
            if n:
                cleaned.append({"name": n, "version": (item.get("version") if isinstance(item, dict) else None)})
        assets.add_source(uk, {
            "name": (data.get("name") or "Manual list")[:40],
            "type": "manual",
            "assets": cleaned,
        })
        return _assets_payload()

    return jsonify({"error": "Upload an SBOM, POST {\"assets\":[...]}, or {\"source\":{\"type\":\"api\",...}}"}), 400


@app.route("/api/assets/<source_id>/resync", methods=["POST"])
def assets_resync(source_id):
    src = assets.resync_source(_user_key(), source_id)
    if src is None:
        return jsonify({"error": "unknown source"}), 404
    return _assets_payload()


@app.route("/api/assets/<source_id>", methods=["DELETE"])
def assets_remove(source_id):
    assets.remove_source(_user_key(), source_id)
    return _assets_payload()


# ---------------------------------------------------------------------------
# Frontend — serve index.html and sample data
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(os.path.join(BASE_DIR, "templates"), "index.html")


@app.route("/demo/sbom/<path:filename>")
def demo_sbom(filename):
    return send_from_directory(os.path.join(BASE_DIR, "demo", "sbom"), filename)


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

monitor.start_scheduler()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"ThreatLens running at http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
