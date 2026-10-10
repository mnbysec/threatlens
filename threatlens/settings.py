"""ThreatLens — user settings (Slack webhook, preferences).

Persisted at data/settings.json as {user_key: {slack_webhook: "...", ...}}.
"""

import json
import os
import threading

from .engine import DATA_DIR

SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
_lock = threading.Lock()


def _load():
    try:
        with open(SETTINGS_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _save(data):
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    with open(SETTINGS_PATH, "w") as f:
        json.dump(data, f, indent=2)


def get(user_key):
    with _lock:
        return _load().get(user_key) or {}


def update(user_key, **kw):
    with _lock:
        data = _load()
        entry = data.get(user_key) or {}
        entry.update(kw)
        data[user_key] = entry
        _save(data)
    return entry


def slack_webhook(user_key):
    """Return the Slack webhook URL — user setting first, then env var."""
    url = get(user_key).get("slack_webhook", "").strip()
    if url:
        return url
    return os.environ.get("SLACK_WEBHOOK_URL", "").strip() or None
