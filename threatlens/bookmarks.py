"""ThreatLens — per-user tech-stack bookmarks.

Persisted at `data/bookmarks.json` as {user_key: [tech, ...]}. Bookmark
names are matched against advisory text (see engine.match_bookmark).
"""

import json
import os
import threading

from .engine import DATA_DIR

BOOKMARKS_PATH = os.path.join(DATA_DIR, "bookmarks.json")
_lock = threading.Lock()


def _load():
    try:
        with open(BOOKMARKS_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _save(data):
    os.makedirs(os.path.dirname(BOOKMARKS_PATH), exist_ok=True)
    with open(BOOKMARKS_PATH, "w") as f:
        json.dump(data, f, indent=2)


def get(user_key):
    with _lock:
        data = _load()
        return [t for t in (data.get(user_key) or []) if t]


def add(user_key, tech):
    tech = (tech or "").strip()
    if not tech:
        return get(user_key)
    with _lock:
        data = _load()
        cur = data.get(user_key) or []
        if tech.lower() not in [t.lower() for t in cur]:
            cur.append(tech)
        data[user_key] = cur
        _save(data)
        return cur


def remove(user_key, tech):
    with _lock:
        data = _load()
        cur = [t for t in (data.get(user_key) or []) if t.lower() != (tech or "").strip().lower()]
        data[user_key] = cur
        _save(data)
        return cur


def all_users():
    """All bookmarks across every user (for the notification monitor)."""
    with _lock:
        data = _load()
    return {k: [t for t in techs if t] for k, techs in data.items() if techs}
