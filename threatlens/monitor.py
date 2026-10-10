"""ThreatLens — notification monitor.

A background scheduler that periodically fetches the latest advisories, matches
them against every user's bookmarks, and sends a Slack webhook for NEW matches.
"""

import json
import os
import threading
import time

from . import assets, bookmarks, engine, notify
from .engine import DATA_DIR

NOTIFIED_PATH = os.path.join(DATA_DIR, "notified.json")
RESYNC_PATH = os.path.join(DATA_DIR, "last_resync.txt")

INTERVAL_SECS = 3600

_state = {"running": False, "last_run": None, "last_sent": 0,
          "last_resync": None, "error": None}
_lock = threading.Lock()
_thread = None


def _daily_resync():
    import datetime
    today = datetime.date.today().isoformat()
    try:
        with open(RESYNC_PATH) as f:
            last = f.read().strip()
    except OSError:
        last = ""
    if last == today:
        return
    try:
        assets.resync_all_api()
        os.makedirs(os.path.dirname(RESYNC_PATH), exist_ok=True)
        with open(RESYNC_PATH, "w") as f:
            f.write(today)
        with _lock:
            _state["last_resync"] = today
    except Exception as e:
        with _lock:
            _state["error"] = "resync: %s" % e


def _load_notified():
    try:
        with open(NOTIFIED_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _save_notified(data):
    os.makedirs(os.path.dirname(NOTIFIED_PATH), exist_ok=True)
    with open(NOTIFIED_PATH, "w") as f:
        json.dump(data, f)


def check_once():
    """Fetch today's feed, match bookmarks, notify new matches."""
    import datetime
    today = datetime.date.today()
    dates = [today.isoformat()]
    try:
        yesterday = today - datetime.timedelta(days=1)
        dates.append(yesterday.isoformat())
    except Exception:
        pass

    advisories = []
    for d in dates:
        try:
            advisories.extend(engine.get_feed(d).get("advisories", []))
        except Exception:
            continue

    users = bookmarks.all_users()
    notified = _load_notified()
    sent = 0
    for user_key, techs in users.items():
        if not notify.is_configured(user_key):
            continue
        for tech in techs:
            hits = [a for a in advisories if engine.match_bookmark(a, tech)]
            new_hits = []
            for a in hits:
                key = "%s|%s" % (tech.lower(), a.get("id"))
                if key not in notified:
                    new_hits.append(a)
                    notified[key] = time.time()
            if new_hits:
                try:
                    notify.notify_matches(user_key, tech, new_hits)
                    sent += 1
                except Exception:
                    pass
    if sent:
        _save_notified(notified)

    with _lock:
        _state["last_run"] = time.time()
        _state["last_sent"] = sent
    return {"ok": True, "sent": sent}


def _loop():
    while _state["running"]:
        try:
            check_once()
        except Exception as e:
            with _lock:
                _state["error"] = str(e)
        try:
            _daily_resync()
        except Exception as e:
            with _lock:
                _state["error"] = "resync: %s" % e
        time.sleep(INTERVAL_SECS)


def start_scheduler(interval=INTERVAL_SECS):
    global _thread, INTERVAL_SECS
    INTERVAL_SECS = interval
    with _lock:
        if _state["running"]:
            return _thread
        _state["running"] = True
    _thread = threading.Thread(target=_loop, name="threatlens-monitor", daemon=True)
    _thread.start()
    return _thread


def status():
    with _lock:
        return dict(_state)
