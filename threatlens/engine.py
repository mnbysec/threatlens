"""ThreatLens — aggregation engine.

Fetches advisories for a date from every source, dedupes, sorts by severity and
caches the result to `data/cache/<date>.json` so repeated views are instant
and survive restarts.
"""

import json
import os
import re
import time

from . import sources

DATA_DIR = os.environ.get("THREATLENS_DATA_DIR",
                          os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data"))
CACHE_DIR = os.path.join(DATA_DIR, "cache")

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}


def _cache_path(date):
    return os.path.join(CACHE_DIR, date + ".json")


def _sort_key(a):
    sev = SEV_ORDER.get(a.get("severity"), 4)
    cvss = a.get("cvss") or 0
    return (sev, -cvss, (a.get("id") or ""))


def get_feed(date, force=False):
    """Return a normalized feed for a date, using the disk cache when present."""
    path = _cache_path(date)
    if not force and os.path.isfile(path):
        try:
            with open(path) as f:
                feed = json.load(f)
                if "by_source" not in feed:
                    by_source = {}
                    for a in feed.get("advisories", []):
                        by_source[a.get("source", "?")] = by_source.get(a.get("source", "?"), 0) + 1
                    feed["by_source"] = by_source
                return feed
        except (OSError, ValueError):
            pass

    advisories = sources.fetch_all(date)
    seen = set()
    deduped = []
    for a in advisories:
        key = (a.get("id"), a.get("source"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(a)

    deduped.sort(key=_sort_key)

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "none": 0}
    by_source = {}
    for a in deduped:
        by_severity[a.get("severity", "none")] = by_severity.get(a.get("severity", "none"), 0) + 1
        by_source[a.get("source", "?")] = by_source.get(a.get("source", "?"), 0) + 1

    feed = {
        "date": date,
        "count": len(deduped),
        "sources": sorted({a["source"] for a in deduped}),
        "by_severity": by_severity,
        "by_source": by_source,
        "advisories": deduped,
        "fetched_at": time.time(),
    }

    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(path, "w") as f:
            json.dump(feed, f)
    except OSError:
        pass
    return feed


def match_bookmark(advisory, tech):
    """Case-insensitive matching of a bookmark against an advisory."""
    tech = (tech or "").strip().lower()
    if not tech:
        return False
    haystack = " ".join(filter(None, [
        advisory.get("id", ""),
        advisory.get("title", ""),
        advisory.get("summary", ""),
        " ".join(advisory.get("products", []) or []),
    ])).lower()
    tslug = re.sub(r"[^a-z0-9]", "", tech)
    return tech in haystack or (tslug and tslug in re.sub(r"[^a-z0-9]", "", haystack))


def match_all(advisories, bookmarks):
    """Return {tech: [advisory ids]} for advisories matching any bookmark."""
    result = {}
    for tech in bookmarks:
        hits = [a["id"] for a in advisories if match_bookmark(a, tech)]
        if hits:
            result[tech] = hits
    return result


def match_asset(advisory, asset_name):
    """Match an advisory against a single asset name (SBOM entry)."""
    return match_bookmark(advisory, asset_name)


def get_trend(days=7):
    """Return a list of {date, count} for the last N days from the disk cache."""
    import datetime
    trend = []
    for i in range(days - 1, -1, -1):
        d = (datetime.date.today() - datetime.timedelta(days=i)).isoformat()
        path = _cache_path(d)
        count = None
        if os.path.isfile(path):
            try:
                with open(path) as f:
                    count = json.load(f).get("count")
            except (OSError, ValueError):
                count = None
        trend.append({"date": d, "count": count})
    return trend
