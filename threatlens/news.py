"""ThreatLens — cyber-news aggregation.

Fetches recent security news from Hacker News (Algolia API) and a few RSS feeds
(The Hacker News, BleepingComputer, Krebs). Each source fails soft; results are
deduped and sorted newest-first.
"""

import threading
import xml.etree.ElementTree as ET

import requests

UA = "ThreatLens/1.0 (news-aggregation)"
TIMEOUT = 12

RSS_FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
]


def _get(url, params=None):
    r = requests.get(url, params=params, headers={"User-Agent": UA}, timeout=TIMEOUT)
    r.raise_for_status()
    return r


def _fetch_hn():
    out = []
    try:
        r = _get("https://hn.algolia.com/api/v1/search_by_date", {
            "query": "security OR vulnerability OR breach OR hack OR ransomware OR exploit OR malware",
            "tags": "story",
            "hitsPerPage": 25,
        })
        for h in r.json().get("hits", []) or []:
            title = h.get("title") or h.get("story_title")
            url = h.get("url") or h.get("story_url")
            if not title:
                continue
            out.append({
                "title": title,
                "url": url or ("https://news.ycombinator.com/item?id=%s" % h.get("objectID")),
                "source": "Hacker News",
                "published": h.get("created_at", ""),
                "points": h.get("points") or 0,
            })
    except (requests.RequestException, ValueError):
        pass
    return out


def _fetch_rss(name, feed_url):
    out = []
    try:
        r = _get(feed_url)
        root = ET.fromstring(r.content)
        for item in root.iter("item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or item.findtext("published") or "").strip()
            if not title:
                continue
            out.append({
                "title": title,
                "url": link,
                "source": name,
                "published": pub,
                "points": 0,
            })
    except Exception:
        pass
    return out


def fetch_news():
    """Return a merged, deduped list of recent cyber news items."""
    results = {}
    lock = threading.Lock()

    def _run(fn, *args):
        try:
            items = fn(*args)
        except Exception:
            items = []
        with lock:
            for it in items:
                key = it["title"].lower()[:120]
                if key not in results:
                    results[key] = it

    threads = [threading.Thread(target=_run, args=(_fetch_hn,))] + \
              [threading.Thread(target=_run, args=(_fetch_rss, n, u)) for n, u in RSS_FEEDS]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    items = list(results.values())
    items.sort(key=lambda x: x.get("published", ""), reverse=True)
    return items[:40]
