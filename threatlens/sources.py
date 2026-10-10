"""ThreatLens — advisory source fetchers.

Each source fetches advisories published on a given date (YYYY-MM-DD) and
returns a list of normalized advisory dicts. Every source is independent and
fails soft: no key, rate-limited, or unreachable means it simply returns [].
"""

import os
import re
import threading

import requests

UA = "ThreatLens/1.0 (vulnerability-intelligence)"
TIMEOUT = 20


def _get(url, params=None, headers=None, timeout=TIMEOUT):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    r = requests.get(url, params=params, headers=h, timeout=timeout)
    r.raise_for_status()
    return r


def _cvss_band(score):
    if score is None:
        return None
    score = float(score)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _iso(date):
    return date + "T00:00:00.000"


def _day_after(date):
    from datetime import datetime, timedelta
    d = datetime.strptime(date, "%Y-%m-%d") + timedelta(days=1)
    return d.strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# NVD (primary CVE source, has CVSS scores)
# ---------------------------------------------------------------------------

def _nvd_cvss(metrics):
    if not metrics:
        return None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []) or []:
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            if score is not None:
                return float(score), data.get("vectorString")
    return None, None


def fetch_nvd(date):
    out = []
    try:
        params = {
            "pubStartDate": _iso(date),
            "pubEndDate": _iso(_day_after(date)),
            "resultsPerPage": 1000,
        }
        key = os.environ.get("NVD_API_KEY", "").strip()
        if key:
            params["apiKey"] = key
        r = _get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
        for v in r.json().get("vulnerabilities", []) or []:
            cve = v.get("cve", {})
            cid = cve.get("id", "")
            if not cid:
                continue
            score, vector = _nvd_cvss(cve.get("metrics"))
            desc = ""
            for d in cve.get("descriptions", []) or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            published = cve.get("published", "")[:10]
            out.append({
                "id": cid,
                "source": "NVD",
                "title": desc[:140],
                "summary": desc,
                "severity": _cvss_band(score) or "none",
                "cvss": score,
                "vector": vector,
                "published": published,
                "url": "https://nvd.nist.gov/vuln/detail/" + cid,
                "products": [],
                "exploited": False,
            })
    except requests.RequestException:
        pass
    except (ValueError, KeyError):
        pass
    return out


# ---------------------------------------------------------------------------
# CISA KEV (known exploited vulnerabilities)
# ---------------------------------------------------------------------------

def fetch_kev(date):
    out = []
    try:
        url = ("https://www.cisa.gov/sites/default/files/feeds/"
               "known_exploited_vulnerabilities.json")
        r = _get(url)
        for v in r.json().get("vulnerabilities", []) or []:
            if (v.get("dateAdded") or "")[:10] != date:
                continue
            cid = v.get("cveID", "")
            product = "%s %s" % (v.get("vendorProject", ""), v.get("product", ""))
            out.append({
                "id": cid or ("KEV-%s" % v.get("vulnerabilityName", "")),
                "source": "CISA KEV",
                "title": v.get("vulnerabilityName", "")[:140],
                "summary": v.get("requiredAction", ""),
                "severity": "high",
                "cvss": None,
                "vector": None,
                "published": v.get("dateAdded", ""),
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "products": [product.strip()],
                "exploited": True,
            })
    except requests.RequestException:
        pass
    except (ValueError, KeyError):
        pass
    return out


# ---------------------------------------------------------------------------
# GitHub Security Advisories
# ---------------------------------------------------------------------------

def _gh_sev(sev):
    m = {"critical": "critical", "high": "high", "moderate": "medium",
         "medium": "medium", "low": "low"}
    return m.get((sev or "").lower(), "none")


def fetch_github(date):
    out = []
    try:
        url = "https://api.github.com/advisories"
        params = {"published": date, "per_page": 100}
        r = _get(url, params=params, headers={"Accept": "application/vnd.github+json"})
        for a in r.json():
            if not isinstance(a, dict):
                continue
            products = []
            for vv in a.get("vulnerabilities", []) or []:
                pkg = vv.get("package") or {}
                if pkg.get("name"):
                    products.append("%s/%s" % (pkg.get("ecosystem", ""), pkg.get("name")))
            cve = a.get("cve_id")
            out.append({
                "id": cve or a.get("ghsa_id", ""),
                "source": "GitHub",
                "title": a.get("summary", "")[:140],
                "summary": a.get("summary", ""),
                "severity": _gh_sev(a.get("severity")),
                "cvss": None,
                "vector": None,
                "published": (a.get("published_at") or "")[:10],
                "url": a.get("html_url", ""),
                "products": products,
                "exploited": False,
            })
    except requests.RequestException:
        pass
    except (ValueError, KeyError):
        pass
    return out


# ---------------------------------------------------------------------------
# Ubuntu USN
# ---------------------------------------------------------------------------

def _ubuntu_sev(sev):
    m = {"critical": "critical", "high": "high", "medium": "medium",
         "low": "low", "negligible": "low"}
    return m.get((sev or "").lower(), "none")


def fetch_ubuntu(date):
    out = []
    try:
        r = _get("https://ubuntu.com/security/notices.json")
        for n in r.json().get("notices", []) or []:
            published = (n.get("published") or "")[:10]
            if published != date:
                continue
            cves = n.get("cves", []) or []
            cid = cves[0] if cves else n.get("id", "")
            out.append({
                "id": n.get("id", "") or cid,
                "source": "Ubuntu",
                "title": n.get("title", "")[:140],
                "summary": (n.get("summary") or "")[:400],
                "severity": _ubuntu_sev(n.get("severity")),
                "cvss": None,
                "vector": None,
                "published": published,
                "url": "https://ubuntu.com/security/notices/" + (n.get("id") or ""),
                "products": ["ubuntu/" + (n.get("title", "") or "")],
                "exploited": False,
            })
    except requests.RequestException:
        pass
    except (ValueError, KeyError):
        pass
    return out


SOURCES = [
    ("NVD", fetch_nvd),
    ("CISA KEV", fetch_kev),
    ("GitHub", fetch_github),
    ("Ubuntu", fetch_ubuntu),
]


def fetch_all(date):
    """Fetch every source in parallel. Returns a list of advisory dicts."""
    results = {}
    lock = threading.Lock()

    def _run(name, fn):
        try:
            data = fn(date)
        except Exception:
            data = []
        with lock:
            results[name] = data

    threads = [threading.Thread(target=_run, args=(n, f)) for n, f in SOURCES]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    merged = []
    for name, _ in SOURCES:
        merged.extend(results.get(name, []))
    return merged
