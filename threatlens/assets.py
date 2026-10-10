"""ThreatLens — SBOM / asset inventory (multi-source).

Users keep MULTIPLE asset lists ("sources"): manual lists, uploaded SBOMs
(.txt/.csv/.xlsx/CycloneDX/SPDX), and API integrations (CrowdStrike, Splunk,
Defender XDR, Elastic Fleet, Wazuh, SentinelOne, Tenable.io, generic REST —
see providers.py) that are resynced on schedule.

Persistence: data/assets.json -> {user_key: {"sources": [source, ...]}}
"""

import csv
import io
import json
import os
import re
import threading
import time
import uuid

from .engine import DATA_DIR

ASSETS_PATH = os.path.join(DATA_DIR, "assets.json")
_lock = threading.Lock()

NAME_KEYS = ("name", "package", "component", "asset", "library", "product", "pkg", "dependency")
VERSION_KEYS = ("version", "software_version", "version_info", "build", "os_version")


def _split_name(value):
    """Return (clean_name, version_or_None) from a name string."""
    value = (value or "").strip()
    if not value:
        return None, None
    version = None
    value = re.sub(r"^pkg:[a-z]+/", "", value)
    m = re.search(r"@([\d][\w.\-+]*)$", value)
    if m:
        version = m.group(1)
        value = value[:m.start()]
    m = re.search(r"==([\d][\w.\-+]*)$", value)
    if m:
        version = m.group(1)
        value = value[:m.start()]
    m = re.search(r":([\d][\w.\-+]*)$", value)
    if m:
        version = m.group(1)
        value = value[:m.start()]
    value = value.split("/")[-1].split(":")[-1].strip()
    return (value or None), version


def _clean_name(name):
    n, _ = _split_name(name)
    return n


def _mk(name, version=None):
    return {"name": name, "version": version} if version else {"name": name}


def _parse_txt(data):
    assets = []
    for line in (data or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        n, v = _split_name(line)
        if n:
            assets.append(_mk(n, v))
    return assets


def _parse_csv(rows):
    assets = []
    if not rows:
        return assets
    header = [c.strip().lower() if c else "" for c in rows[0]]
    name_idx = version_idx = None
    for i, h in enumerate(header):
        if name_idx is None and h in NAME_KEYS:
            name_idx = i
        if version_idx is None and h in VERSION_KEYS:
            version_idx = i
    for row in rows[1:]:
        if not row:
            continue
        val = row[name_idx] if name_idx is not None and name_idx < len(row) else (row[0] if row else "")
        n, v = _split_name(val)
        if version_idx is not None and version_idx < len(row) and not v:
            v = (row[version_idx] or "").strip() or None
        if n:
            assets.append(_mk(n, v))
    return assets


def _parse_json(data):
    try:
        doc = json.loads(data)
    except (ValueError, TypeError):
        return []
    assets = []
    if isinstance(doc, list):
        for item in doc:
            if isinstance(item, str):
                n, v = _split_name(item)
                if n:
                    assets.append(_mk(n, v))
            elif isinstance(item, dict):
                n, v = _split_name(item.get("name") or item.get("package") or "")
                if not v:
                    v = item.get("version")
                if n:
                    assets.append(_mk(n, v))
        return assets
    if isinstance(doc, dict):
        comps = doc.get("components") or doc.get("packages") or doc.get("assets") or []
        for c in comps:
            if isinstance(c, str):
                n, v = _split_name(c)
            elif isinstance(c, dict):
                n, v = _split_name(c.get("name") or c.get("package") or c.get("component") or "")
                if not v:
                    v = c.get("version") or c.get("versionInfo")
            else:
                n, v = None, None
            if n:
                assets.append(_mk(n, v))
    return assets


def parse_sbom(data, filename=""):
    """Parse SBOM bytes into a normalized asset list. Never raises."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    name = (filename or "").lower()

    if name.endswith(".json"):
        assets = _parse_json(data.decode("utf-8", errors="replace"))
    elif name.endswith(".csv"):
        text = data.decode("utf-8", errors="replace")
        assets = _parse_csv(list(csv.reader(io.StringIO(text))))
    elif name.endswith((".xlsx", ".xlsm")):
        assets = _parse_xlsx(data)
    else:
        text = data.decode("utf-8", errors="replace").lstrip()
        assets = _parse_json(text) if text.startswith("{") else _parse_txt(text)
    return assets


def _parse_xlsx(data):
    try:
        import openpyxl
    except ImportError:
        return []
    try:
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True)
        ws = wb.active
        rows = [[("" if c.value is None else str(c.value)) for c in r] for r in ws.iter_rows()]
        wb.close()
    except Exception:
        return []
    return _parse_csv(rows)


# ---------------------------------------------------------------------------
# Per-user multi-source persistence
# ---------------------------------------------------------------------------

def _load():
    try:
        with open(ASSETS_PATH) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def _save(data):
    os.makedirs(os.path.dirname(ASSETS_PATH), exist_ok=True)
    with open(ASSETS_PATH, "w") as f:
        json.dump(data, f, indent=2)


def _normalize_user(entry):
    if isinstance(entry, dict) and "sources" in entry:
        return entry
    legacy = entry if isinstance(entry, list) else []
    src = {
        "id": "legacy-" + uuid.uuid4().hex[:8],
        "name": "My assets",
        "type": "manual",
        "provider": "",
        "assets": legacy,
        "config": {},
        "updated_at": time.time(),
        "status": "ok",
        "last_error": "",
    }
    return {"sources": [src]}


def get_sources(user_key):
    with _lock:
        entry = _load().get(user_key)
        if entry is None:
            return []
        entry = _normalize_user(entry)
        return entry.get("sources", [])


def get(user_key):
    """Effective merged asset list (for feed matching)."""
    seen = set()
    out = []
    for src in get_sources(user_key):
        for a in src.get("assets", []) or []:
            n = (a.get("name") or "").strip().lower()
            if n and n not in seen:
                seen.add(n)
                out.append(a)
    return out


def add_source(user_key, source):
    source = dict(source)
    source.setdefault("id", uuid.uuid4().hex[:10])
    source.setdefault("name", "Asset list")
    source.setdefault("type", "manual")
    source.setdefault("provider", "")
    source.setdefault("assets", [])
    source.setdefault("config", {})
    source.setdefault("updated_at", time.time())
    source.setdefault("status", "ok")
    source.setdefault("last_error", "")
    with _lock:
        data = _load()
        entry = _normalize_user(data.get(user_key, []))
        entry.setdefault("sources", []).append(source)
        data[user_key] = entry
        _save(data)
    return get_sources(user_key)


def remove_source(user_key, source_id):
    with _lock:
        data = _load()
        entry = _normalize_user(data.get(user_key, []))
        entry["sources"] = [s for s in entry.get("sources", []) if s.get("id") != source_id]
        data[user_key] = entry
        _save(data)
    return get_sources(user_key)


def update_source(user_key, source_id, **kw):
    with _lock:
        data = _load()
        entry = _normalize_user(data.get(user_key, []))
        for s in entry.get("sources", []):
            if s.get("id") == source_id:
                for k, v in kw.items():
                    s[k] = v
                s["updated_at"] = time.time()
                break
        data[user_key] = entry
        _save(data)
    return get_sources(user_key)


def set_source_assets(user_key, source_id, assets, status="ok", last_error=""):
    return update_source(user_key, source_id, assets=assets, status=status,
                         last_error=last_error or "")


def all_users():
    """All users' entries (for the scheduler)."""
    with _lock:
        return dict(_load())


# ---------------------------------------------------------------------------
# API resync
# ---------------------------------------------------------------------------

def resync_source(user_key, source_id):
    """Resync a single api-type source now. Returns the updated source dict."""
    from . import providers
    src = next((s for s in get_sources(user_key) if s.get("id") == source_id), None)
    if not src:
        return None
    if src.get("type") != "api":
        return src
    assets, err = providers.fetch_api_assets(src.get("config") or {})
    if err:
        set_source_assets(user_key, source_id, src.get("assets", []), status="error", last_error=err)
    else:
        set_source_assets(user_key, source_id, assets, status="ok", last_error="")
    return next((s for s in get_sources(user_key) if s.get("id") == source_id), src)


def resync_all_api():
    """Resync every api-type source across all users (called by the scheduler)."""
    from . import providers
    data = all_users()
    for user_key, entry in data.items():
        entry = _normalize_user(entry)
        for src in entry.get("sources", []):
            if src.get("type") != "api":
                continue
            assets, err = providers.fetch_api_assets(src.get("config") or {})
            set_source_assets(user_key, src["id"], assets,
                              status="ok" if not err else "error",
                              last_error=err or "")
