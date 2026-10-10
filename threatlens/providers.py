"""ThreatLens — asset-provider API connectors.

Pulls an asset inventory from a third-party API using a user-provided config,
then normalizes it to [{"name", "version"}] for advisory matching.

Supported providers:
  * crowdstrike  — CrowdStrike Falcon OAuth2
  * splunk       — Splunk REST API (splunkd)
  * defender     — Microsoft Defender XDR (Entra ID)
  * elastic      — Elastic Fleet (Kibana)
  * wazuh        — Wazuh manager API
  * sentinelone  — SentinelOne console API
  * tenable      — Tenable.io
  * generic      — plain Bearer-token GET
"""

import re
import time
from ipaddress import ip_address
from urllib.parse import urlparse

import requests

TIMEOUT = 10
UA = "ThreatLens/1.0 (asset-inventory-sync)"
MAX_PAGES = 10

DEFAULT_SPLUNK_SEARCH = "search index=* earliest=-24h | stats count by host"

NAME_KEYS = ("name", "software", "product", "asset", "package", "hostname",
             "title", "id", "name_cpe", "host", "computername",
             "computerdnsname")
VERSION_KEYS = ("version", "software_version", "version_info", "os_version",
                "build", "firmware_version", "os")

PROVIDER_LABELS = {
    "crowdstrike": "CrowdStrike Falcon",
    "splunk": "Splunk",
    "defender": "Microsoft Defender XDR",
    "elastic": "Elastic Fleet",
    "wazuh": "Wazuh",
    "sentinelone": "SentinelOne",
    "tenable": "Tenable.io",
    "generic": "Generic HTTP API",
}

METADATA_IPS = {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}
METADATA_HOSTS = {"metadata", "metadata.google.internal",
                  "metadata.google.internal."}


class _FetchError(RuntimeError):
    pass


def _is_metadata_url(url):
    """Block cloud metadata endpoints (SSRF guard)."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if host in METADATA_HOSTS:
            return True
        try:
            addr = ip_address(host)
            if str(addr) in METADATA_IPS or addr.is_link_local:
                return True
        except ValueError:
            pass
    except Exception:
        pass
    return False


def _verify(config, default=True):
    v = config.get("verify_tls")
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() not in ("0", "false", "no", "off", "")


def _req(method, url, headers=None, data=None, params=None, auth=None,
         verify=True):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        h.update(headers)
    try:
        r = requests.request(method, url, headers=h, data=data, params=params,
                             auth=auth, timeout=TIMEOUT, verify=verify)
    except requests.exceptions.SSLError:
        raise _FetchError(
            "TLS verification failed — the server cert is not trusted "
            "(self-signed?). Disable verify_tls for this source and retry.")
    except requests.exceptions.RequestException as e:
        raise _FetchError("request failed: %s" % e)
    if r.status_code == 401:
        raise _FetchError("HTTP 401 — bad credentials or expired token")
    if r.status_code == 403:
        raise _FetchError("HTTP 403 — credentials lack permission for this API")
    if r.status_code == 404:
        raise _FetchError("HTTP 404 — endpoint not found (check the base URL)")
    if r.status_code >= 400:
        raise _FetchError("HTTP %s — %s" % (r.status_code, r.text[:200]))
    return r


def _json(r):
    try:
        return r.json()
    except ValueError:
        raise _FetchError("non-JSON response")


def _navigate(data, path):
    if not path:
        return data
    cur = data
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur


def _split(value):
    value = (value or "").strip()
    m = re.search(r"@([\d][\w.\-+]*)$", value)
    if m:
        return value[:m.start()].strip(), m.group(1)
    return value, None


def _flat(value):
    if isinstance(value, dict):
        name = value.get("name") or value.get("platform") or ""
        ver = value.get("version") or ""
        combined = ("%s %s" % (name, ver)).strip()
        return combined or None
    if isinstance(value, list):
        for v in value:
            if isinstance(v, str) and v.strip():
                return v.strip()
        return None
    return value


def _extract_assets(data, assets_path="", name_keys=NAME_KEYS,
                    version_keys=VERSION_KEYS):
    items = _navigate(data, assets_path) if assets_path else data
    if isinstance(items, dict):
        pool = [items]
        for v in items.values():
            if isinstance(v, dict):
                pool.append(v)
        for obj in pool:
            lowered = {str(k).lower(): v for k, v in obj.items()}
            for key in ("resources", "items", "data", "assets", "results",
                        "entries", "value", "affected_items"):
                if isinstance(lowered.get(key), list):
                    items = lowered[key]
                    break
            if isinstance(items, list):
                break
    if not isinstance(items, list):
        return [], "response does not contain a list of assets (check the assets field path)"

    assets = []
    for item in items:
        if isinstance(item, str):
            name, version = _split(item)
        elif isinstance(item, dict):
            lowered = {str(k).lower(): v for k, v in item.items()}
            name = None
            for k in name_keys:
                v = lowered.get(k.lower())
                v = _flat(v) if k == "os" else v
                if v:
                    name = v
                    break
            version = None
            for k in version_keys:
                v = _flat(lowered.get(k.lower()))
                if v:
                    version = v
                    break
        else:
            continue
        if not name:
            continue
        name, v2 = _split(str(name))
        version = version or v2
        assets.append({"name": name, "version": (str(version) if version else None)})
    return assets, None


def _fetch_custom_endpoint(config, extra_headers=None):
    base = (config.get("base_url") or "").rstrip("/")
    endpoint = config.get("endpoint") or ""
    url = (endpoint if endpoint.startswith("http")
           else (base + (endpoint if endpoint.startswith("/") else "/" + endpoint)))
    if not url or url == base:
        return [], "no endpoint configured"
    if _is_metadata_url(url):
        return [], "endpoint host is not allowed (cloud metadata)"
    headers = dict(extra_headers or {})
    try:
        r = _req("GET", url, headers=headers,
                 verify=_verify(config, default=True))
        data = _json(r)
    except _FetchError as e:
        return [], str(e)
    return _extract_assets(data, config.get("assets_path") or "")


def _crowdstrike_token(config):
    base = (config.get("base_url") or "https://api.crowdstrike.com").rstrip("/")
    token_url = config.get("token_endpoint") or (base + "/oauth2/token")
    client_id = config.get("client_id", "")
    client_secret = config.get("client_secret", "")
    if not client_id or not client_secret:
        raise _FetchError("CrowdStrike requires a client ID and client secret")
    r = _req("POST", token_url, data={
        "client_id": client_id, "client_secret": client_secret,
        "grant_type": "client_credentials"})
    tok = _json(r)
    access = tok.get("access_token")
    if not access:
        raise _FetchError("CrowdStrike token response has no access_token")
    return access


def _fetch_crowdstrike(config):
    try:
        token = _crowdstrike_token(config)
    except _FetchError as e:
        return [], str(e)
    return _fetch_custom_endpoint(config, {"Authorization": "Bearer " + token})


def _fetch_generic(config):
    headers = {}
    key = config.get("api_key") or config.get("token")
    if key:
        headers["Authorization"] = "Bearer " + key
    return _fetch_custom_endpoint(config, headers)


def _fetch_splunk(config):
    base = (config.get("base_url") or "").rstrip("/")
    if not base:
        return [], "Splunk requires the splunkd base URL (e.g. https://splunk:8089)"
    token = config.get("api_key") or config.get("token") or ""
    if not token:
        return [], "Splunk requires an authentication token"
    verify = _verify(config, default=False)
    search = (config.get("search") or DEFAULT_SPLUNK_SEARCH).strip()
    if not search.startswith(("search ", "search\t", "|")):
        search = "search " + search
    headers = {"Authorization": "Bearer " + token}
    try:
        r = _req("POST", base + "/services/search/jobs",
                 headers=headers, data={"search": search}, verify=verify)
        m = re.search(r"<sid>(.*?)</sid>", r.text)
        if not m:
            return [], "Splunk did not return a search job id"
        sid = m.group(1)
        job_url = base + "/services/search/jobs/" + sid
        deadline = time.time() + 50
        while True:
            jr = _req("GET", job_url, headers=headers, verify=verify)
            dm = re.search(r'name="dispatchState"[^>]*>([^<]+)<', jr.text)
            state = (dm.group(1).strip().upper() if dm else "")
            if state == "DONE":
                break
            if state in ("FAILED", "ERROR"):
                return [], "Splunk search job failed"
            if time.time() > deadline:
                return [], ("Splunk search still running after 50s — "
                             "narrow the time range and retry")
            time.sleep(2)
        rr = _req("GET", job_url + "/results",
                  headers=headers,
                  params={"output_mode": "json", "count": "0"},
                  verify=verify)
        data = _json(rr)
    except _FetchError as e:
        return [], str(e)
    return _extract_assets(data.get("results", data), "",
                           name_keys=("host", "name", "hostname"),
                           version_keys=("os", "version"))


def _fetch_defender(config):
    tenant = (config.get("tenant_id") or "").strip()
    client_id = (config.get("client_id") or "").strip()
    client_secret = (config.get("client_secret") or "")
    if not tenant or not client_id or not client_secret:
        return [], "Defender requires a tenant ID, client ID and client secret"
    base = (config.get("base_url") or "https://api.security.microsoft.com").rstrip("/")
    verify = _verify(config, default=True)
    try:
        tr = _req("POST",
                  "https://login.microsoftonline.com/%s/oauth2/v2.0/token" % tenant,
                  data={"client_id": client_id,
                        "client_secret": client_secret,
                        "scope": "https://api.security.microsoft.com/.default",
                        "grant_type": "client_credentials"},
                  verify=verify)
        tok = _json(tr)
        access = tok.get("access_token")
        if not access:
            return [], "Entra token response has no access_token"
        headers = {"Authorization": "Bearer " + access}
        assets = []
        url = base + "/api/machines"
        params = {"$top": "500"}
        for _ in range(5):
            mr = _req("GET", url, headers=headers, params=params,
                      verify=verify)
            data = _json(mr)
            for m in data.get("value", []) or []:
                name = m.get("computerDnsName") or m.get("id")
                if not name:
                    continue
                ver = " ".join(x for x in
                               (m.get("osPlatform"), m.get("version")) if x).strip()
                assets.append({"name": str(name),
                               "version": ver or None})
            nxt = data.get("@odata.nextLink")
            if not nxt:
                break
            url, params = nxt, None
    except _FetchError as e:
        return [], str(e)
    return assets, None


def _fetch_elastic(config):
    base = (config.get("base_url") or "").rstrip("/")
    if not base:
        return [], "Elastic requires the Kibana base URL"
    key = config.get("api_key") or config.get("token") or ""
    if not key:
        return [], "Elastic requires an API key (fleet-agents-read privilege)"
    verify = _verify(config, default=True)
    headers = {"Authorization": "ApiKey " + key, "kbn-xsrf": "xx"}
    endpoint = config.get("endpoint") or "/api/fleet/agents"
    url = endpoint if endpoint.startswith("http") else base + endpoint
    try:
        assets = []
        page = 1
        for _ in range(MAX_PAGES):
            r = _req("GET", url, headers=headers,
                     params={"page": page, "perPage": "100"}, verify=verify)
            data = _json(r)
            items = data.get("items", []) or []
            for it in items:
                meta = it.get("local_metadata") or {}
                host = (meta.get("host") or {}).get("hostname")
                name = host or it.get("hostname") or it.get("id")
                if not name:
                    continue
                elastic = meta.get("elastic") or {}
                agent = elastic.get("agent") or {}
                ver = agent.get("version") or it.get("version")
                assets.append({"name": str(name),
                               "version": (str(ver) if ver else None)})
            total = data.get("total", len(items))
            if page * 100 >= (total or 0) or not items:
                break
            page += 1
    except _FetchError as e:
        return [], str(e)
    if not assets:
        return [], "no Fleet agents returned (check the API key privileges)"
    return assets, None


def _fetch_wazuh(config):
    base = (config.get("base_url") or "").rstrip("/")
    if not base:
        return [], "Wazuh requires the manager API base URL (e.g. https://wazuh:55000)"
    username = config.get("username") or config.get("client_id") or ""
    password = config.get("password") or config.get("client_secret") or ""
    if not username or not password:
        return [], "Wazuh requires an API username and password"
    verify = _verify(config, default=False)
    try:
        lr = _req("POST", base + "/security/user/authenticate",
                  auth=(username, password), verify=verify)
        tok = _json(lr).get("data", {}).get("token")
        if not tok:
            return [], "Wazuh login did not return a token"
        ar = _req("GET", base + "/agents", headers={"Authorization": "Bearer " + tok},
                  params={"limit": "500", "select": "name,version,os"},
                  verify=verify)
        items = _json(ar).get("data", {}).get("affected_items", []) or []
        assets = []
        for a in items:
            name = a.get("name")
            if not name or name == "wazuh-master":
                continue
            osv = (a.get("os") or {})
            ver = " ".join(x for x in
                           (osv.get("name"), osv.get("version")) if x).strip()
            assets.append({"name": str(name), "version": ver or None})
    except _FetchError as e:
        return [], str(e)
    return assets, None


def _fetch_sentinelone(config):
    base = (config.get("base_url") or "").rstrip("/")
    if not base:
        return [], "SentinelOne requires the console URL (e.g. https://usea1.sentinelone.net)"
    token = config.get("api_key") or config.get("token") or ""
    if not token:
        return [], "SentinelOne requires an API token"
    verify = _verify(config, default=True)
    headers = {"Authorization": "ApiToken " + token}
    try:
        assets = []
        cursor = None
        for _ in range(MAX_PAGES):
            params = {"limit": "100"}
            if cursor:
                params["cursor"] = cursor
            r = _req("GET", base + "/web/api/v2.1/agents", headers=headers,
                     params=params, verify=verify)
            data = _json(r)
            for a in data.get("data", []) or []:
                name = a.get("computerName") or a.get("uuid")
                if not name:
                    continue
                ver = " ".join(x for x in
                               (a.get("osName"), a.get("osRevision")) if x).strip()
                assets.append({"name": str(name), "version": ver or None})
            cursor = (data.get("pagination") or {}).get("nextCursor")
            if not cursor:
                break
    except _FetchError as e:
        return [], str(e)
    return assets, None


def _fetch_tenable(config):
    base = (config.get("base_url") or "https://cloud.tenable.com").rstrip("/")
    access = config.get("access_key") or config.get("client_id") or ""
    secret = config.get("secret_key") or config.get("client_secret") or ""
    if not access or not secret:
        return [], "Tenable.io requires an access key and a secret key"
    verify = _verify(config, default=True)
    headers = {"X-ApiKeys": "accessKey=%s;secretKey=%s" % (access, secret)}
    try:
        assets = []
        offset = 0
        for _ in range(MAX_PAGES):
            r = _req("GET", base + "/assets", headers=headers,
                     params={"limit": "200", "offset": str(offset)},
                     verify=verify)
            data = _json(r)
            items = data.get("assets", []) or []
            for a in items:
                fqdns = a.get("fqdns") or []
                name = a.get("hostname") or (fqdns[0] if fqdns else None)
                if not name:
                    continue
                ops = a.get("operating_systems") or []
                assets.append({"name": str(name),
                               "version": (str(ops[0]) if ops else None)})
            pg = data.get("pagination") or {}
            total = pg.get("total", len(items))
            offset += len(items)
            if not items or offset >= (total or 0):
                break
    except _FetchError as e:
        return [], str(e)
    return assets, None


_FETCHERS = {
    "crowdstrike": _fetch_crowdstrike,
    "generic": _fetch_generic,
    "splunk": _fetch_splunk,
    "defender": _fetch_defender,
    "elastic": _fetch_elastic,
    "wazuh": _fetch_wazuh,
    "sentinelone": _fetch_sentinelone,
    "tenable": _fetch_tenable,
}


def fetch_api_assets(config):
    """Return (assets, error). Never raises."""
    config = config or {}
    provider = (config.get("provider") or "generic").lower()
    fn = _FETCHERS.get(provider)
    if fn is None:
        return [], "unknown provider '%s'" % provider
    try:
        return fn(config)
    except Exception as e:
        return [], "sync failed: %s" % e
