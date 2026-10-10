<p align="center">
  <img src="https://raw.githubusercontent.com/mnbysec/threatlens/main/screenshot.png" alt="ThreatLens" width="800" />
</p>

<h1 align="center">ThreatLens</h1>

<p align="center">
  <strong>Open-source vulnerability & advisory intelligence — one feed, every major source.</strong>
  <br />
  <em>From the security platform at <a href="https://ylbsecurity.com">ylbsecurity.com</a></em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="#features">Features</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#api">API Reference</a> ·
  <a href="https://ylbsecurity.com">YLB Security Platform</a>
</p>

---

ThreatLens is the advisory intelligence module from [YLB Security](https://ylbsecurity.com), extracted and open-sourced so anyone can run it. It aggregates CVEs and security advisories from NVD, CISA KEV, GitHub Security Advisories and Ubuntu USN into a single date-filtered, severity-ranked feed. Bookmark your tech stack, connect your Slack, and get notified the moment a new advisory hits something you run.

The full [YLB Security platform](https://ylbsecurity.com) includes additional tools — domain impersonation scanning, LLM/MCP pentesting, AI governance compliance — built for security teams that need more than just advisory tracking. ThreatLens is the piece we thought everyone should have access to.

> If you find ThreatLens useful, give it a ⭐ — it helps other security teams discover it.
>
> Questions, feedback, or want to talk about the full platform? Reach us at **hello@ylbsecurity.com**

## Features

- **4 advisory sources** — NVD, CISA KEV, GitHub, Ubuntu, fetched in parallel
- **Date picker** — browse any day's disclosures, cached to disk
- **Severity ranking** — critical → high → medium → low → unrated, with CVSS scores
- **Tech-stack bookmarks** — bookmark technologies, get Slack alerts when they're hit
- **Slack integration** — configure your webhook URL right from the UI (or via env var), test it with one click
- **SBOM import** — upload .txt, .csv, .xlsx, CycloneDX or SPDX JSON to match against the feed
- **8 asset-provider integrations** — CrowdStrike, Splunk, Defender XDR, Elastic Fleet, Wazuh, SentinelOne, Tenable.io, generic REST API
- **Security news** — aggregated from Hacker News, The Hacker News, BleepingComputer, Krebs on Security
- **7-day trend chart** — see disclosure volume over time
- **Zero dependencies** — no database, no Redis, no external services required. Everything persists to JSON files in a `data/` folder
- **Self-hosted** — runs on your own infra, your data stays with you

## Quick Start

### Option 1: Python

```bash
git clone https://github.com/mnbysec/threatlens.git
cd threatlens
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open http://localhost:8080

### Option 2: Docker Compose

```bash
git clone https://github.com/mnbysec/threatlens.git
cd threatlens
cp .env.example .env
docker compose up -d
```

Open http://localhost:8080

### Option 3: Docker (no clone needed)

```bash
docker run -p 8080:8080 -v threatlens-data:/app/data ghcr.io/mnbysec/threatlens
```

That's it. No database to configure, no accounts to create. Open the browser and start using it.

## Configuration

Copy `.env.example` to `.env` and edit as needed. Everything is optional — ThreatLens works out of the box with zero config.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `SECRET_KEY` | dev key | Flask secret (change in production) |
| `NVD_API_KEY` | none | Free NVD API key — increases rate limit from 5 to 50 req/30s. [Get one here](https://nvd.nist.gov/developers/request-an-api-key) |
| `SLACK_WEBHOOK_URL` | none | Default Slack webhook (can also be configured per-user in the UI) |
| `THREATLENS_DATA_DIR` | `./data` | Where cached feeds, bookmarks, settings and assets are stored |

### Slack Notifications

You can configure Slack in two ways:
1. **Via the UI** — open ThreatLens, scroll to Settings, paste your webhook URL and click Save
2. **Via env var** — set `SLACK_WEBHOOK_URL` in your `.env` file (the UI setting takes priority)

The background monitor checks every hour. When a new advisory matches one of your bookmarked technologies, you'll get a Slack message with the CVE ID, severity, and link.

## API

All endpoints are under `/api/`. No authentication by default — this is a self-hosted tool. Add a `Bearer` token header to scope data per API key if you want multi-user separation.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/feed?date=YYYY-MM-DD&refresh=1` | Advisory feed for a date |
| GET | `/api/stats` | 7-day trend + severity/source breakdown |
| GET | `/api/news` | Security news aggregation |
| GET | `/api/bookmarks` | List bookmarked technologies |
| POST | `/api/bookmarks` | Add a bookmark `{"tech": "nginx"}` |
| DELETE | `/api/bookmarks` | Remove a bookmark `{"tech": "nginx"}` |
| GET | `/api/settings` | Get current settings (Slack webhook) |
| POST | `/api/settings` | Update settings `{"slack_webhook": "https://hooks.slack.com/..."}` |
| GET | `/api/assets` | List asset sources + effective assets |
| POST | `/api/assets` | Upload SBOM (multipart file), manual list, or API source |
| POST | `/api/assets/<id>/resync` | Resync an API asset source |
| DELETE | `/api/assets/<id>` | Remove an asset source |
| POST | `/api/test-webhook` | Send a Slack test notification |
| GET | `/api/status` | Monitor scheduler status |

## Asset Provider Setup

ThreatLens can pull your asset inventory from 8 providers and match it against the advisory feed automatically. API sources resync once per day, or hit "sync" in the UI to resync immediately.

| Provider | Auth | What it pulls |
|----------|------|---------------|
| **CrowdStrike Falcon** | OAuth2 (client ID + secret) | Hosts from a configurable endpoint |
| **Splunk** | Bearer token | Hosts from an SPL search |
| **Microsoft Defender XDR** | Entra ID (tenant + client ID + secret) | Machines via `/api/machines` |
| **Elastic Fleet** | API key | Fleet agents via Kibana |
| **Wazuh** | Username + password | Agents via manager API |
| **SentinelOne** | API token | Agents via console API |
| **Tenable.io** | Access key + secret key | Assets via Tenable API |
| **Generic** | Bearer token (optional) | Any JSON endpoint — bring your own CMDB |

## How Data is Stored

Everything lives in the `data/` folder. No database, no external services. Back up this one folder and you're covered.

```
data/
  ├── cache/          # Advisory feeds cached by date (one JSON per day)
  ├── bookmarks.json  # Your bookmarked technologies
  ├── assets.json     # Asset sources + inventories (SBOM, API providers)
  ├── settings.json   # User settings (Slack webhook URL)
  ├── notified.json   # Dedup tracker — prevents duplicate Slack alerts
  └── last_resync.txt # Daily API resync marker
```

With Docker, the `data/` folder is a volume mount, so everything persists across container restarts and upgrades.

## Architecture

```
Browser → Flask app (port 8080)
           ├── /api/feed       → Advisory engine (NVD, CISA KEV, GitHub, Ubuntu)
           ├── /api/news       → News aggregation (HN + 3 RSS feeds)
           ├── /api/bookmarks  → Per-user tech bookmarks
           ├── /api/settings   → Per-user Slack webhook config
           ├── /api/assets     → SBOM + 8 provider integrations
           └── Background monitor
                 ├── Hourly: fetch feed → match bookmarks → Slack alert
                 └── Daily: resync API asset providers
```

## Contributing

Contributions are welcome. Open an issue or submit a PR.

If you're using ThreatLens in your security workflow, we'd love to hear about it — drop us a line at **hello@ylbsecurity.com**.

## License

MIT — see [LICENSE](LICENSE).

## About

ThreatLens is built and maintained by [YLB Security](https://ylbsecurity.com).

YLB Security is a security platform with tools for domain impersonation detection, LLM/MCP pentesting, advisory intelligence, and AI governance compliance. ThreatLens is one of those tools — open-sourced for the community.

[Visit ylbsecurity.com](https://ylbsecurity.com) to see the full platform.
