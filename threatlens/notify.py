"""ThreatLens — webhook notifications.

Sends a Slack message (blocks) when advisories matching a user's bookmarked
technologies are found. Webhook URL from user settings or SLACK_WEBHOOK_URL env var.
"""

import requests

from . import settings

TIMEOUT = 10


def _webhook(user_key="default"):
    return settings.slack_webhook(user_key)


def is_configured(user_key="default"):
    return bool(_webhook(user_key))


def send_slack(text, blocks=None, user_key="default"):
    """Post to the Slack webhook. Returns True on success."""
    hook = _webhook(user_key)
    if not hook:
        return False
    payload = {"text": text}
    if blocks:
        payload["blocks"] = blocks
    try:
        r = requests.post(hook, json=payload, timeout=TIMEOUT)
        return r.status_code == 200
    except requests.RequestException:
        return False


def _advisory_block(a):
    sev_emoji = {"critical": "\U0001f534", "high": "\U0001f7e0", "medium": "\U0001f7e1",
                 "low": "\U0001f535", "none": "⚪"}.get(a.get("severity"), "⚪")
    url = a.get("url") or ""
    line = "%s *%s* — %s" % (sev_emoji, a.get("id"), a.get("title", "")[:120])
    if a.get("cvss"):
        line += "  (CVSS %s)" % a["cvss"]
    if url:
        line += "\n<%s|%s>" % (url, a.get("source", ""))
    return {"type": "section", "text": {"type": "mrkdwn", "text": line}}


def notify_matches(user_key, tech, advisories):
    """Notify about advisories matching one bookmarked tech."""
    blocks = [
        {"type": "section",
         "text": {"type": "mrkdwn",
                  "text": ":rotating_light: *ThreatLens* — new advisories matching your bookmark *%s*" % tech}},
    ]
    for a in advisories[:20]:
        blocks.append(_advisory_block(a))
    text = "ThreatLens: %d new advisory/advisories matching '%s'" % (len(advisories), tech)
    return send_slack(text, blocks, user_key=user_key)
