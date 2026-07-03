"""HTTP helpers."""

from urllib.parse import urlparse

import requests


def normalize_target_url(raw):
    if not urlparse(raw).scheme:
        raw = "https://" + raw
    return raw.rstrip("/") + "/"


def make_session(user_agent, insecure=False):
    session = requests.Session()
    session.headers["User-Agent"] = user_agent
    session.verify = not insecure
    return session
