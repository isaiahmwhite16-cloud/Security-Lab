#!/usr/bin/env python3
"""
Step 1: Pull recent IOCs from ThreatFox and print them.
No MISP interaction yet — just confirming the abuse.ch API call works.
"""

import os
import json
import requests
from dotenv import load_dotenv

# Load ABUSECH_AUTH_KEY, MISP_URL, MISP_API_KEY from .env
load_dotenv()

AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY")

if not AUTH_KEY:
    raise SystemExit("ABUSECH_AUTH_KEY not found — check your .env file")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

def fetch_recent_iocs(days=1):
    """Query ThreatFox for IOCs first seen in the last `days` days (max 7)."""
    headers = {"Auth-Key": AUTH_KEY}
    payload = {"query": "get_iocs", "days": days}

    response = requests.post(THREATFOX_URL, headers=headers, json=payload, timeout=30)
    response.raise_for_status()  # blow up loudly if the request failed

    result = response.json()

    if result.get("query_status") != "ok":
        raise SystemExit(f"ThreatFox API returned an error: {result}")

    return result.get("data", [])


if __name__ == "__main__":
    iocs = fetch_recent_iocs(days=1)
    print(f"Fetched {len(iocs)} IOCs from the last 1 day.\n")

    # Print the first 5 as a sanity check — don't dump hundreds to the terminal
    for ioc in iocs[:5]:
        print(json.dumps(ioc, indent=2))
        print("-" * 40)