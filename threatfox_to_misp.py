#!/usr/bin/env python3
"""
Pull recent IOCs from ThreatFox and push them into MISP as a new event.
"""

import os
import sys
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymisp import PyMISP, MISPEvent

load_dotenv()

ABUSECH_AUTH_KEY = os.getenv("ABUSECH_AUTH_KEY")
MISP_URL = os.getenv("MISP_URL")
MISP_API_KEY = os.getenv("MISP_API_KEY")
MISP_VERIFY_SSL = os.getenv("MISP_VERIFY_SSL", "True").lower() == "true"

if not all([ABUSECH_AUTH_KEY, MISP_URL, MISP_API_KEY]):
    raise SystemExit("Missing one of ABUSECH_AUTH_KEY / MISP_URL / MISP_API_KEY in .env")

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"

# Maps ThreatFox's ioc_type values to MISP's expected attribute type strings.
# ThreatFox has more granular types than this; expand as you encounter new ones.
IOC_TYPE_MAP = {
    "domain": "domain",
    "url": "url",
    "ip:port": "ip-dst|port",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
}


def fetch_recent_iocs(days=1):
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    payload = {"query": "get_iocs", "days": days}

    response = requests.post(THREATFOX_URL, headers=headers, json=payload, timeout=30)
    response.raise_for_status()

    result = response.json()
    if result.get("query_status") != "ok":
        raise SystemExit(f"ThreatFox API returned an error: {result}")

    return result.get("data", [])


def build_misp_event(iocs):
    """Create a MISPEvent object and populate it with attributes from the IOC list."""
    event = MISPEvent()
    event.info = f"ThreatFox IOCs - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
    event.distribution = 0   # 0 = Your organization only. Change if you understand the sharing implications.
    event.threat_level_id = 2  # Medium
    event.analysis = 1         # Ongoing

    skipped = 0

    for ioc in iocs:
        ioc_type = ioc.get("ioc_type")
        misp_type = IOC_TYPE_MAP.get(ioc_type)

        if not misp_type:
            skipped += 1
            continue  # unmapped type — skip for now rather than guess

        attribute = event.add_attribute(
            type=misp_type,
            value=ioc["ioc"],
            comment=f"malware={ioc.get('malware_printable')}, confidence={ioc.get('confidence_level')}",
            to_ids=True,
        )

        # Tag with the malware family and threat type for easier searching later
        if ioc.get("malware_printable"):
            attribute.add_tag(f"malware:{ioc['malware_printable']}")
        if ioc.get("threat_type"):
            attribute.add_tag(f"threat-type:{ioc['threat_type']}")

    print(f"Built event with {len(event.attributes)} attributes ({skipped} skipped due to unmapped type).")
    return event


def main():
    days = 1
    if len(sys.argv) > 1:
        days = int(sys.argv[1])

    print(f"Fetching IOCs from the last {days} day(s)...")
    iocs = fetch_recent_iocs(days=days)
    print(f"Fetched {len(iocs)} IOCs.")

    if not iocs:
        print("Nothing to push — exiting.")
        return

    event = build_misp_event(iocs)

    misp = PyMISP(MISP_URL, MISP_API_KEY, MISP_VERIFY_SSL)
    created_event = misp.add_event(event, pythonify=True)

    if isinstance(created_event, dict) and created_event.get("errors"):
        raise SystemExit(f"MISP rejected the event: {created_event['errors']}")

    print(f"Created MISP event ID {created_event.id}: {created_event.info}")

    # Publish it so it's visible/searchable immediately (optional — comment out if you'd
    # rather review events manually before publishing)
    misp.publish(created_event)
    print("Event published.")


if __name__ == "__main__":
    main()