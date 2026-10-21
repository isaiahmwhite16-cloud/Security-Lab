Security-Lab

A small, Docker-based home security lab: Pi-hole for DNS filtering, MISP for threat intelligence, and a Python pipeline that pulls fresh indicators of compromise (IOCs) from abuse.ch ThreatFox into MISP.

The end goal is a closed loop: threat intel collected in MISP feeds Pi-hole, so DNS requests to known-bad domains get blackholed.

abuse.ch ThreatFox --> threatfox_to_misp.py --> MISP --> (planned) Pi-hole blocklist --> DNS queries from your PC
Status
Component	Status
Pi-hole in Docker	Working
MISP in Docker (official misp-docker)	Working
ThreatFox -> MISP ingestion	Working
MISP -> Pi-hole blocklist export	Planned
More feeds (URLhaus, MalwareBazaar), de-duplication, scheduling	Planned
Prerequisites
Windows 10/11 with Docker Desktop (WSL2 backend), Git, and Python 3.10+
Roughly 4 GB of free RAM and 30 GB of disk for MISP (it runs several containers)
A free abuse.ch account for an Auth-Key: https://auth.abuse.ch/

Commands below are PowerShell. On Linux/macOS, the Docker and Git commands are the same; only the virtual environment activation line differs.

Quick start
1. Clone this repo
powershell
git clone https://github.com/isaiahmwhite16-cloud/Security-Lab.git
cd Security-Lab
2. Start Pi-hole
powershell
Copy-Item pihole-docker-compose.example.yml docker-compose.yml

Open docker-compose.yml and set TZ to your timezone, then:

powershell
docker compose up -d
docker exec -it pihole pihole setpassword

The dashboard is at http://localhost/admin. (docker-compose.yml and Pi-hole's data folders are git-ignored on purpose.)

Optional: to filter your own PC's DNS, set your network adapter's DNS server to 127.0.0.1. Note that if the Pi-hole container is stopped, name resolution on that adapter fails until you stop using it as DNS or restart the container.

3. Start MISP

MISP uses the official MISP/misp-docker project. Clone it outside this repo.

Windows users: set this first, or the build fails on \r\n line endings.

powershell
git config --global core.autocrlf input
cd ..
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
Copy-Item template.env .env

Edit misp-docker\.env and set at least:

ADMIN_EMAIL=you@example.com
ADMIN_ORG=YourLab
ADMIN_PASSWORD=choose-a-real-password
GPG_PASSPHRASE=choose-something-private
DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true

Pi-hole and MISP's web server both default to port 80, so only one can bind it. To run both at once, move MISP to port 8080 by also setting (uncomment these lines):

NGINX_HTTP_PORT=8080
BASE_URL=http://localhost:8080

Then build and start:

powershell
docker compose build
docker compose up -d
docker ps

The first boot takes several minutes. misp-core may show unhealthy while it initializes; that is normal. Wait until docker logs misp-docker-misp-core-1 --tail 20 shows "MISP is now live", then run docker compose up -d once more if misp-nginx isn't running.

Log in at http://localhost:8080 (or http://localhost if you kept port 80) with your ADMIN_EMAIL and ADMIN_PASSWORD. Then create an API key under your profile's Auth Keys page. MISP shows the key only once, so copy it immediately.

4. Run the ThreatFox pipeline

Back in this repo's folder:

powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install requests pymisp python-dotenv

Create a file named .env in the repo folder with your abuse.ch Auth-Key, your MISP URL, and your MISP API key (plain values, no quotes, no spaces around the =):

ABUSECH_AUTH_KEY=your-abusech-auth-key
MISP_URL=http://localhost:8080
MISP_API_KEY=your-misp-api-key
MISP_VERIFY_SSL=False

Then:

powershell
python threatfox_to_misp.py 1

The argument is how many days of IOCs to pull (1-7, default 1). On success you'll see the number of IOCs fetched and the new MISP event ID. Open Event Actions > List Events in MISP to browse it.

Repo contents
File	Purpose
threatfox_to_misp.py	Pulls recent ThreatFox IOCs and pushes them into MISP as a published event
pihole-docker-compose.example.yml	Pi-hole compose template (copy to docker-compose.yml)
.gitignore	Keeps secrets, virtual environments, and Pi-hole data out of Git
How the pipeline works
Calls the ThreatFox get_iocs API for the last N days, authenticating with your Auth-Key.
Maps each IOC type to a MISP attribute type; anything unmapped is skipped.
ThreatFox type	MISP attribute
domain	domain
url	url
ip:port	ip-dst|port
md5_hash / sha1_hash / sha256_hash	md5 / sha1 / sha256
Creates one event named ThreatFox IOCs - <UTC timestamp>, adds each IOC as an attribute (IDS flag on, a comment with malware family and confidence, tags malware:<family> and threat-type:<type>), and publishes it.

Current limitations:

Every run creates a new event; there is no de-duplication yet, so re-running on the same day adds the same IOCs again.
Events use distribution = 0 (visible only to your MISP organization), which is right for a local lab.
Roadmap: MISP -> Pi-hole

Design notes, not yet implemented:

Query MISP (via PyMISP) for to_ids attributes of type domain, plus hostnames extracted from url attributes, optionally filtered by tag, confidence, or age.
Write them out as a plain list, one domain per line.
Get that list into Pi-hole, either as a local file adlist mounted into the container or by pushing entries through Pi-hole's API, then update gravity.
Run it on a schedule (Task Scheduler or cron).

Things to design around:

DNS can't block IPs. Pi-hole only sees domain lookups, so ip:port command-and-control IOCs can't be blackholed this way.
False positives. A malicious URL on a shared host (a code-hosting site, a CDN) would take down the whole legitimate domain if blocked. Prefer domain-type IOCs, filter by confidence, and expire old entries.
Troubleshooting
docker compose build fails and the error shows \r\n: Git converted line endings on Windows. Run git config --global core.autocrlf input, delete the misp-docker folder, and clone it again.
Bind for 0.0.0.0:80 failed: port is already allocated: another container (usually Pi-hole) holds port 80. Set NGINX_HTTP_PORT=8080 in MISP's .env.
misp-nginx keeps restarting with host not found in upstream "misp-core": the container never attached to the network. Run docker compose up -d --force-recreate misp-nginx.
misp-core shows unhealthy right after start: first-run setup takes several minutes. Check its logs for "MISP is now live" before troubleshooting further.
ThreatFox returns 403 / unknown_auth_key: the key in .env is wrong. The line must be exactly ABUSECH_AUTH_KEY=<key>, with no quotes or spaces. Regenerate the key at https://auth.abuse.ch/ if in doubt.
Can't log in to Pi-hole: newer Pi-hole images generate a random password on first start. Set your own with docker exec -it pihole pihole setpassword.
Security notes
Never commit .env. If a key or password ever lands in Git history or a chat, rotate it.
Change MISP's default credentials (set them in misp-docker\.env before first boot) and keep DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true so they aren't written to container logs.
This lab is designed for local use over plain HTTP. Don't expose MISP or Pi-hole to the internet as configured here.
