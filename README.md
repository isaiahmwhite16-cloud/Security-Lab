Security-Lab

A Docker-based home security lab that connects three tools:

MISP, a threat intelligence platform that stores indicators of compromise (IOCs)
Pi-hole, a DNS server that blocks lookups of bad domains
Suricata, an intrusion detection system that raises alerts

Python scripts pull fresh IOCs from abuse.ch ThreatFox into MISP, then export them from MISP to Pi-hole and Suricata.

abuse.ch ThreatFox --> threatfox_to_misp.py --> MISP --> misp_export.py --+--> Pi-hole  (blocks the domains)
                                                                          +--> Suricata (alerts on lookups of the domains)

Tested end to end on Windows with Docker Desktop: a lookup of a domain from the MISP list is answered with 0.0.0.0 by Pi-hole, and Suricata raises an alert that includes MISP's details (malware family, threat type, event).

Status
Component	Status
MISP in Docker (official misp-docker)	Working
ThreatFox -> MISP ingestion	Working
MISP -> Pi-hole domain blocklist	Working (run by hand)
MISP -> Suricata rules	Working (run by hand)
One-command setup, scheduled sync, de-duplication, more feeds (URLhaus, MalwareBazaar)	Planned
What this lab does and does not do
Pi-hole only filters lookups that are sent to it. Out of the box, nothing on your PC is. The lab proves the pipeline by sending lookups to it directly. To filter your PC's everyday traffic, see Using Pi-hole as your DNS.
Suricata only sees the DNS lookups that reach Pi-hole. It shares Pi-hole's network, so only domain IOCs can trigger an alert. IP-based IOCs from ThreatFox are not exported. Suricata is detection only: its alerts say "action":"allowed" because it never blocks anything. The blocking is Pi-hole's job.
DNS blocking can't stop a connection made straight to an IP address, because that connection never asks DNS first.
Prerequisites
Windows with Docker Desktop (WSL2 backend), Git, and Python 3.10+
About 4 GB of free RAM and 30 GB of disk for MISP (it runs several containers)
A free abuse.ch account for an Auth-Key: https://auth.abuse.ch/

Commands are PowerShell. On Linux or macOS the Docker and Git commands are the same, and only the virtual environment activation line differs.

Quick start
1. Clone this repo
powershell
git clone https://github.com/isaiahmwhite16-cloud/Security-Lab.git
cd Security-Lab
2. Start MISP

MISP uses the official MISP/misp-docker project. Clone it outside this repo.

Windows users: set this first, or the build fails on \r\n line endings.

powershell
git config --global core.autocrlf input
cd ..
git clone https://github.com/MISP/misp-docker.git
cd misp-docker
Copy-Item template.env .env

Edit misp-docker\.env and set these values:

ADMIN_EMAIL=you@example.com
ADMIN_ORG=YourLab
ADMIN_PASSWORD=choose-a-real-password
GPG_PASSPHRASE=choose-something-private
DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true
NGINX_HTTP_PORT=8080
BASE_URL=http://localhost:8080

The last two lines move MISP to port 8080 because Pi-hole uses port 80. Two of them are commented out in the template (DISABLE_PRINTING_PLAINTEXT_CREDENTIALS and NGINX_HTTP_PORT), so remove the #.

Then build and start:

powershell
docker compose build
docker compose up -d
docker ps

The first start takes several minutes. misp-core may show unhealthy while it sets itself up, which is normal. Wait until docker logs misp-docker-misp-core-1 --tail 20 shows "MISP is now live". If misp-nginx isn't running by then, run docker compose up -d again.

Log in at http://localhost:8080 with your ADMIN_EMAIL and ADMIN_PASSWORD, then create an API key on your profile's Auth Keys page. MISP shows the key only once, so copy it right away.

3. Set up the Python scripts

Back in this repo's folder:

powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install requests pymisp python-dotenv

Create a file named .env in this folder (plain values, no quotes, no spaces around =):

ABUSECH_AUTH_KEY=your-abusech-auth-key
MISP_URL=http://localhost:8080
MISP_API_KEY=your-misp-api-key
MISP_VERIFY_SSL=False
PIHOLE_PASSWORD=choose-a-password

PIHOLE_PASSWORD becomes your Pi-hole admin password. Don't use a $ character in it. .env is git-ignored, so your keys are never uploaded.

4. Load IOCs into MISP
powershell
python threatfox_to_misp.py 1

The number is how many days of ThreatFox IOCs to pull (1-7). It creates a new MISP event and publishes it.

5. Export from MISP
powershell
python misp_export.py

This writes lists\misp-iocs.txt for Pi-hole and suricata\rules\misp.rules for Suricata, and prints a few sample domains. Run this before the next step, because Suricata needs the rules file when it starts.

6. Start Pi-hole and Suricata

Set TZ in docker-compose.yml to your timezone, then:

powershell
docker compose up -d
docker ps
docker exec suricata suricatasc -c ruleset-stats

Both containers should be Up, and ruleset-stats should show rules_loaded close to the rule count from step 5 with rules_failed at 0.

7. Give Pi-hole the list
Open http://localhost/admin and log in with PIHOLE_PASSWORD.
Go to the Adlists page (called Lists in some versions) and choose Add blocklist.
For the address, enter file:///lists/misp-iocs.txt (three slashes), add a comment such as MISP IOCs, and save.
Tell Pi-hole to read it:
powershell
docker exec pihole pihole -g

The list's details page should now show a number of entries close to your domain count.

8. Test it

Pick a domain from lists\misp-iocs.txt (the first line is a comment) or from the samples misp_export.py printed, and look it up through Pi-hole. This only asks for the address. It doesn't connect to the site.

powershell
nslookup THE-DOMAIN 127.0.0.1

Pi-hole should answer 0.0.0.0. Then look for the Suricata alert:

powershell
Select-String -Path .\suricata\logs\eve.json -Pattern '"event_type":"alert"' | Select-Object -Last 1

On Linux or macOS: grep '"event_type":"alert"' suricata/logs/eve.json | tail -1

The alert names the domain and carries the malware family and threat type from MISP.

Keeping it fresh

To pull newer IOCs into the lab, run the two scripts again and reload both services:

powershell
python threatfox_to_misp.py 1
python misp_export.py --reload
Using Pi-hole as your DNS (optional)

By default Pi-hole answers only lookups that are sent to it. To have it filter a PC's everyday traffic, set that PC's DNS server to Pi-hole. After that, a lookup of any domain on the MISP list is blocked, and Suricata alerts on it.

Windows (this PC only):

Go to Settings > Network & Internet, open your active connection (Wi-Fi or Ethernet), and choose Edit next to DNS server assignment.
Change it from Automatic to Manual, turn on IPv4, and enter 127.0.0.1 as the preferred DNS server. Save.
Clear the DNS cache: ipconfig /flushdns
Browse a few sites, then check the Query Log at http://localhost/admin. Your PC's lookups should appear there.

To undo it, set DNS server assignment back to Automatic.

Things to know before you switch:

If Pi-hole is not running, your PC has no DNS. With only 127.0.0.1 set, name lookups fail whenever Docker Desktop is closed or the pihole container is stopped. Switch back to Automatic, or start the container.
A backup DNS server isn't a clean fix. Adding a second server such as 1.1.1.1 keeps you online while Pi-hole is down, but Windows may use it even while Pi-hole is running, so some lookups could skip the filtering.
Normal browsing keeps working. Pi-hole sends lookups for domains that aren't blocked to an upstream DNS server and passes the answers back. You can see or change the upstream in Pi-hole under Settings > DNS.
Browsers can bypass it. Chrome, Edge and Firefox can send lookups straight to their own secure DNS provider and ignore the Windows setting. Turn off "secure DNS" in the browser if you want it to use Pi-hole.
It only protects the PC you change. To cover a whole network you would point your router's DNS at the machine running Pi-hole. That works best on an always-on device (a Raspberry Pi, for example) and may need extra Pi-hole settings when Pi-hole runs in Docker. It hasn't been tested in this lab.
Repo contents
File	Purpose
threatfox_to_misp.py	Pulls recent ThreatFox IOCs and pushes them into MISP as a published event
misp_export.py	Exports IOCs from MISP to a Pi-hole domain list and Suricata rules
docker-compose.yml	Runs Pi-hole and Suricata (MISP runs from its own project)
.gitignore	Keeps secrets, virtual environments, and generated data out of Git

Generated at run time and git-ignored: etc-pihole/, etc-dnsmasq.d/, lists/, suricata/rules/, suricata/logs/.

How it works
threatfox_to_misp.py
Calls the ThreatFox get_iocs API for the last N days, authenticating with your Auth-Key.
Maps each IOC type to a MISP attribute type. Anything unmapped is skipped.
ThreatFox type	MISP attribute
domain	domain
url	url
ip:port	ip-dst|port
md5_hash / sha1_hash / sha256_hash	md5 / sha1 / sha256
Creates one event named ThreatFox IOCs - <UTC timestamp>. Each IOC is added with the IDS flag on, a comment with the malware family and confidence, and tags malware:<family> and threat-type:<type>. Then it publishes the event.

Current limitations:

Every run creates a new event. There is no de-duplication yet, so running it twice adds the same IOCs again.
Events use distribution = 0 (visible only to your MISP organization), which suits a local lab.
misp_export.py
Asks MISP for published, IDS-flagged domain and hostname attributes, and drops any that match a MISP warninglist of known-good domains.
Writes the cleaned domain list to lists/misp-iocs.txt, one domain per line.
Writes the Suricata rules that MISP generates for those same attributes to suricata/rules/misp.rules.

Options: --days N limits the export to events published in the last N days, and --reload reloads Pi-hole's lists and Suricata's rules after writing the files.

Roadmap
A one-command setup script that clones MISP, generates credentials, and starts everything
De-duplication in the ingestion script, then a scheduled sync
More feeds: URLhaus and MalwareBazaar
Automatically registering the Pi-hole list, so step 7 needs no clicking
A demo script that shows a lookup being blocked and alerted in one run
Troubleshooting
docker compose build fails and the error shows \r\n: Git converted line endings on Windows. Run git config --global core.autocrlf input, delete the misp-docker folder, and clone it again.
Connection refused on localhost:8080 when running a script: MISP isn't running. Check docker ps, and start it from the misp-docker folder with docker compose up -d.
Bind for 0.0.0.0:80 failed: port is already allocated: something else is using port 80. MISP must use 8080 (see step 2), because Pi-hole uses 80.
misp-nginx keeps restarting with host not found in upstream "misp-core": the container never attached to the network. Run docker compose up -d --force-recreate misp-nginx in the misp-docker folder.
misp-core shows unhealthy right after starting: first-run setup takes several minutes. Look for "MISP is now live" in its logs before troubleshooting further.
ThreatFox returns 403 or unknown_auth_key: the key in .env is wrong. The line must be exactly ABUSECH_AUTH_KEY=<key> with no quotes or spaces. Regenerate it at https://auth.abuse.ch/ if in doubt.
The suricata container won't stay up: suricata/rules/misp.rules probably doesn't exist yet. Run python misp_export.py, then docker compose up -d again.
The Pi-hole list says "not downloaded": run docker exec pihole pihole -g (both words pihole are needed).
docker compose up complains about the pihole container name: an older Pi-hole container exists. Run docker compose down in the folder it was started from.
Can't log in to Pi-hole: the password is the PIHOLE_PASSWORD line in .env. If you change it, recreate the container with docker compose up -d.
Security notes
Never commit .env. If a key or password ends up in Git history or a chat, rotate it.
Change MISP's default credentials in misp-docker\.env before the first boot, and keep DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true so they aren't written to container logs.
The IOC list contains real malicious domains. This lab only looks them up as text and never visits them. Don't open them in a browser.
The lab is designed for local use over plain HTTP. Don't expose MISP or Pi-hole to the internet as configured here.