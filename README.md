# ForgeScan ⚙️🧭  
**Massive Web Vendor & Version Scanner** — detects stacks, extracts versions (incl. GitLab via `gon.revision`), probes common APIs, and enriches results with CVEs. Clean console UI + JSON/CSV/Markdown reports.

> _“Point at an IP or list — get a map of your attack surface.”_ 🚀

<p align="left">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green">
  <img alt="Async" src="https://img.shields.io/badge/Async-aiohttp-blue">
</p>

---

## ✨ Highlights

- 🔍 **Fingerprinting engine**: titles/headers/body/cookies + smart path probes
- 🧬 **Version extraction** from APIs, JS vars, asset names, and GitLab **`gon.revision`** (auto fetch `/users/sign_in`)
- 🧠 **CVE enrichment** (NVD 2.0) with **version-range** filtering and tidy console/Markdown sections
- 🧯 **False-positive guards** (e.g., phpMyAdmin vs SonarQube)
- 📝 **Reports**: table (TTY), `report.json`, `report.csv`, `report.md`
- 🗂️ **Single file**, async, fast, terminal-friendly (optional color)

---

## 📦 Install

```bash
# Python 3.10+
python3 -V

# Install deps
pip install aiohttp mmh3
```

---

## 🚀 Quickstart

```bash
# 1) Put targets in List.txt (URLs, hosts, or host:port), one per line
echo "https://example.org" >> List.txt
echo "10.10.10.10:8080"   >> List.txt
echo "gitlab.example.com" >> List.txt

# 2) Run
python3 forgescan.py -i List.txt --concurrency 300 --http-timeout 12 --color -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
```

> Tip: set an NVD API key for higher rate limits (https://nvd.nist.gov/developers/request-an-api-key):
```bash
export NVD_API_KEY="YOUR_KEY"
```

---

## 🔧 Usage

```
ForgeScan v2.1 — Massive Web Vendor & Version Scanner (single file)

options:
  -h, --help            show this help message and exit
  -i, --input INPUT     Input file (default: List.txt)
  -o, --outdir OUTDIR   Output directory (default: current)
  -f, --format FORMAT   Formats: table,json,csv,md
  --concurrency CONCURRENCY
                        Max concurrent HTTP (default: 200)
  --probe-concurrency PROBE_CONCURRENCY
                        Per-host probe concurrency (default: 6)
  --http-timeout HTTP_TIMEOUT
                        HTTP total timeout seconds (default: 20)
  -k, --insecure        Disable TLS verification (default: on)
  -A, --user-agent USER_AGENT
                        Custom User-Agent
  --no-probes           Disable extra probes for speed
  --verify-tls          Enable TLS verification (overrides -k)
  --selftest            Run local parsing self-test and exit
  --list-products       List built-in products and exit
  --color               Enable colorized output
  --dump-gitlab-html    Dump fetched HTML for pages that look like GitLab into OUTDIR/gitlab_<host>_<port>.html
  --cve                 Enrich results with CVEs from NVD 2.0
  --nvd-api-key NVD_API_KEY
                        NVD API key (or env NVD_API_KEY)
  --cve-timeout CVE_TIMEOUT
                        Timeout for NVD requests (seconds)
  --cve-concurrency CVE_CONCURRENCY
                        Max concurrent NVD product queries
  --cve-max-per CVE_MAX_PER
                        Max CVEs per product+version (0 = unlimited)
```

---

## 🧭 Examples

**Minimal**
```bash
python3 forgescan.py -i List.txt --color
```

**Faster scans**
```bash
python3 forgescan.py -i test_list.txt --concurrency 300 --http-timeout 12 --color -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
```

**Faster scans with CVE's**
```bash
python3 forgescan.py -i test_list.txt --concurrency 300 --http-timeout 12 --color -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36' --cve
```

**Dump GitLab HTML (capture `gon.revision`)**
```bash
python3 forgescan.py -i List.txt --dump-gitlab-html -o dumps
```

---

## 🧩 Products

```
Adminer, Alertmanager, Apache Guacamole, Apache Tomcat, Argo CD, Atlassian Confluence, Atlassian Jira, Bamboo, Bitbucket Server, Cacti, Centreon, Ceph, Cisco ASA, Citrix ADC (NetScaler), Discourse, DokuWiki, Drupal, Elasticsearch, F5 BIG-IP, Forgejo, Fortinet FortiGate, GLPI, Gerrit Code Review, Ghost, GitLab, Gitea, Gogs, Grafana, Graylog, HAProxy, HP Printer (Embedded Web Server), Harbor, Horde Webmail, Icinga Web 2, JFrog Artifactory, Jenkins, Joomla!, Keycloak, Kibana, Kubernetes Dashboard, Magento, Mattermost, MediaWiki, Microsoft Exchange Server, Microsoft IIS, Microsoft SharePoint, MikroTik RouterOS, MinIO, Moodle, NGINX, Nagios Core, NetBox, Netdata, Nextcloud, Nexus Repository Manager, Okta, OpenCart, OpenMediaVault, OpenNebula Sunstone, OpenShift, Outlook Web App, Palo Alto Panorama, Portainer, PrestaShop, Prometheus, Proxmox VE, QNAP QTS, RainLoop, Rancher, Redmine, Rocket.Chat, Roundcube Webmail, SOGo, Shopware, SonarQube, Sophos UTM, Splunk, Strapi, Synology DSM, TYPO3, TeamCity, Traefik, TrueNAS, Ubiquiti UniFi Network, Umbraco, VMware ESXi, VMware vCenter, WooCommerce, WordPress, Zabbix, Zimbra, Znuny/OTRS, oVirt Engine, osTicket, ownCloud, pfSense, phpBB, phpMyAdmin, vBulletin
```

---

## 🖨️ Output (console sample)

```
┌──(root㉿kali)-[~/Desktop/kruto/AuroraScanner]
└─# python3 test.py -i test_list.txt --concurrency 300 --http-timeout 12 --color -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36' 
+----------------------------------------+------------------+--------------------+----------------------+------------+------+--------------------+------------------------------+
| Target                                 | Product          | Version            | Vendor               | Confidence | HTTP | Server             | Title                        |
+----------------------------------------+------------------+--------------------+----------------------+------------+------+--------------------+------------------------------+
| http://217.11.69.181:8080/             | phpMyAdmin       | 5.1.3              | The phpMyAdmin Proj… | 42.0       | 200  | Apache/2.4.52 (De… | phpMyAdmin                   |
| http://194.32.141.229:8081/            | Adminer          | 4.8.1              | Adminer              | 30.0       | 200  | nginx/1.20.1       | Login - Adminer              |
| http://127.0.0.1/wordpress/            | WordPress        | 6.8.2              | WordPress            | 35.0       | 200  | Apache/2.4.63 (De… | forgenasd &#8211; 123        |
| http://5.76.33.93:37777/              | Apache Tomcat    | 9.0.20             | Apache               | 22.0       | 200  | -                  | Apache Tomcat/9.0.20         |
| http://5.76.14.121:311/               | Apache Tomcat    | 9.0.20             | Apache               | 22.0       | 200  | -                  | Apache Tomcat/9.0.20         |
| http://5.16.134.121:3790/              | Apache Tomcat    | 9.0.20             | Apache               | 22.0       | 200  | -                  | Apache Tomcat/9.0.20         |
| http://101.239.43.162:1926/            | Apache Tomcat    | 9.0.20             | Apache               | 22.0       | 200  | -                  | Apache Tomcat/9.0.20         |
| http://5.71.133.93:4433/               | Apache Tomcat    | 9.0.20             | Apache               | 22.0       | 200  | -                  | Apache Tomcat/9.0.20         |
| http://178.81.130.169:55553/           | Apache Tomcat    | 9.0.20             | Apache               | 22.0       | 200  | -                  | Apache Tomcat/9.0.20         |
| https://91.141.110.114/users/sign_in/  | GitLab           | 17.11.1            | GitLab               | 112.2      | 200  | nginx              | Sign in · GitLab             |
| http://62.84.31.36:5006/               | phpMyAdmin       | 5.0.1              | The phpMyAdmin Proj… | 56.0       | 200  | Apache/2.4.38 (De… | 62.84.34.36:5006 / mysql3 |… |
| http://195.49.220.91:5601/app/kibana   | Kibana           | 7.2                | Elastic              | 60.0       | 200  | -                  | Kibana                       |
| https://89.219.1.62:4443/              | Magento          | version not …      | Adobe/Magento        | 13.0       | 200  | xxxxxxxx-xxxxx     | -                            |
| https://zabbix-phone.easdu.kz/           | Zabbix           | version not …      | Zabbix               | 27.5       | 200  | Apache/2.4.65 (De… | zabbix-phone.enu.kz: Zabbix  |
| https://zabbix-print.test.kz/           | Zabbix           | version not …      | Zabbix               | 27.5       | 200  | Apache/2.4.65 (De… | zabbix-print.enu.kz: Zabbix  |
| https://94.247.134.12/users/sign_in   | GitLab           | 18.2.4             | GitLab               | 112.2      | 200  | nginx              | Sign in · GitLab             |
| https://176.96.227.21/users/sign_in/   | GitLab           | 18.2.1             | GitLab               | 112.2      | 200  | nginx              | Sign in · GitLab             |
| http://185.129.51.203/users/sign_in/   | GitLab           | 18.0.1             | GitLab               | 112.2      | 200  | nginx              | Sign in · GitLab             |
| https://mail.sdd.kz/owa/auth/logon.aspx | Outlook Web App  | 15.2.1544          | Microsoft            | 96.0       | 200  | Microsoft-IIS/10.0 | Outlook                      |
| https://mail.sdg.kz/owa/auth/logon.as… | Outlook Web App  | 15.1.2507          | Microsoft            | 96.0       | 200  | Microsoft-IIS/10.0 | Outlook                      |
| http://185.48.49.114:8009/            | phpMyAdmin       | 5.2.1              | The phpMyAdmin Proj… | 42.0       | 200  | nginx/1.14.1       | phpMyAdmin                   |
| https://mail.rwth-aachen.de/owa/auth/… | Outlook Web App  | 15.2.1748          | Microsoft            | 96.0       | 200  | Microsoft-IIS/10.0 | Outlook                      |
| https://swapi-platform.ontotext.com/g… | Grafana          | 8.3.4              | Grafana Labs         | 56.0       | 200  | openresty/1.15.8.2 | Grafana                      |
| https://ithaca-power.mcci.com/grafana… | Grafana          | 7.5.7              | Grafana Labs         | 56.0       | 200  | nginx/1.18.0 (Ubu… | Grafana                      |
| https://82.200.250.21/users/sign_in/  | GitLab           | 17.10.4            | GitLab               | 112.2      | 200  | nginx              | Sign in · GitLab             |
| http://91.147.103.1:5601/login        | Kibana           | 8.0.               | Elastic              | 27.0       | 200  | nginx              | Elastic                      |
| https://mail.23v.sn/                  | -                | version not …      | -                    | -          | -    | -                  | -                            |
| http://188.94.133.115:8081/            | Atlassian Jira   | 8.3.1              | Atlassian            | 36.0       | 200  | -                  | System Dashboard - Jira      |
| https://www.k12.kz/                   | WordPress        | 6.2.2              | WordPress            | 17.5       | 200  | Apache/2.4.41 (Ub… | Главная - ТОО «КМГ Инжинири… |
Running ForgeScan against 29 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (29/29)

Findings:
Apache Tomcat (6):
  • http://5.76.133.91:37777/ — 9.0.20
  • http://5.76.134.12:311/ — 9.0.20
  • http://5.76.134.11:3790/ — 9.0.20
  • http://109.232.43.162:1926/ — 9.0.20
  • http://5.76.12.93:4433/ — 9.0.20
  • http://178.89.133.169:55553/ — 9.0.20
GitLab (5):
  • https://91.147.112.114/users/sign_in/ — 17.11.1
  • https://94.247.111.165/users/sign_in — 18.2.4
  • https://176.96.244.29/users/sign_in/ — 18.2.1
  • http://185.129.52.207/users/sign_in/ — 18.0.1
  • https://82.200.210.201/users/sign_in/ — 17.10.4
Outlook Web App (3):
  • https://mail.asdk.kz/owa/auth/logon.aspx — 15.2.1544
  • https://mail.ksafg.kz/owa/auth/logon.aspx — 15.1.2507
  • https://mail.rwth-aachen.de/owa/auth/logon.aspx — 15.2.1748
phpMyAdmin (3):
  • http://217.11.61.186:8080/ — 5.1.3
  • http://62.84.34.46:5006/ — 5.0.1
  • http://185.48.141.114:8009/ — 5.2.1
Grafana (2):
  • https://swapi-platform.ontotext.com/grafana/login/ — 8.3.4
  • https://ithaca-power.mcci.com/grafana/login — 7.5.7
Kibana (2):
  • http://195.49.212.91:5601/app/kibana — 7.2
  • http://91.147.104.68:5601/login — 8.0.
WordPress (2):
  • http://127.0.0.1/wordpress/ — 6.8.2
  • https://www.km123.kz/ — 6.2.2
Zabbix (2):
  • https://zabbix-phone.easdu.kz/ — version not detected
  • https://zabbix-print.nusssd.kz/ — version not detected
Adminer (1):
  • http://194.32.141.211:8081/ — 4.8.1
Atlassian Jira (1):
  • http://188.94.155.125:8081/ — 8.3.1
Magento (1):
  • https://89.219.8.61:4443/ — version not detected
[+] JSON saved to ./report.json
[+] CSV saved to ./report.csv
[+] Markdown saved to ./report.md
```

---

## 🎨 Color & Emphasis Legend

- ✅ **Green**: detected version present  
- ⚠️ **Yellow**: redirects / 3xx  
- 🔴 **Red**: HTTP errors / **CVSS 8.8** emphasis  
- 🟨 **Yellow background + 🔴 red text**: CVEs likely **unauthenticated** exploitation  
- 🧩 **Gray**: version not detected

---

## 🛠️ Features in detail

- **Smart probes**: `/api/health`, `/api/status`, `/api/v4/version`, `/-/status`, `/service/rest/v1/status`, HP printer XMLs, Zabbix JSON-RPC, and more  
- **Version harvesters**: JS globals, asset names/querystrings, rule-specific regexes, and guarded generic regexes  
- **Printers**: HP EWS families — firmware strings from XML/HTML  
- **TTY UX**: single progress bar line, tidy table, colorized HTTP and version states

---

## 🗺️ Roadmap / TODO

**Presentation & UX**
- [ ] 🎨 **Beautiful HTML report** export (`report.html`): dark/light theme, filters, search, collapsible details  
- [ ] 🔴 **Highlight CVSS _8.8_ in red** across console/MD/HTML  
- [ ] 🟨🔴 **Mark “Unauth” CVEs** with **yellow background** + **red text** (keyword heuristics)  
- [ ] 🏷️ **Show CVE titles** (short names) next to IDs in console/MD/HTML

**Scanning & Coverage**
- [ ] 🔢 **Additional ports via `-p`** (e.g., `-p 80,443,8080,8443` and ranges `-p 8000-8100`)  
- [ ] 🌐 **Network mask scans** (CIDR: `10.10.0.0/16`) with async resolver/queue  
- [ ] 🗝️ **Default-creds module** for `mysql`, `psql`, `mssql`, `ssh`, `ftp` on default ports & common weak combos  
  - Flag: `--default-creds` (alias `-C`), service allowlist, safe timeouts, non-destructive checks  
  - Output reachability + credential verdicts per host:port

**Detection & Content**
- [ ] 📚 Expand **GitLab `revs.json`** (CE/EE disambiguation)  
- [ ] 🧩 More product fingerprints + favicon hashes where useful

---

## 🔐 Safety & Ethics

ForgeScan is for **defensive** and **authorized** assessment only.  
Scan only systems you own or have explicit permission to test. Respect laws, rules, and rate limits.  
The default-creds module will be **non-destructive**, but can still trigger alerts.

---

## 🤝 Contributing

PRs welcome!  
- Add fingerprints (title/body/header/cookie/probe + version regex)  
- Extend `revs.json` (GitLab)  
- Improve UI/HTML export & CVE rendering (titles, unauth highlight, 8.8 rule)  
- Implement `-p`, CIDR scans, and `--default-creds`

---

## 📄 License

MIT — see `LICENSE`.

---

## ❤️ Credits

Inspired by the daily pains of manual version hunting.  
