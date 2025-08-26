#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ForgeScan v2.1.0 — Massive Web Vendor & Version Scanner (single file)
"""

import asyncio
import ipaddress
import aiohttp
import argparse
import json
import os
import re
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, quote, urlunparse

__VERSION__ = "2.1.0"

try:
    import mmh3  # type: ignore
    HAVE_MMH3 = True
except Exception:
    HAVE_MMH3 = False

DEFAULT_USER_AGENT = f"ForgeScan/{__VERSION__} (+https://aurorascope.local) aiohttp"

# Топовые веб-порты для -p top (уникальные, отсортированные)
TOP_WEB_PORTS = sorted({
    80,81,82,85,88,443,591,631,1311,1880,2222,2375,2376,2379,3000,
    4040,4041,4042,4043,4171,4180,4200,4440,4646,4848,5000,5001,5480,5555,5601,
    5900,5984,5985,5986,6080,6443,7001,7002,7080,7180,7183,7443,7473,7474,
    8000,8001,8006,8008,8025,8042,8065,8069,8080,8081,8082,8083,8086,8088,8091,
    8092,8093,8111,8153,8154,8180,8181,8200,8243,8280,8333,8404,8443,8444,8500,
    8501,8530,8531,8834,8880,8881,8888,8889,8983,9000,9001,9043,9060,9080,9090,
    9091,9093,9100,9200,9392,9440,9443,9600,9864,9869,9870,9901,9980,9990,10000,
    10254,10443,15671,15672,16686,16992,16993,18080,19888,27117,28017,32400,
    50070,50075,50090,61208
})


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def human_url(u: str) -> str:
    try:
        p = urlparse(u)
        host = p.hostname or ""
        port = p.port
        scheme = p.scheme or "http"
        path = p.path or "/"
        if port and ((scheme == "http" and port != 80) or (scheme == "https" and port != 443)):
            return f"{scheme}://{host}:{port}{path}"
        return f"{scheme}://{host}{path}"
    except Exception:
        return u

def normalize_targets(lines, ports=None):
    """
    lines: iterable строк-целей (IP/host, host:port, URL с/без пути).
    ports: Optional[Iterable[int]] — если задано (в т.ч. через -p top/all/CSV),
           для КАЖДОЙ цели генерируем http:// и https:// c КАЖДЫМ портом,
           при этом встроенный в строку порт/путь игнорируется.
    Если ports не задан — старое поведение: для 'host' -> http://host/ (HTTPS фоллбек в scan_one).
    """
    # подготовим список портов
    port_list = []
    if ports:
        seenp = set()
        for p in ports:
            try:
                pi = int(str(p).strip())
                if 1 <= pi <= 65535 and pi not in seenp:
                    port_list.append(pi)
                    seenp.add(pi)
            except Exception:
                pass

    targets = []

    for raw in lines:
        line = (raw or "").strip()
        if not line or line.startswith("#"):
            continue

        # Функция добавления пары схем для заданного host:port
        def add_for_host_ports(hostname: str):
            if not hostname:
                return
            if port_list:
                for p in port_list:
                    targets.append(f"http://{hostname}:{p}/")
                    targets.append(f"https://{hostname}:{p}/")
            else:
                # Без -p: только HTTP (HTTPS попробуем в scan_one)
                targets.append(f"http://{hostname}/")

        # Случай 1: уже есть схема (http/https/другая)
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", line):
            try:
                pu = urlparse(line)
                host = pu.hostname or ""
                if port_list:
                    # Требование: если -p задан, игнорируем порт/путь из исходной строки
                    add_for_host_ports(host)
                else:
                    # Старое поведение: оставляем как есть, только завершаем слешем
                    url = line if line.endswith("/") else line + "/"
                    targets.append(url)
            except Exception:
                # если парсер вдруг не справился — попробуем как host
                add_for_host_ports(line)
            continue

        # Случай 2: строка БЕЗ схемы, но с портом и/или путём, типа: "1.2.3.4:8080/x"
        # Подставим "http://" временно, чтобы распарсить netloc/path корректно
        has_colon = ":" in line
        has_slash = "/" in line
        if (has_colon or has_slash) and "://" not in line:
            try:
                pu = urlparse("http://" + line)
                host = pu.hostname or ""
                # Если список портов задан — игнорируем явный порт/путь и разворачиваем по -p
                if port_list:
                    add_for_host_ports(host)
                else:
                    # Без -p: если порт был — сохраним его, иначе просто host
                    if pu.port:
                        targets.append(f"http://{host}:{pu.port}/")
                    else:
                        targets.append(f"http://{host}/")
            except Exception:
                # Произошла ошибка — трактуем как голый host
                add_for_host_ports(line)
            continue

        # Случай 3: просто "host" или "ip"
        add_for_host_ports(line)

    # дедуп с сохранением порядка
    seen = set()
    uniq = []
    for t in targets:
        if t not in seen:
            uniq.append(t)
            seen.add(t)
    return uniq



def extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:200]

def extract_meta(html: str, name: str) -> str:
    m = re.search(
        rf'<meta[^>]+name=["\']{re.escape(name)}["\'][^>]+content=["\']([^"\']+)["\']',
        html, re.I
    )
    return (m.group(1).strip() if m else "")[:200]

def guess_charset(resp: aiohttp.ClientResponse, body: bytes) -> str:
    cs = resp.charset or None
    if cs:
        return cs
    try:
        body.decode("utf-8")
        return "utf-8"
    except Exception:
        return "latin-1"

def to_text(resp: aiohttp.ClientResponse, body: bytes, limit=150_000) -> str:
    try:
        txt = body.decode(guess_charset(resp, body), errors="ignore")
        return txt[:limit]
    except Exception:
        return ""

def safe_regex_search(pattern, text):
    try:
        return re.search(pattern, text, re.I)
    except re.error:
        return None

def keypath_get(obj, path: str):
    cur = obj
    for part in path.split("/"):
        if not part:
            continue
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur

SIGNATURES = [
    # Microsoft & Collaboration
    {"name":"Outlook Web App","vendor":"Microsoft","score":60,"matchers":[{"title":"Outlook|Outlook Web App|Outlook on the web"},{"body": r"/owa/auth/|owa\.auth|<!-- OWA "},{"headers":{"x-owa-version": r"[0-9.]+"}},{"path_probe":{"path": "/owa/","contains": r"Outlook|OWA","status_max":399}}],"version_extract":[r"X-OWA-Version:\s*([0-9.]+)",r"owa/auth/([0-9]+(?:\.[0-9]+){1,3})/",r"[?&](?:appver|ver|v)=([0-9]+(?:\.[0-9]+){1,3})"],"no_generic_version": True},
    {"name":"Microsoft Exchange Server","vendor":"Microsoft","score":45,
     "matchers":[
        {"headers":{"x-owa-version": r"[0-9.]+"}},
        {"body": r"Microsoft Exchange|/ecp/|Exchange Server"},
        {"title": r"Exchange\s*(Admin|Control|Server)|ECP"},
        {"path_probe":{"path": "/ecp/","contains": r"Exchange|ECP","status_max":399}},
     ],
     "version_extract":[r"Microsoft Exchange Server\s*([0-9]{4})"]
    },
    {"name":"Microsoft SharePoint","vendor":"Microsoft","score":35,
     "matchers":[
        {"title": r"SharePoint"},
        {"meta":{"name":"generator","regex": r"Microsoft SharePoint"}},
        {"body": r"spPageContextInfo|_spPageContextInfo"},
     ],
     "version_extract":[r"Microsoft SharePoint\s*([0-9]{4})"]
    },
    {"name":"Microsoft IIS","vendor":"Microsoft","score":15,
     "matchers":[{"headers":{"server": r"Microsoft-IIS/([0-9.]+)"}}],
     "version_extract":[r"Microsoft-IIS/([0-9.]+)"]
    },

    # Kubernetes & Cloud/DevOps
    {"name":"Kubernetes Dashboard","vendor":"Kubernetes","score":45,
     "matchers":[
        {"title": r"Kubernetes Dashboard"},
        {"body": r"Kubernetes Dashboard|Kubernetes\s+v?[0-9]+\.[0-9]+"},
        {"path_probe":{"path": "/api","contains": r"k8s|kubernetes|swagger","status_max":399}},
     ],
     "version_extract":[r"Kubernetes\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Rancher","vendor":"Rancher Labs","score":35,
     "matchers":[
        {"title": r"Rancher"},
        {"path_probe":{"path": "/v3/settings/ui-pl","contains": r"value","status_max":399}},
     ],
     "version_extract":[r"Rancher\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"OpenShift","vendor":"Red Hat","score":35,
     "matchers":[
        {"title": r"OpenShift"},
        {"body": r"openshift|k8s\.io/api"},
     ],
     "version_extract":[r"OpenShift\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Keycloak","vendor":"Red Hat","score":35,
     "matchers":[
        {"title": r"Keycloak"},
        {"body": r"keycloak|kc\.init|auth-server"},
     ],
     "version_extract":[r"Keycloak\s*v?([0-9]+\.[0-9.]+)"]
    },

    # CI/CD, repos, dev tools
    {"name":"Jenkins","vendor":"Jenkins","score":40,
     "matchers":[
        {"headers":{"x-jenkins": r"[0-9.]+"}},
        {"title": r"\bJenkins\b"},
        {"path_probe":{"path": "/api/json","contains": r"mode|nodeDescription","status_max":399}},
     ],
     "version_extract":[r"X-Jenkins:\s*([0-9.]+)", r"Jenkins\s*([0-9.]+)"]
    },
    {"name":"GitLab","vendor":"GitLab","score":66,
 "matchers":[
    {"title": r"GitLab"},
    {"body": r"(?:GitLab Community Edition|GitLab Enterprise Edition|Sign in · GitLab|gitlab_logo|gon\.gitlab_url)"},
    {"headers":{"x-gitlab-meta": r".+"}},
    {"path_probe":{"path": "/api/v4/version","status_max":399,"json_version_key":"version"}}
 ],
 "version_extract":[
    r"gitlab_version=([0-9]+(?:\.[0-9]+){1,2})",
    r'instance_version"\s*:\s*"([0-9]+(?:\.[0-9]+){1,2})',
    r"GitLab\s*([0-9]+\.[0-9.]+)"
 ],
 "no_generic_version": True},
    {"name":"Gitea","vendor":"Gitea","score":30,
     "matchers":[{"title": r"Gitea"}, {"body": r"Powered by Gitea|gitea\.io"}],
     "version_extract":[r"Gitea\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"SonarQube","vendor":"SonarSource","score":35,
     "matchers":[
        {"title": r"SonarQube"},
        {"path_probe":{"path": "/api/server/version","digits_only": True,"status_max":399}},
     ],
     "version_extract":[r"SonarQube\s*([0-9.]+)"]
    },
    {"name":"Nexus Repository Manager","vendor":"Sonatype","score":35,
     "matchers":[
        {"title": r"Nexus Repository Manager"},
        {"path_probe":{"path": "/service/rest/v1/status","json_version_key": "version","status_max":399}},
        {"path_probe":{"path": "/nexus/service/local/status","contains": r"version","status_max":399}},
     ],
     "version_extract":[r"Nexus Repository Manager\s*([0-9.]+)"]
    },
    {"name":"JFrog Artifactory","vendor":"JFrog","score":35,
     "matchers":[
        {"headers":{"x-artifactory-id": r".+"}},
        {"title": r"Artifactory"},
        {"path_probe":{"path": "/artifactory/api/system/version","json_version_key": "version","status_max":399}},
     ],
     "version_extract":[r"Artifactory\s*([0-9.]+)"]
    },
    {"name":"Harbor","vendor":"CNCF","score":30,
     "matchers":[{"title": r"Harbor"}, {"body": r"Harbor Portal|harbor\."}],
     "version_extract":[r"Harbor\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Argo CD","vendor":"Argo","score":30,
     "matchers":[{"title": r"Argo CD"}, {"body": r"argo\.cd|argocd"}],
     "version_extract":[r"Argo\s*CD\s*v?([0-9]+\.[0-9.]+)"]
    },

    # Monitoring / Logs
    {"name":"Grafana","vendor":"Grafana Labs","score":35,
     "matchers":[
        {"title": r"Grafana"},
        {"headers":{"set-cookie": r"grafana_session"}},
        {"path_probe":{"path": "/api/health","json_version_key": "version","status_max":399}},
        {"body": r"grafanaBootData|Welcome to Grafana"},
     ],
     "version_extract":[r"Grafana\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Kibana","vendor":"Elastic","score":30,
     "matchers":[
        {"title": r"Kibana"},
        {"headers":{"kbn-name": r".+"}},
        {"path_probe":{"path": "/api/status","contains": r"kibana|statuses","status_max":399}},
     ],
     "version_extract":[r"Kibana\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Elasticsearch","vendor":"Elastic","score":30,
     "matchers":[
        {"headers":{"x-elastic-product": r"Elasticsearch"}},
        {"path_probe":{"path": "/","contains": r"cluster_name|tagline|number","json_version_key": "version/number","status_max":399}},
     ],
     "version_extract":[r"number[\"']?\s*:\s*[\"']([0-9.]+)"]
    },
    {"name":"Prometheus","vendor":"Prometheus","score":25,
     "matchers":[
        {"title": r"Prometheus"},
        {"path_probe":{"path": "/-/status","contains": r"Version|prometheus","status_max":399}},
        {"path_probe":{"path": "/-/ready","contains": r"OK","status_max":399}},
     ],
     "version_extract":[r"Prometheus\s*([0-9.]+)"]
    },
    {"name":"Alertmanager","vendor":"Prometheus","score":25,
     "matchers":[
        {"title": r"Alertmanager"},
        {"path_probe":{"path": "/api/v2/status","json_version_key": "versionInfo/version","status_max":399}},
     ],
     "version_extract":[r"Alertmanager\s*([0-9.]+)"]
    },
    {"name":"Zabbix","vendor":"Zabbix","score":25,
     "matchers":[{"title": "Zabbix"}, {"cookie": "zbx_sessionid"}],
     "version_extract":["Zabbix\\s*([0-9.]+)"],
     "path_probe": "/api_jsonrpc.php",
     "json_version_key": "result"
    },
    {"name":"Graylog","vendor":"Graylog","score":30,
     "matchers":[{"title": r"Graylog"}, {"body": r"Graylog Web Interface"}],
     "version_extract":[r"Graylog\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Splunk","vendor":"Splunk","score":30,
     "matchers":[{"title": r"Splunk"}, {"body": r"Splunkd|splunk> prompt"}],
     "version_extract":[r"Splunk\s*(?:Enterprise\s*)?([0-9]+\.[0-9.]+)"]
    },

    # Portal / Auth / SSO
    {"name":"Okta","vendor":"Okta","score":25,
     "matchers":[{"title": r"Okta"}, {"body": r"okta-signin-widget|okta\.com"}],
     "version_extract":[r"Okta\s*v?([0-9]+\.[0-9.]+)"]
    },

    # Ticketing / Wiki
    {"name":"Atlassian Jira","vendor":"Atlassian","score":30,
     "matchers":[
        {"title": r"Jira|Atlassian Jira"},
        {"meta":{"name":"application-name","regex": r"Jira"}},
     ],
     "version_extract":[r"Jira\s*(?:Software|Core)?\s*([0-9]+\.[0-9.]+)"]
    },
    {"name":"Atlassian Confluence","vendor":"Atlassian","score":30,
     "matchers":[{"title": r"Confluence"}, {"meta":{"name":"application-name","regex": r"Confluence"}}],
     "version_extract":[r"Confluence\s*([0-9]+\.[0-9.]+)"]
    },
    {"name":"Redmine","vendor":"Redmine","score":25,
     "matchers":[{"title": r"Redmine"}, {"meta":{"name":"generator","regex": r"Redmine"}}],
     "version_extract":[r"Redmine\s*([0-9]+\.[0-9.]+)"]
    },

    # Messaging / Collab
    {"name":"Mattermost","vendor":"Mattermost","score":25,
     "matchers":[{"title": r"Mattermost"}, {"body": r"window\.mm_config"}],
     "version_extract":[r"Mattermost\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Rocket.Chat","vendor":"Rocket.Chat","score":25,
     "matchers":[{"title": r"Rocket\.Chat"}, {"body": r"__meteor_runtime_config__"}],
     "version_extract":[r"Rocket\.Chat\s*v?([0-9]+\.[0-9.]+)"]
    },
    {"name":"Zimbra","vendor":"Synacor","score":25,
     "matchers":[{"title": r"Zimbra"}, {"body": r"zimbraMailApp"}],
     "version_extract":[r"Zimbra\s*(?:Collaboration\s*Suite\s*)?([0-9]+\.[0-9.]+)"]
    },

    # SDN / Network / Security
    {"name":"F5 BIG-IP","vendor":"F5","score":30,
     "matchers":[{"title": r"BIG-?IP|F5"}, {"body": r"F5 Networks|BIGIP"}],
     "version_extract":[r"BIG-?IP\s*([0-9]+\.[0-9.]+)"]
    },
    {"name":"Palo Alto Panorama","vendor":"Palo Alto","score":30,
     "matchers":[{"title": r"Panorama|Palo Alto Networks"}, {"body": r"ngfw|pan-os"}],
     "version_extract":[r"PAN-OS\s*([0-9]+\.[0-9.]+)"]
    },

    # Fortinet FortiGate (improved)
    {"name":"Fortinet FortiGate","vendor":"Fortinet","score":40,
     "matchers":[
        {"title": r"FortiGate|Fortinet|SSL VPN Portal"},
        {"body": r"FortiGate|FortiOS|FortiClient|fgt_lang|svpn"},
        {"headers":{"server": r"Forti(?:Gate|Web|net)|FortiHTTP"}},
        {"cookie": r"(?:FGTSSID|SVPNCOOKIE|ccsrftoken)"},
        {"path_probe":{"path": "/remote/login","status_max":399,"contains": r"Forti(?:Gate|OS)|Fortinet"}},
        {"path_probe":{"path": "/login","status_max":399,"contains": r"Forti(?:Gate|OS)|Fortinet"}}
     ],
     "version_extract":[
        r"FortiOS\\s*v?([0-9]+(?:\\.[0-9]+){1,3})",
        r"FortiGate\\s*v?([0-9]+(?:\\.[0-9]+){1,3})",
        r'version\\s*[=:]\\s*([0-9]+(?:\\.[0-9]+){1,3})'
     ]
    },

    {"name":"Cisco ASA","vendor":"Cisco","score":30,
     "matchers":[{"title": r"Cisco Adaptive Security Appliance|ASA"}, {"body": r"Cisco ASDM|ASA"}],
     "version_extract":[r"ASA\s*([0-9]+(?:\.[0-9]+)*(?:\([^)]+\))?[A-Za-z0-9-]*)"]
    },
    {"name":"pfSense","vendor":"Netgate","score":25,
     "matchers":[{"title": r"pfSense"}, {"body": r"pfSense"}],
     "version_extract":[r"pfSense\s*([0-9]+\.[0-9.]+)"]
    },
    {"name":"Sophos UTM","vendor":"Sophos","score":25,
     "matchers":[{"title": r"Sophos"}, {"body": r"WebAdmin|Astaro|Sophos UTM"}],
     "version_extract":[r"Sophos\s*(?:UTM|XG)?\s*([0-9]+\.[0-9.]+)"]
    },
    {"name":"Citrix ADC (NetScaler)","vendor":"Citrix","score":25,
     "matchers":[{"title": r"Citrix ADC|NetScaler"}, {"body": r"netscaler"}],
     "version_extract":[r"(?:ADC|NetScaler)\s*([0-9]+\.[0-9.]+)"]
    },

    # Storage / Object
    {"name":"MinIO","vendor":"MinIO","score":25,
     "matchers":[{"title": r"MinIO"}, {"body": r"MinIO Console|MinIO Browser"}],
     "version_extract":[r"minio(?:\s*server)?\s*RELEASE\.(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)"]
    },
    {"name":"Ceph","vendor":"Ceph","score":25,
     "matchers":[{"title": r"Ceph"}, {"body": r"Ceph Dashboard"}],
     "version_extract":[r"Ceph\s*([0-9]+\.[0-9.]+)"]
    },

    # Web servers / proxies
    {"name":"Apache Tomcat","vendor":"Apache","score":20,
     "matchers":[{"title": r"Apache Tomcat"}, {"headers":{"server": r"Apache-Coyote|Tomcat"}}],
     "version_extract":[r"Apache Tomcat/?\s*([0-9.]+)"]
    },
    {"name":"NGINX","vendor":"F5/NGINX","score":15,
     "matchers":[{"headers":{"server": r"nginx/([0-9.]+)|\bnginx\b"}}],
     "version_extract":[r"nginx/([0-9.]+)"]
    },
    {"name":"Traefik","vendor":"Traefik Labs","score":20,
     "matchers":[{"title": r"Traefik"}, {"headers":{"server": r"\btraefik\b"}},
                 {"path_probe":{"path": "/api/version","contains": r"[0-9.]+","status_max":399}}],
     "version_extract":[r"Traefik\s*([0-9.]+)"]
    },
    {"name":"HAProxy","vendor":"HAProxy","score":20,
     "matchers":[{"title": r"HAProxy"}, {"body": r"Statistics Report|HAProxy"}],
     "version_extract":[r"HAProxy\s*([0-9]+\.[0-9.]+)"]
    },

    # Virtualization / VMware
    {"name":"VMware vCenter","vendor":"VMware","score":30,
     "matchers":[{"title": r"vSphere|vCenter"}, {"body": r"VMware vCenter"}],
     "version_extract":[r"(?:vCenter|vSphere)\s*([0-9]+\.[0-9.]+)"]
    },
    {"name":"VMware ESXi","vendor":"VMware","score":30,
     "matchers":[{"title": r"ESXi"}, {"body": r"VMware ESXi|/ui/"}],
     "version_extract":[r"ESXi\s*([0-9]+\.[0-9.]+)"]
    },

    # Databases (web UIs)
    {"name":"phpMyAdmin","vendor":"The phpMyAdmin Project","score":35,
     "matchers":[{"title": r"phpMyAdmin"}, {"body": r"phpMyAdmin"}],
     "version_extract":[r"phpMyAdmin\s*([0-9]+\.[0-9.]+)"]
    },
    {"name":"Adminer","vendor":"Adminer","score":25,
     "matchers":[{"title": r"Adminer"}, {"body": r"Adminer"}],
     "version_extract":[r"Adminer\s*([0-9]+\.[0-9.]+)"]
    },

    # --- Printers / EWS (HP LaserJet, PageWide, OfficeJet etc.) ---
    {"name":"HP Printer (Embedded Web Server)","vendor":"HP","score":34,
     "matchers":[
        {"title": r"(?:HP\s+)?(?:Color\s+)?LaserJet|HP\s+PageWide|HP\s+OfficeJet|Embedded Web Server"},
        {"body": r"Embedded Web Server|EWS|HP\s+(?:LaserJet|PageWide|OfficeJet)"},
        {"path_probe":{"path": "/DevMgmt/DiscoveryTree.xml","status_max":399,"contains": r"(?:HP|DiscoveryTree)"}},
        {"path_probe":{"path": "/DevMgmt/ProductConfigDyn.xml","status_max":399,"contains": r"(?:Firmware|Revision|Version)"}},
        {"path_probe":{"path": "/hp/device/DeviceInformation.xml","status_max":399,"contains": r"(?:DeviceInformation|Firmware)"}},
        {"path_probe":{"path": "/hp/device/DeviceInformationView","status_max":399,"contains": r"(?:Firmware|Revision|Version|HP)"}}
     ],
     "version_extract":[
        r"Firmware(?:\\s*Revision|\\s*Version|\\s*Datecode)?\\s*[:=]\\s*([0-9A-Za-z._-]{3,})",
        r"<Firmware(?:Version|Revision)[^>]*>\\s*([0-9A-Za-z._-]{3,})\\s*</Firmware(?:Version|Revision)>",
        r'"firmware(?:Version|Revision)"\\s*:\\s*"([0-9A-Za-z._-]{3,})"',
        r"FW(?:\\s*Rev(?:ision)?)?\\s*[:=]\\s*([0-9A-Za-z._-]{3,})"
     ]
    },

    # --- CMS / Wikis / Blogs ---
    {"name":"WordPress","vendor":"WordPress","score":35,
     "matchers":[
        {"meta":{"name":"generator","regex": r"WordPress"}},
        {"body": r"wp-content|wp-includes|/wp-json"},
        {"path_probe":{"path": "/wp-json","status_max":399,"json_version_key": None}},
        {"path_probe":{"path": "/readme.html","status_max":399,"contains": r"Version\\s*[0-9]"}}
     ],
     "version_extract":[r"WordPress\\s*([0-9.]+)", r"Version\\s*([0-9.]+)"]
    },
    {"name":"Joomla!","vendor":"Open Source Matters","score":30,
     "matchers":[
        {"meta":{"name":"generator","regex": r"Joomla"}},
        {"title": r"Joomla"},
        {"body": r"Joomla!"}
     ],
     "version_extract":[r"Joomla!?\\s*([0-9.]+)"]
    },
    {"name":"Drupal","vendor":"Drupal","score":30,
     "matchers":[
        {"meta":{"name":"generator","regex": r"Drupal"}},
        {"body": r"drupalSettings|Drupal"},
        {"path_probe":{"path": "/CHANGELOG.txt","status_max":399,"contains": r"Drupal\\s*[0-9]"}},
     ],
     "version_extract":[r"Drupal\\s*([0-9.]+)"]
    },
    {"name":"MediaWiki","vendor":"Wikimedia","score":28,
     "matchers":[
        {"meta":{"name":"generator","regex": r"MediaWiki"}},
        {"title": r"MediaWiki"},
        {"path_probe":{"path": "/api.php","status_max":399,"contains": r"MediaWiki"}},
     ],
     "version_extract":[r"MediaWiki\\s*([0-9.]+)"]
    },
    {"name":"TYPO3","vendor":"TYPO3","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"TYPO3"}},{"title": r"TYPO3"}],
     "version_extract":[r"TYPO3\\s*([0-9.]+)"]
    },
    {"name":"DokuWiki","vendor":"DokuWiki","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"DokuWiki"}},{"title": r"DokuWiki"}],
     "version_extract":[r"DokuWiki(?:\\s*Release)?\\s*([0-9][0-9A-Za-z\\-\\.]+)"]
    },
    {"name":"Ghost","vendor":"Ghost Foundation","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"Ghost"}},{"title": r"Ghost"}],
     "version_extract":[r"Ghost\\s*([0-9.]+)"]
    },
    {"name":"Strapi","vendor":"Strapi","score":24,
     "matchers":[{"title": r"Strapi"},{"body": r"Welcome to your Strapi app|/admin/"}],
     "version_extract":[r"Strapi\\s*([0-9.]+)"]
    },
    {"name":"Umbraco","vendor":"Umbraco","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"Umbraco"}},{"title": r"Umbraco"}],
     "version_extract":[r"Umbraco\\s*([0-9.]+)"]
    },
    {"name":"Magento","vendor":"Adobe/Magento","score":26,
     "matchers":[
        {"meta":{"name":"generator","regex": r"Magento"}},
        {"headers":{"x-magento-cache-debug": r".*"}},
     ],
     "version_extract":[r"Magento\\s*([0-9.]+)"]
    },
    {"name":"PrestaShop","vendor":"PrestaShop","score":26,
     "matchers":[{"meta":{"name":"generator","regex": r"PrestaShop"}},{"title": r"PrestaShop"}],
     "version_extract":[r"PrestaShop\\s*([0-9.]+)"]
    },
    {"name":"OpenCart","vendor":"OpenCart","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"OpenCart"}},{"body": r"Powered By OpenCart"}],
     "version_extract":[r"OpenCart\\s*([0-9.]+)"]
    },
    {"name":"Shopware","vendor":"Shopware","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"Shopware"}},{"headers":{"x-shopware-shopid": r".+"}}],
     "version_extract":[r"Shopware\\s*([0-9.]+)"]
    },
    {"name":"WooCommerce","vendor":"Automattic","score":22,
     "matchers":[{"body": r"woocommerce_params|wc_cart_fragments_params"}],
     "version_extract":[r"WooCommerce\\s*([0-9.]+)"]
    },

    # --- File sync/groupware ---
    {"name":"Nextcloud","vendor":"Nextcloud","score":35,
     "matchers":[
        {"title": r"Nextcloud"},
        {"path_probe":{"path": "/status.php","status_max":399,"json_version_key": "version"}},
     ],
     "version_extract":[r"Nextcloud\\s*([0-9.]+)"]
    },
    {"name":"ownCloud","vendor":"ownCloud","score":32,
     "matchers":[
        {"title": r"ownCloud|Owncloud"},
        {"path_probe":{"path": "/status.php","status_max":399,"json_version_key": "versionstring"}},
     ],
     "version_extract":[r"ownCloud\\s*([0-9.]+)"]
    },
    {"name":"Roundcube Webmail","vendor":"Roundcube","score":28,
     "matchers":[{"title": r"Roundcube\\s*Webmail|Roundcube"}],
     "version_extract":[r"Roundcube\\s*(?:Webmail\\s*)?([0-9.]+)"]
    },
    {"name":"SOGo","vendor":"Inverse","score":24,
     "matchers":[{"title": r"SOGo"},{"body": r"SOGo"}],
     "version_extract":[r"SOGo\\s*([0-9.]+)"]
    },
    {"name":"Horde Webmail","vendor":"Horde","score":22,
     "matchers":[{"title": r"Horde"},{"body": r"Horde Groupware|IMP Webmail"}],
     "version_extract":[r"Horde\\s*([0-9.]+)"]
    },
    {"name":"RainLoop","vendor":"RainLoop","score":22,
     "matchers":[{"title": r"RainLoop"},{"body": r"RainLoop Webmail"}],
     "version_extract":[r"RainLoop\\s*([0-9.]+)"]
    },

    # --- Helpdesk / ITSM ---
    {"name":"osTicket","vendor":"osTicket","score":24,
     "matchers":[{"title": r"osTicket"},{"body": r"Support Ticket System|osTicket"}],
     "version_extract":[r"osTicket\\s*([0-9.]+)"]
    },
    {"name":"GLPI","vendor":"Teclib","score":24,
     "matchers":[{"title": r"GLPI"},{"body": r"GLPI"}],
     "version_extract":[r"GLPI\\s*([0-9.]+)"]
    },
    {"name":"Znuny/OTRS","vendor":"Znuny/OTRS","score":24,
     "matchers":[{"title": r"OTRS|Znuny"},{"body": r"OTRS|Znuny"}],
     "version_extract":[r"(?:OTRS|Znuny)\\s*([0-9.]+)"]
    },

    # --- Forums / community ---
    {"name":"phpBB","vendor":"phpBB Group","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"phpBB"}},{"title": r"phpBB"}],
     "version_extract":[r"phpBB\\s*([0-9.]+)"]
    },
    {"name":"vBulletin","vendor":"vBulletin","score":24,
     "matchers":[{"meta":{"name":"generator","regex": r"vBulletin"}},{"title": r"vBulletin"}],
     "version_extract":[r"vBulletin\\s*([0-9.]+)"]
    },
    {"name":"Discourse","vendor":"Discourse","score":26,
     "matchers":[
        {"title": r"Discourse"},
        {"headers":{"x-discourse-version": r".+"}},
     ],
     "version_extract":[r"X-Discourse-Version:\\s*([0-9.]+)"]
    },

    # --- LMS ---
    {"name":"Moodle","vendor":"Moodle","score":26,
     "matchers":[{"meta":{"name":"generator","regex": r"Moodle"}},{"title": r"Moodle"}],
     "version_extract":[r"Moodle\\s*([0-9.]+)"]
    },

    # --- Monitoring/IT ---
    {"name":"Nagios Core","vendor":"Nagios","score":28,
     "matchers":[{"title": r"Nagios\\s*Core"},{"body": r"Nagios Core"}],
     "version_extract":[r"Nagios\\s*Core\\s*([0-9.]+)"]
    },
    {"name":"Icinga Web 2","vendor":"Icinga","score":26,
     "matchers":[{"title": r"Icinga Web 2"},{"body": r"Icinga Web 2"}],
     "version_extract":[r"Icinga\\s*Web\\s*2\\s*([0-9.]+)"]
    },
    {"name":"Centreon","vendor":"Centreon","score":26,
     "matchers":[{"title": r"Centreon"},{"body": r"Centreon"}],
     "version_extract":[r"Centreon\\s*([0-9.]+)"]
    },
    {"name":"Cacti","vendor":"The Cacti Group","score":24,
     "matchers":[{"title": r"Cacti"},{"body": r"The Cacti Group|Cacti"}],
     "version_extract":[r"Cacti\\s*([0-9.]+)"]
    },
    {"name":"Netdata","vendor":"Netdata","score":28,
     "matchers":[{"title": r"netdata"},{"path_probe":{"path": "/api/v1/info","status_max":399,"json_version_key": "version"}}],
     "version_extract":[r"netdata\\s*([0-9.]+)"]
    },
    {"name":"NetBox","vendor":"NetBox","score":28,
     "matchers":[{"title": r"NetBox"},{"path_probe":{"path": "/api/status","status_max":399,"json_version_key": "version"}}],
     "version_extract":[r"NetBox\\s*([0-9.]+)"]
    },

    # --- Containers / Infra ---
    {"name":"Portainer","vendor":"Portainer","score":30,
     "matchers":[{"title": r"Portainer"},{"path_probe":{"path": "/api/status","status_max":399,"json_version_key": "Version"}}],
     "version_extract":[r"Portainer\\s*([0-9.]+)"]
    },
    {"name":"Proxmox VE","vendor":"Proxmox","score":30,
     "matchers":[{"title": r"Proxmox\\s*VE"},{"path_probe":{"path": "/api2/json/version","status_max":399,"json_version_key": "data/version"}}],
     "version_extract":[r"Proxmox\\s*VE\\s*([0-9.]+)"]
    },
    {"name":"oVirt Engine","vendor":"oVirt","score":24,
     "matchers":[{"title": r"oVirt\\s*Engine"},{"body": r"oVirt Engine"}],
     "version_extract":[r"oVirt\\s*Engine\\s*([0-9.]+)"]
    },
    {"name":"OpenNebula Sunstone","vendor":"OpenNebula","score":24,
     "matchers":[{"title": r"OpenNebula\\s*Sunstone"},{"body": r"OpenNebula"}],
     "version_extract":[r"OpenNebula\\s*(?:Sunstone\\s*)?([0-9.]+)"]
    },
    {"name":"TrueNAS","vendor":"iXsystems","score":30,
     "matchers":[{"title": r"TrueNAS"},{"path_probe":{"path": "/api/v2.0/system/version","status_max":399,"digits_only": True}}],
     "version_extract":[r"TrueNAS\\s*([0-9.]+)"]
    },
    {"name":"OpenMediaVault","vendor":"OpenMediaVault","score":24,
     "matchers":[{"title": r"OpenMediaVault|openmediavault"},{"body": r"openmediavault"}],
     "version_extract":[r"OpenMediaVault\\s*([0-9.]+)"]
    },
    {"name":"Synology DSM","vendor":"Synology","score":24,
     "matchers":[{"title": r"Synology|DSM"},{"body": r"Synology"}],
     "version_extract":[r"DSM\\s*([0-9.]+)"]
    },
    {"name":"QNAP QTS","vendor":"QNAP","score":24,
     "matchers":[{"title": r"QTS|QNAP Turbo NAS|QNAP"},{"body": r"QNAP"}],
     "version_extract":[r"QTS\\s*([0-9.]+)"]
    },

    # --- Code hosting / CI ---
    {"name":"Gerrit Code Review","vendor":"Google","score":28,
     "matchers":[{"title": r"Gerrit\\s*Code\\s*Review"},{"path_probe":{"path": "/config/server/version","status_max":399,"digits_only": True}}],
     "version_extract":[r"Gerrit\\s*Code\\s*Review\\s*([0-9.]+)"]
    },
    {"name":"Bitbucket Server","vendor":"Atlassian","score":28,
     "matchers":[
        {"title": r"Bitbucket"},
        {"path_probe":{"path": "/rest/api/1.0/application-properties","status_max":399,"json_version_key":"version"}}
     ],
     "version_extract":[r"Bitbucket\\s*Server\\s*([0-9.]+)"]
    },
    {"name":"Gogs","vendor":"Gogs","score":26,
     "matchers":[{"title": r"Gogs"},{"body": r"Powered by Gogs"},{"path_probe":{"path": "/api/v1/version","status_max":399,"digits_only": True}}],
     "version_extract":[r"Gogs\\s*([0-9.]+)"]
    },
    {"name":"Forgejo","vendor":"Forgejo","score":24,
     "matchers":[{"title": r"Forgejo"},{"body": r"Forgejo"}],
     "version_extract":[r"Forgejo\\s*([0-9.]+)"]
    },
    {"name":"TeamCity","vendor":"JetBrains","score":26,
     "matchers":[{"title": r"TeamCity|JetBrains TeamCity"}],
     "version_extract":[r"TeamCity\\s*([0-9.]+)"]
    },
    {"name":"Bamboo","vendor":"Atlassian","score":26,
     "matchers":[{"title": r"Bamboo|Atlassian Bamboo"},{"path_probe":{"path": "/rest/api/latest/server","status_max":399,"json_version_key":"version"}}],
     "version_extract":[r"Bamboo\\s*([0-9.]+)"]
    },

    # --- Remote access / networking ---
    {"name":"Apache Guacamole","vendor":"Apache","score":26,
     "matchers":[{"title": r"Apache Guacamole"},{"body": r"Guacamole"}],
     "version_extract":[r"Guacamole\\s*([0-9.]+)"]
    },
    {"name":"Ubiquiti UniFi Network","vendor":"Ubiquiti","score":24,
     "matchers":[{"title": r"UniFi\\s*Network|UniFi\\s*Login|UniFi Controller"}],
      "version_extract":[r"UniFi\\s*(?:Network|Controller)\\s*([0-9.]+)"]
    },
    {"name":"MikroTik RouterOS","vendor":"MikroTik","score":24,
     "matchers":[{"title": r"RouterOS|MikroTik RouterOS"},{"body": r"WebFig|RouterOS"}],
     "version_extract":[r"RouterOS\\s*v?([0-9.]+)"]
    },

]

GENERIC_VERSION_REGEX = [
    r"\bversion[\"']?\s*[:=]\s*[\"']?([0-9]+(?:\.[0-9]+){1,3})\b",
    r"\bver(?:sion)?\.?\s*[:#]?\s*v?([0-9]+(?:\.[0-9]+){1,3})\b",
    r"\bv([0-9]+(?:\.[0-9]+){1,3})\b",
]

DEFAULT_PROBE_PATHS = [
    "/api/health", "/api/status", "/api/server/version", "/api/overview",
    "/service/rest/v1/status", "/nexus/service/local/status",
    "/artifactory/api/system/version", "/api/v2/status",
    "/version", "/help", "/login", "/robots.txt", "/favicon.ico",
    "/manifest.json", "/-/ready", "/-/status", "/v1/agent/self", "/v1/sys/health",
    "/actuator/health", "/swagger-ui/", "/api-docs", "/openapi.json",
    # Zabbix JSON-RPC (version)
    {"path": "/api_jsonrpc.php", "post_json": {"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1,"auth": None}},
    # FortiGate / SSL VPN login
    "/remote/login",
    # HP EWS / printers discovery & info
    "/DevMgmt/DiscoveryTree.xml",
    "/DevMgmt/ProductConfigDyn.xml",
    "/api/v4/version",
    "/api/v4/metadata",
    "/-/metadata",
    "/-/manifest.json",
    "/hp/device/DeviceInformation.xml",
    "/hp/device/DeviceInformationView"
]

JS_VERSION_REGEXPS = [
    r"window\.__APP_VERSION__\s*=\s*['\"]([0-9]+(?:\.[0-9]+){0,3})['\"]",
    r"APP_VERSION\s*[:=]\s*['\"]([0-9]+(?:\.[0-9]+){0,3})['\"]",
    r"version\s*[:=]\s*['\"]([0-9]+(?:\.[0-9]+){0,3})['\"]"
]

ASSET_VERSION_IN_QUERY = re.compile(r"[?&](?:ver|version)=([0-9]+(?:\.[0-9]+){0,3})", re.I)
ASSET_VERSION_IN_NAME = re.compile(r"[-_\.]v?([0-9]+(?:\.[0-9]+){0,3})(?:[-_\.]|\.js|\.css)", re.I)

# ----- GitLab gon.revision → version map & helper -----

# Заполните словарь известными ревизиями (короткий или полный SHA) → версия GitLab
# Примеры добавления:
#   "b4d1554": "18.2.4",
#   "b4d1554c4b9a7f0f3e1be2a1c2d3e4f5a6b7c8d": "18.2.4",
GITLAB_GON_REV_MAP_BUILTIN = {
    # TODO: пополните из ваших источников
    # "xxxxxxxx": "18.2.1",
    # "yyyyyyy": "18.0.1",
    # ...
}
GITLAB_REVS_PATH = os.environ.get("GITLAB_REVS_JSON", "revs.json")
GITLAB_GON_REV_MAP = dict(GITLAB_GON_REV_MAP_BUILTIN)
try:
    with open(GITLAB_REVS_PATH, "r", encoding="utf-8") as _f:
        _disk = json.load(_f)
        if isinstance(_disk, dict):
            # ключи/значения приводим к str
            for k, v in _disk.items():
                if isinstance(k, str) and isinstance(v, str):
                    GITLAB_GON_REV_MAP[k.strip()] = v.strip()
    if os.environ.get("AURORA_DEBUG"):
        print(f"[gitlab] loaded {len(GITLAB_GON_REV_MAP)} revs from {GITLAB_REVS_PATH}", file=sys.stderr)
except Exception as e:
    print(f"[gitlab] failed to load revs from {GITLAB_REVS_PATH}: {e}", file=sys.stderr)

_GITLAB_GON_REV_RE = re.compile(r'gon\.revision\s*=\s*[\'"]([0-9a-f]{7,40})[\'"]', re.I)
_GITLAB_GON_EE_RE  = re.compile(r'gon\.ee\s*=\s*(true|false)', re.I)

def _clean_version(v: str) -> str:
    return v.replace("-ee", "").strip()

def _prefer_by_ee(candidates, ee_flag: bool):
    if not candidates:
        return None
    filtered = [kv for kv in candidates if kv[1].endswith("-ee") == ee_flag]
    pool = filtered if filtered else candidates
    pool.sort(key=lambda kv: len(kv[0]), reverse=True)
    return pool[0][1]

def gitlab_version_from_gon(html: str):
    """
    Возвращает (version, revision). Работает даже если на странице нет явных "name clues".
    """
    if not html:
        return None, None
    m_rev = _GITLAB_GON_REV_RE.search(html)
    if not m_rev:
        return None, None
    rev = m_rev.group(1)

    m_ee = _GITLAB_GON_EE_RE.search(html)
    ee_flag = (m_ee and m_ee.group(1).lower() == "true")

    candidates = []
    for k, v in GITLAB_GON_REV_MAP.items():
        if rev.startswith(k) or k.startswith(rev):
            candidates.append((k, v))
    if not candidates:
        return None, rev

    chosen = _prefer_by_ee(candidates, ee_flag)
    return (_clean_version(chosen) if chosen else None), rev


class FingerprintEngine:
    def __init__(self, signatures, generic_version_regex):
        self.rules = signatures
        self.generic_version_regex = [re.compile(x, re.I) for x in generic_version_regex]

    def match(self, ctx):
        results = []
        body_text = ctx.get("body_text", "") or ""
        headers_join = ctx["headers_join"]

        # Быстрый хинт: есть ли на странице gitlab gon.*
        has_gitlab_gon = bool(
            re.search(r'\bgon\.revision\s*=\s*[\'"][0-9a-f]{7,40}[\'"]', body_text, re.I) or
            re.search(r'\bgon\.gitlab_url\s*=\s*[\'"]https?://', body_text, re.I)
        )

        for rule in self.rules:
            base = rule.get("score", 10)
            conf = 0.0
            version = None
            evidence = []
            name_clues = 0

            # --- стандартные матчеры ---
            for m in rule.get("matchers", []):
                if "headers" in m:
                    ok = True
                    for hk, hv in m["headers"].items():
                        val = ctx["headers"].get(hk.lower(), "")
                        if hk.lower() == "set-cookie":
                            val = "; ".join(ctx.get("cookies", []))
                        if not safe_regex_search(hv, val):
                            ok = False
                            break
                    if ok:
                        conf += base * 0.5
                        evidence.append("headers")
                        name_clues += 1

                if "title" in m and ctx.get("title"):
                    if safe_regex_search(m["title"], ctx["title"]):
                        conf += base * 0.7
                        evidence.append("title")
                        name_clues += 1

                if "body" in m and body_text:
                    if safe_regex_search(m["body"], body_text):
                        conf += base * 0.5
                        evidence.append("body")
                        name_clues += 1

                if "cookie" in m and ctx.get("cookies"):
                    cookies = "; ".join(ctx.get("cookies", []))
                    if safe_regex_search(m["cookie"], cookies):
                        conf += base * 0.4
                        evidence.append("cookie")
                        name_clues += 1

                if "meta" in m and ctx.get("meta"):
                    meta = m["meta"]
                    name = meta.get("name","").lower()
                    regex = meta.get("regex",".*")
                    if name in ctx["meta"] and safe_regex_search(regex, ctx["meta"][name]):
                        conf += base * 0.5
                        evidence.append(f"meta:{name}")
                        name_clues += 1

                if "path_probe" in m:
                    pp = m["path_probe"]
                    path = pp.get("path","/")
                    pdata = ctx["probes"].get(path)
                    if pdata and isinstance(pdata, dict):
                        try:
                            status_max = int(pp.get("status_max", 399))
                        except Exception:
                            status_max = 399
                        try:
                            status_val = pdata.get("status", 999)
                            status_int = int(status_val) if status_val is not None else 999
                        except Exception:
                            status_int = 999
                        if status_int <= status_max:
                            txt = pdata.get("text","") or ""
                            contains = pp.get("contains")
                            digits_only = pp.get("digits_only", False)
                            jvk = pp.get("json_version_key", "___none___")

                            probe_hit = False
                            if contains and safe_regex_search(contains, txt):
                                probe_hit = True
                            if digits_only and re.match(r"^\s*[0-9]+(?:\.[0-9]+){1,3}\s*$", txt.strip()):
                                probe_hit = True
                            if jvk is None:
                                mt = re.search(r"([0-9]+(?:\.[0-9]+){1,3})", txt)
                                if mt:
                                    version = version or mt.group(1)
                                    probe_hit = True
                            elif isinstance(jvk, str) and jvk != "___none___":
                                jobj = pdata.get("json")
                                if jobj is not None:
                                    val = keypath_get(jobj, jvk)
                                    if isinstance(val, (str,int,float)):
                                        sv = str(val)
                                        if re.match(r"^[0-9]+(?:\.[0-9]+){1,3}", sv):
                                            version = version or sv
                                            probe_hit = True

                            if probe_hit:
                                conf += base * (0.25 if name_clues == 0 else 0.8)
                                evidence.append(f"probe:{path}")

            # --- GitLab: gon.* как самостоятельный признак + извлечение версии ---
            if rule.get("name") == "GitLab" and has_gitlab_gon:
                # если до этого не было «name clues», добавим мягкий
                if name_clues == 0:
                    name_clues = 1
                    conf = max(conf, base * 0.7)
                    evidence.append("gon_hint")

                ver_from_gon, rev = gitlab_version_from_gon(body_text)
                if rev:
                    evidence.append(f"gitlab_gon_revision:{rev}")
                    # если версию нашли по map — считаем почти уверенны
                    conf = max(conf, base * (0.9 if ver_from_gon else 0.6))
                if ver_from_gon:
                    version = ver_from_gon

            # --- Регексы конкретного правила (title/body/headers/meta + из проб) ---
            if not version and name_clues > 0 and not rule.get("no_generic_assets"):
                blobs = [ctx.get("title",""), body_text, headers_join, ctx.get("meta_join","")]
                for rgx in rule.get("version_extract", []):
                    cre = re.compile(rgx, re.I)
                    found = False
                    for b in blobs:
                        m = cre.search(b or "")
                        if m:
                            version = m.group(1)
                            conf += base * 0.4
                            evidence.append("version_regex")
                            found = True
                            break
                    if found:
                        break
                    for pdata in ctx.get("probes", {}).values():
                        t = (pdata.get("text") or "")
                        if not t:
                            continue
                        m2 = cre.search(t)
                        if m2:
                            version = m2.group(1)
                            conf += base * 0.35
                            evidence.append("version_regex_probe")
                            found = True
                            break
                    if found:
                        break

            # --- generic JS/assets версии (уважаем флаг no_generic_version) ---
            if not version and name_clues > 0 and not rule.get("no_generic_version") and not rule.get("no_generic_assets"):
                for rgx in JS_VERSION_REGEXPS:
                    m = re.search(rgx, body_text, re.I)
                    if m:
                        version = m.group(1)
                        evidence.append("js_var")
                        break
            if not version and name_clues > 0 and not rule.get("no_generic_version") and not rule.get("no_generic_assets"):
                for asset in ctx.get("assets", []):
                    m = ASSET_VERSION_IN_QUERY.search(asset)
                    if m:
                        version = m.group(1)
                        evidence.append("asset_query")
                        break
                    m2 = ASSET_VERSION_IN_NAME.search(asset)
                    if m2:
                        version = m2.group(1)
                        evidence.append("asset_name")
                        break

            # --- самый последний бэкап (ТЕПЕРЬ уважаем no_generic_version) ---
            if conf > 0 and name_clues > 0 and not version and not rule.get("no_generic_version"):
                for cre in self.generic_version_regex:
                    m = cre.search(body_text) or cre.search(ctx.get("title","")) or cre.search(headers_join)
                    if m:
                        version = m.group(1)
                        evidence.append("generic")
                        break

            if conf > 0:
                results.append({
                    "name": rule["name"],
                    "vendor": rule.get("vendor",""),
                    "confidence": round(min(conf, base*3), 2),
                    "version": version or "",
                    "evidence": evidence,
                    "name_clues": name_clues
                })
        return sorted(results, key=lambda x: (x["confidence"], x["name_clues"]), reverse=True)



class Scanner:
    def __init__(self, args):
        self.args = args
        self.timeout = aiohttp.ClientTimeout(total=args.http_timeout)
        self.ssl_context = ssl.create_default_context()
        if args.insecure and not args.verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
        self.sem = asyncio.Semaphore(args.concurrency)
        self.fp = FingerprintEngine(SIGNATURES, GENERIC_VERSION_REGEX)
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=self.timeout,
            connector=aiohttp.TCPConnector(ssl=self.ssl_context, limit=0, ttl_dns_cache=300),
            headers={"User-Agent": self.args.user_agent or DEFAULT_USER_AGENT},
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def _get(self, url, allow_redirects=True):
        try:
            async with self.sem:
                async with self.session.get(url, allow_redirects=allow_redirects) as r:
                    body = await r.read()
                    return r, body, None
        except Exception as e:
            return None, b"", e


    async def _probe_paths(self, base_url, paths):
        out = {}
        sem = asyncio.Semaphore(min(10, max(2, self.args.probe_concurrency)))
        async def worker(p):
            # p can be string path or dict with {"path":..., "post_json": {...}} for JSON-RPC probes
            try:
                if isinstance(p, dict):
                    key = p.get("path", "/")
                    url = urljoin(base_url, key)
                    async with sem:
                        try:
                            async with self.session.post(url, json=p.get("post_json", {}), headers={"Content-Type":"application/json"}, timeout=self.timeout, allow_redirects=False) as r:
                                body = await r.read()
                                try:
                                    jobj = json.loads(body.decode("utf-8", "ignore"))
                                except Exception:
                                    jobj = None
                                out[key] = {"status": r.status, "text": body.decode("utf-8", "ignore"), "json": jobj, "headers": dict(r.headers)}
                        except Exception as e:
                            out[key] = {"status": None, "text": "", "json": None, "headers": {}, "error": str(e)}
                    return
                # default GET path
                key = p
                url = urljoin(base_url, p)
                async with sem:
                    try:
                        async with self.session.get(url, timeout=self.timeout, allow_redirects=False) as r:
                            body = await r.read()
                            try:
                                jobj = json.loads(body.decode("utf-8", "ignore"))
                            except Exception:
                                jobj = None
                            out[key] = {"status": r.status, "text": body.decode("utf-8", "ignore"), "json": jobj, "headers": dict(r.headers)}
                    except Exception as e:
                        out[key] = {"status": None, "text": "", "json": None, "headers": {}, "error": str(e)}
            except Exception as e:
                out[str(p)] = {"status": None, "text": "", "json": None, "headers": {}, "error": str(e)}
        await asyncio.gather(*[worker(p) for p in paths])
        return out

    async def _favicon_hash(self, base_url):
        if not HAVE_MMH3:
            return None
        fav = urljoin(base_url, "/favicon.ico")
        try:
            async with self.sem:
                async with self.session.get(fav, allow_redirects=True) as r:
                    if r.status != 200:
                        return None
                    import base64
                    content = await r.read()
                    b64 = base64.b64encode(content).decode()
                    try:
                        return mmh3.hash(b64)
                    except Exception:
                        return None
        except Exception:
            return None

    def _extract_assets(self, html: str):
        assets = []
        for m in re.finditer(r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css)(?:\?[^"\']*)?)["\']', html, re.I):
            assets.append(m.group(1))
        return assets[:200]

    async def scan_one(self, base_url):
        result = {
            "input": base_url, "final_url": "", "status": None, "headers": {},
            "cookies": [], "server": "", "x_powered_by": "", "title": "",
            "meta": {}, "meta_join": "", "body_preview": "", "assets": [],
            "probes": {}, "favicon_mmh3": None, "fingerprints": [], "best": {}, "error": ""
        }
        resp, body, err = await self._get(base_url, allow_redirects=True)
        if err or not resp:
            # HTTP->HTTPS fallback for bare HTTP inputs
            try:
                pu = urlparse(base_url)
                if pu.scheme == "http":
                    netloc = pu.hostname or ""
                    if pu.port:
                        netloc = f"{netloc}:{pu.port}"
                    https_url = urlunparse(("https", netloc, pu.path or "/", pu.params, pu.query, pu.fragment))
                    resp, body, err2 = await self._get(https_url, allow_redirects=True)
                    if err2 or not resp:
                        result["error"] = str(err2 or err) if (err2 or err) else "request_failed"
                        return result
                    base_url = https_url
                else:
                    result["error"] = str(err) if err else "request_failed"
                    return result
            except Exception as e:
                result["error"] = str(e)
                return result
        result["final_url"] = str(resp.url)
        result["status"] = resp.status
        headers = {k.lower(): v for k,v in resp.headers.items()}
        result["headers"] = headers
        result["cookies"] = resp.headers.getall("Set-Cookie", [])
        result["server"] = headers.get("server","")
        result["x_powered_by"] = headers.get("x-powered-by","")

        text = to_text(resp, body)
        result["body_preview"] = text
        result["title"] = extract_title(text)
        # --- GitLab: дамп и добор signin при отсутствующем gon.revision ---
        try:
            is_gitlab_like = (
                ("x-gitlab-meta" in headers)
                or bool(re.search(r'\bGitLab\b|gon\.gitlab_url|gitlab_logo', text, re.I))
            )
            if getattr(self.args, "dump_gitlab_html", False) and is_gitlab_like:
                try:
                    os.makedirs(self.args.outdir, exist_ok=True)
                except Exception:
                    pass
                pu = urlparse(str(resp.url))
                host = pu.hostname or "unknown"
                port = pu.port or (443 if pu.scheme == "https" else 80)
                dump_path = os.path.join(self.args.outdir, f"gitlab_{host}_{port}.html")
                try:
                    with open(dump_path, "wb") as _fout:
                        _fout.write(body)  # полный ответ
                    print(f"[debug] GitLab HTML dump saved: {dump_path}", file=sys.stderr)
                    result["gitlab_html_dump"] = dump_path
                except Exception as _e:
                    print(f"[debug] Failed to save GitLab HTML dump for {result.get('final_url') or base_url}: {_e}", file=sys.stderr)

            # Если GitLab и нет gon.revision — попробуем явно /users/sign_in
            if is_gitlab_like and not re.search(r'\bgon\.revision\s*=\s*[\'"][0-9a-f]{7,40}[\'"]', text, re.I):
                alt = await self._fetch_gitlab_signin_html(result["final_url"])
                if alt:
                    # Дописываем, чтобы FingerprintEngine увидел gon.revision
                    text = result["body_preview"] = (text + "\n\n<!-- alt_signin -->\n" + alt)
                    # тайтл обновлять не обязательно, но можно:
                    if not result["title"]:
                        result["title"] = extract_title(alt)
        except Exception as _e:
            print(f"[debug] GitLab signin enrichment failed: {_e}", file=sys.stderr)

        meta_names = ["generator","application-name"]
        meta_map = {}
        for n in meta_names:
            val = extract_meta(text, n)
            if val:
                meta_map[n] = val
        result["meta"] = meta_map
        result["meta_join"] = "\n".join([f"{k}:{v}" for k,v in meta_map.items()])
        result["assets"] = self._extract_assets(text)

        paths = DEFAULT_PROBE_PATHS if self.args.probes else ["/favicon.ico"]
        result["probes"] = await self._probe_paths(result["final_url"], paths)

        result["favicon_mmh3"] = await self._favicon_hash(result["final_url"])

        ctx = {
            "url": result["final_url"],
            "status": result["status"],
            "headers": result["headers"],
            "headers_join": "\n".join([f"{k}: {v}" for k,v in result["headers"].items()]),
            "cookies": result["cookies"],
            "title": result["title"],
            "meta": result["meta"],
            "meta_join": result["meta_join"],
            "body_text": result["body_preview"],
            "probes": result["probes"],
            "favicon_mmh3": result["favicon_mmh3"],
            "assets": result["assets"],
        }
        fps = self.fp.match(ctx)
        result["fingerprints"] = fps
        result["best"] = fps[0] if fps else {}
        return result
    async def _fetch_gitlab_signin_html(self, any_url):
        """
        Если текущая страница похожа на GitLab, но gon.revision не найден,
        попробовать дернуть /users/sign_in с 'браузерными' Accept-заголовками.
        Вернет text (str) либо None.
        """
        try:
            pu = urlparse(any_url)
            host = pu.hostname or "unknown"
            port = pu.port
            base = f"{pu.scheme}://{host}"
            if port:
                base += f":{port}"
            signin = urljoin(base, "/users/sign_in")

            # Браузерные Accept / Accept-Language — как в твоем curl
            hdrs = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                # User-Agent уже выставлен на уровне сессии из args.user_agent
            }
            async with self.session.get(signin, allow_redirects=True, headers=hdrs) as r2:
                b2 = await r2.read()
                t2 = to_text(r2, b2)
                if re.search(r'\bgon\.revision\s*=\s*[\'"][0-9a-f]{7,40}[\'"]', t2, re.I):
                    # опционально дампим «успешную» страницу
                    if getattr(self.args, "dump_gitlab_html", False):
                        try:
                            os.makedirs(self.args.outdir, exist_ok=True)
                            dump_path = os.path.join(self.args.outdir, f"gitlab_{host}_{port or (443 if pu.scheme=='https' else 80)}_signin.html")
                            with open(dump_path, "wb") as _fout:
                                _fout.write(b2)
                            print(f"[debug] GitLab signin HTML dump saved: {dump_path}", file=sys.stderr)
                        except Exception as _e:
                            print(f"[debug] Failed to save GitLab signin dump for {signin}: {_e}", file=sys.stderr)
                    return t2
        except Exception as _e:
            print(f"[debug] _fetch_gitlab_signin_html error: {_e}", file=sys.stderr)
        return None


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", str(s))

# compiled ANSI regex used by truncate_display
_ansi_re = re.compile(r"\x1b\[[0-9;]*m")

def display_width(s: str) -> int:
    """Visible width of string in terminal, ignoring ANSI and counting wide chars."""
    import unicodedata, re as _re
    s = strip_ansi(s)
    w = 0
    for ch in s:
        if unicodedata.combining(ch):
            continue
        ea = unicodedata.east_asian_width(ch)
        w += 2 if ea in ('W', 'F') else 1
    return w

def truncate_display(s: str, maxw: int) -> str:
    """Truncate preserving ANSI color codes and visible width; add ellipsis if truncated."""
    if maxw <= 0:
        return ''
    raw = s
    plain = strip_ansi(raw)
    # Quick path: already fits
    if display_width(raw) <= maxw:
        return raw
    # Build truncated plain string
    import unicodedata
    res_plain = ''
    w = 0
    for ch in plain:
        if unicodedata.combining(ch):
            continue
        ea = unicodedata.east_asian_width(ch)
        cw = 2 if ea in ('W', 'F') else 1
        if w + cw > maxw - 1:  # leave space for ellipsis
            break
        res_plain += ch
        w += cw
    res_plain += '…'
    # If ANSI present, best effort: wrap the entire truncated text in same outer colors as original
    start_codes = _ansi_re.findall(raw[:raw.find(plain[0])]) if plain else []
    end_reset = "\x1b[0m" if "\x1b[" in raw else ""
    if start_codes:
        return ''.join(start_codes) + res_plain + (end_reset if not raw.endswith(end_reset) else '')
    return res_plain

def _is_http_ok(code) -> bool:
    """
    Возвращает True, если код похож на валидный HTTP-статус (1xx..5xx).
    Любые ошибки сети/таймауты, где статуса нет, вернут False.
    """
    try:
        n = int(str(code))
        return 100 <= n <= 599
    except Exception:
        return False

def _row_has_response(row) -> bool:
    """
    Ожидаемый формат строки:
      [0 Target, 1 Product, 2 Version, 3 Vendor, 4 Confidence, 5 HTTP, 6 Server, 7 Title]
    Показываем только те строки, где есть валидный HTTP-код.
    """
    try:
        return len(row) > 5 and _is_http_ok(row[5])
    except Exception:
        return False


def fmt_table(rows, headers, colorize=None):
    """
    Рендер статической таблицы для консоли.
    Теперь скрывает все строки без HTTP-ответа.
    """
    # фильтрация "живых" строк
    rows = [r for r in (rows or []) if _row_has_response(r)]

    # compute widths on visible (ANSI-stripped) text
    widths = []
    for i, h in enumerate(headers):
        col_vals = [strip_ansi(r[i]) for r in rows] if rows else []
        w = max(len(strip_ansi(h)), *(len(str(v)) for v in col_vals)) if col_vals else len(strip_ansi(h))
        widths.append(min(60, w))

    def cut_raw(s, w):
        s = str(s)
        return s if len(s) <= w else s[:w-1] + "…"

    sep = "+".join("-"*(w+2) for w in widths)
    out = [sep]

    # Header (colorize if provided for -1 index)
    hdr_cells = []
    for i, h in enumerate(headers):
        cell = cut_raw(h, widths[i])
        if colorize:
            cell = colorize(-1, h, cell)
        hdr_cells.append(cell + ' ' * max(0, widths[i] - display_width(cell)))
    out.append("| " + " | ".join(hdr_cells) + " |")
    out.append(sep)

    for r in rows:
        cells = []
        for i in range(len(headers)):
            raw = r[i] if i < len(r) else ""
            cell = cut_raw(raw, widths[i])
            if colorize:
                cell = colorize(i, raw, cell)
            cells.append(cell + ' ' * max(0, widths[i] - display_width(cell)))
        out.append("| " + " | ".join(cells) + " |")
    out.append(sep)
    return "\n".join(out)

# --- Live rendering helpers ---
ANSI = {
    "reset":"\x1b[0m","bold":"\x1b[1m",
    "green":"\x1b[32m","yellow":"\x1b[33m","red":"\x1b[31m",
    "cyan":"\x1b[36m","magenta":"\x1b[35m","dim":"\x1b[2m",
    "blue":"\x1b[34m","gray":"\x1b[90m"
}

def colorize_factory(use_color):
    def colorize(col_idx, raw, cell):
        if not use_color:
            return cell
        # header
        if col_idx == -1:
            return f"{ANSI['magenta']}{ANSI['bold']}{cell}{ANSI['reset']}"
        # columns: 0 Target, 1 Product, 2 Version, 3 Vendor, 4 Confidence, 5 HTTP, 6 Server, 7 Title
        if col_idx == 1:  # Product
            return f"{ANSI['cyan']}{cell}{ANSI['reset']}"
        if col_idx == 2:  # Version
            if str(raw).lower().startswith("version not detected") or raw in ("-", "", None):
                return f"{ANSI['gray']}{cell}{ANSI['reset']}"
            return f"{ANSI['green']}{cell}{ANSI['reset']}"
        if col_idx == 5:  # HTTP code
            try:
                code = int(str(raw))
                if 200 <= code < 300:
                    c = 'green'
                elif 300 <= code < 400:
                    c = 'yellow'
                else:
                    c = 'red'
                return f"{ANSI[c]}{cell}{ANSI['reset']}"
            except:
                return cell
        return cell
    return colorize


def render_progress_line(done, total, use_color):
    # NetExec-style one-liner: "Running ForgeScan against N targets ━━━ 100% (x/x)"
    import shutil
    termw = shutil.get_terminal_size(fallback=(100, 20)).columns
    pct = int((done/total)*100) if total else 0
    prefix = f"Running ForgeScan against {total} targets "
    # Reserve suffix length like " 100% (xxx/yyy)"
    suffix = f" {pct:3d}% ({done}/{total})"
    bar_space = max(0, termw - len(prefix) - len(suffix) - 2)
    filled = int((pct/100)*bar_space) if bar_space>0 else 0
    bar = "━"*filled + " "*(bar_space - filled)
    line = f"{prefix}{bar}{suffix}"
    if use_color and filled>0:
        bar_col = f"{ANSI['cyan']}{'━'*filled}{ANSI['reset']}{' '*(bar_space - filled)}"
        line = f"{prefix}{bar_col}{suffix}"
    return line



# --- Incremental live printer (no full table redraw, no console clear) ---

class _LivePrinter:
    def __init__(self):
        self.header_printed = False
        self.printed_rows = 0
        self.col_widths = None
        self.headers = None
        self.use_color = False
        self.progress_printed = False  # whether a progress line currently sits at the bottom

    def _strip_ansi(self, s: str) -> str:
        return strip_ansi(s)

    def _visible_len(self, s: str) -> int:
        return len(self._strip_ansi(s))

    def _compute_widths(self, headers):
        base = [38, 16, 18, 20, 10, 4, 18, 28]
        return [max(b, self._visible_len(h)) for b, h in zip(base, headers)]

    def _fmt_row(self, row):
        cells = []
        for v, w in zip(row, self.col_widths):
            s_raw = v
            s = s_raw if self._visible_len(s_raw) <= w else s_raw[:max(0, w-1)] + "…"
            pad = w - self._visible_len(s)
            cells.append(s + (" " * pad))
        return "| " + " | ".join(cells) + " |"

    def _sep_line(self):
        parts = []
        for w in self.col_widths:
            parts.append("-" * (w + 2))
        return "+".join([""] + parts + [""])

    def ensure_header(self, headers, use_color, total):
        if not self.header_printed:
            self.use_color = use_color
            self.headers = headers
            self.col_widths = self._compute_widths(headers)
            sep = self._sep_line()
            sys.stdout.write(sep + "\n")
            sys.stdout.write(self._fmt_row(headers) + "\n")
            sys.stdout.write(sep + "\n")
            sys.stdout.flush()
            # Immediately render an initial progress line beneath the header
            sys.stdout.write(render_progress_line(0, total, self.use_color))  # dummy denominator to draw the bar
            sys.stdout.flush()
            self.progress_printed = True
            self.header_printed = True

    def append_rows(self, new_rows, done, total):
        if not new_rows:
            # still update progress
            self.update_progress(done, total)
            return
        # Move cursor up 1 line to overwrite the previous progress line (if we printed it)
        if self.progress_printed:
            sys.stdout.write("\r\x1b[2K")   # clear current line (progress)
        for r in new_rows:
            sys.stdout.write(self._fmt_row(r) + "\n")
        # After printing rows, write the progress line again
        sys.stdout.write(render_progress_line(done, total, self.use_color))
        sys.stdout.flush()
        self.progress_printed = True

    def update_progress(self, done, total):
        # Overwrite the existing progress line in-place
        if not self.progress_printed:
            sys.stdout.write(render_progress_line(done, total, self.use_color))
            sys.stdout.flush()
            self.progress_printed = True
            return
        sys.stdout.write("\r\x1b[2K")   # clear progress line in-place
        sys.stdout.write(render_progress_line(done, total, self.use_color))
        sys.stdout.flush()
        if done == total:
            # finalize with newline so subsequent prints don't clobber the bar
            sys.stdout.write("\n")
            sys.stdout.flush()

_live_printer = _LivePrinter()

def render_live_table(rows, headers, done, total, use_color, tail_hint=None):
    """
    Инкрементальный рендер без полного перерисовывания.
    Теперь выводит только строки с валидным HTTP-статусом.
    """
    colorize = colorize_factory(use_color)

    # оставляем только "живые" строки
    rows = [r for r in (rows or []) if _row_has_response(r)]

    def _display(r):
        # защита от коротких строк
        c = (list(r) + [""]*8)[:8]
        return [
            c[0],                               # Target
            colorize(1, c[1], c[1]),            # Product
            colorize(2, c[2], c[2]),            # Version
            c[3],                               # Vendor
            colorize(4, c[4], str(c[4])),       # Confidence
            colorize(5, c[5], c[5]),            # HTTP
            c[6],                               # Server
            c[7],                               # Title
        ]

    display_rows = [ _display(r) for r in rows ]

    # Ensure header printed
    _live_printer.ensure_header(headers, use_color, total)

    # Append only the new rows since last call
    to_print = display_rows[_live_printer.printed_rows:]
    _live_printer.append_rows(to_print, done, total)
    _live_printer.printed_rows = len(display_rows)



def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_csv(path, rows, headers):
    """
    CSV-экспорт. Скрывает строки без HTTP-ответа.
    """
    import csv
    rows = [r for r in (rows or []) if _row_has_response(r)]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            # выравниваем длину строки под заголовки
            out = [(r[i] if i < len(r) else "") for i in range(len(headers))]
            w.writerow(out)


def render_md(rows, headers):
    """
    Markdown-таблица. Скрывает строки без HTTP-ответа.
    """
    rows = [r for r in (rows or []) if _row_has_response(r)]
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    for r in rows:
        cells = []
        for i in range(len(headers)):
            v = r[i] if i < len(r) else ""
            cells.append(str(v).replace("\n", " "))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _split_csv_ports(s: str):
    """
    Парсит аргумент -p:
      - 'top'  -> список TOP_WEB_PORTS
      - 'all'  -> порты 1..65535  (ОСТОРОЖНО: очень много целей)
      - CSV    -> '80,443,8080' и т.п.
    Возвращает List[int].
    """
    if not s:
        return []
    val = str(s).strip().lower()
    if val == "top":
        return list(TOP_WEB_PORTS)
    if val == "all":
        # Предупреждение: породит 65535*2 URL'ов (и больше, если много хостов)
        return list(range(1, 65536))

    out = []
    seen = set()
    for chunk in s.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            v = int(chunk)
            if 1 <= v <= 65535 and v not in seen:
                out.append(v)
                seen.add(v)
        except Exception:
            # игнорируем мусор
            pass
    return out



def expand_cli_targets(items):
    """
    items: list[str] from -t/--targets (IPs/hosts and/or CIDR).
    Returns list[str] of hosts (without scheme).
    """
    out = []
    for it in (items or []):
        it = it.strip()
        if not it:
            continue
        # CIDR?
        try:
            net = ipaddress.ip_network(it, strict=False)
            # for /32 include the single address; for larger — only hosts()
            if net.prefixlen >= (32 if net.version == 4 else 128):
                out.append(str(net.network_address))
            else:
                for ip in net.hosts():
                    out.append(str(ip))
            continue
        except Exception:
            pass
        # plain IP or hostname
        out.append(it)
    return out


# -------- Findings summary helpers --------
def build_findings(rows):
    """
    Собирает сводку найденных продуктов только по целям, давшим HTTP-ответ.
    rows: list of [url, name, version, vendor, conf, status, server, title]
    returns dict: {product: [(url, version), ...]}
    """
    grouped = {}
    for r in (rows or []):
        if not _row_has_response(r):
            continue
        product = (r[1] or "").strip() if len(r) > 1 else ""
        if not product or product == "-":
            continue
        url = r[0] if len(r) > 0 else ""
        version = r[2] if len(r) > 2 and r[2] not in (None, "", "-") else "version not detected"
        grouped.setdefault(product, [])
        # Avoid duplicates for same URL within product
        if url and url not in [u for u, _ in grouped[product]]:
            grouped[product].append((url, version))
    # Sort by count desc, then name asc
    return dict(sorted(grouped.items(), key=lambda kv: (-len(kv[1]), kv[0].lower())))


def findings_to_markdown(findings):
    if not findings:
        return ""
    out = ["\n## Findings\n"]
    for product, items in findings.items():
        out.append(f"**{product} ({len(items)}):**\n")
        for url, ver in items:
            vdisp = ver if ver and ver != "version not detected" else "_version not detected_"
            out.append(f"- `{url}` — **{vdisp}**")
        out.append("")  # blank line
    return "\n".join(out)

def findings_to_json(findings):
    arr = []
    for product, items in findings.items():
        arr.append({
            "product": product,
            "count": len(items),
            "items": [{"url": u, "version": v} for u, v in items]
        })
    return {"by_product": arr}

# ---------------- CVE enrichment (NVD 2.0) ----------------

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Map our product labels -> list of (vendor, product) candidates (CPE 2.3 'a' part)
CPE_MAP = {
    "Adminer": [("adminer","adminer")],
    "phpMyAdmin": [("phpmyadmin","phpmyadmin")],
    "Apache Tomcat": [("apache","tomcat")],
    "Magento": [("magento","magento"), ("adobe","magento")],
    "Atlassian Jira": [("atlassian","jira"), ("atlassian","jira_software"), ("atlassian","jira_core")],
    "GitLab": [("gitlab","gitlab")],
    "Kibana": [("elastic","kibana")],
    "Zabbix": [("zabbix","zabbix")],
    "Microsoft Exchange Server": [("microsoft","exchange_server")],
    "Outlook Web App": [("microsoft","exchange_server"),("microsoft","outlook_web_access")],
    "WordPress": [("wordpress","wordpress")],
    "Joomla!": [("joomla","joomla")],
    "Grafana": [("grafana","grafana")],
    "Fortinet FortiGate": [("fortinet","fortios"), ("fortinet","fortigate")],
    "Jenkins": [("jenkins","jenkins")],
    "Nexus Repository Manager": [("sonatype","nexus_repository_manager")],
    "JFrog Artifactory": [("jfrog","artifactory")],
    "Harbor": [("vmware","harbor"), ("goharbor","harbor")],
    "Argo CD": [("argoproj","argo_cd"), ("argoproj","argo")],
    "Elasticsearch": [("elastic","elasticsearch")],
    "Prometheus": [("prometheus","prometheus")],
    "Alertmanager": [("prometheus","alertmanager")],
    "Cisco ASA": [("cisco","adaptive_security_appliance")],
    "pfSense": [("netgate","pfsense")],
    "Sophos UTM": [("sophos","utm"),("sophos","xg_firewall")],
    "Citrix ADC (NetScaler)": [("citrix","application_delivery_controller"), ("citrix","netscaler")],
    "MinIO": [("minio","minio")],
    "Ceph": [("ceph","ceph")],
    "NGINX": [("f5","nginx"),("nginx","nginx")],
    "HAProxy": [("haproxy_technologies","haproxy")],
    "VMware vCenter": [("vmware","vcenter_server")],
    "VMware ESXi": [("vmware","esxi")],
    "Gitea": [("gitea","gitea")],
    "SonarQube": [("sonarsource","sonarqube")],
    "Nextcloud": [("nextcloud","nextcloud_server"), ("nextcloud","nextcloud")],
    "ownCloud": [("owncloud","owncloud_server"), ("owncloud","owncloud")],
    "Roundcube Webmail": [("roundcube","roundcube_webmail"), ("roundcube","roundcube")],
    "osTicket": [("osticket","osticket")],
    "GLPI": [("teclib","glpi")],
    "Centreon": [("centreon","centreon")],
    "Cacti": [("cacti","cacti")],
    "Netdata": [("netdata","netdata")],
    "NetBox": [("netbox","netbox")],
    "Portainer": [("portainer","portainer")],
    "Proxmox VE": [("proxmox","proxmox_virtual_environment")],
    "TrueNAS": [("ixsystems","truenas")],
    "OpenMediaVault": [("openmediavault","openmediavault")],
    "Synology DSM": [("synology","diskstation_manager")],
    "QNAP QTS": [("qnap","qts")],
    "Bitbucket Server": [("atlassian","bitbucket_server"), ("atlassian","bitbucket")],
    "Gogs": [("gogs","gogs")],
    "Forgejo": [("forgejo","forgejo")],
    "TeamCity": [("jetbrains","teamcity")],
    "Bamboo": [("atlassian","bamboo")],
    "Apache Guacamole": [("apache","guacamole")],
    "Ubiquiti UniFi Network": [("ui","unifi_network_application"), ("ubiquiti","unifi")],
    "MikroTik RouterOS": [("mikrotik","routeros")],
}

def _norm_ver(v: str) -> str:
    v = (v or "").strip()
    v = v.rstrip(".")
    # sometimes WordPress etc may have absurd numeric "build timestamps"; leave as is
    return v

def _split_ver(v: str):
    v = _norm_ver(v)
    if not v:
        return ()
    # keep numeric parts; if non-numeric, try to split by non-digits and keep numbers
    parts = re.split(r"[^0-9]+", v)
    nums = tuple(int(p) for p in parts if p.isdigit())
    return nums

def _cmp_ver(a: str, b: str) -> int:
    A, B = _split_ver(a), _split_ver(b)
    if not A and not B:
        return 0
    if not A:
        return -1
    if not B:
        return 1
    # pad to same length
    m = max(len(A), len(B))
    A += (0,) * (m - len(A))
    B += (0,) * (m - len(B))
    if A < B: return -1
    if A > B: return 1
    return 0

def _exchange_track_from_build(v: str):
    """
    По билду Exchange (например, '14.3.513.0' или '15.02.1234.5') возвращает трек:
    '2007' | '2010' | '2013' | '2016' | '2019' | None
    """
    nums = _split_ver(v)
    if len(nums) < 1:
        return None
    major = nums[0]
    minor = nums[1] if len(nums) >= 2 else 0
    if major == 8:
        return "2007"
    if major == 14:
        return "2010"
    if major == 15:
        if minor >= 2:
            return "2019"
        if minor == 1:
            return "2016"
        if minor == 0:
            return "2013"
    return None

def _exchange_track_from_bound(s: str):
    """
    По строке из границы CPE (например, '15.02.2562.020' или '2019')
    возвращает трек Exchange: '2010'/'2013'/'2016'/'2019'/... либо None.
    """
    if not s:
        return None
    s = str(s).strip()
    # В некоторых CPE version — это просто год ('2019', '2016' и т.п.)
    if re.fullmatch(r"\d{4}", s):
        return s
    nums = _split_ver(s)
    if len(nums) < 1:
        return None
    major = nums[0]
    minor = nums[1] if len(nums) >= 2 else 0
    if major == 8:
        return "2007"
    if major == 14:
        return "2010"
    if major == 15:
        if minor >= 2:
            return "2019"
        if minor == 1:
            return "2016"
        if minor == 0:
            return "2013"
    return None


def _ver_in_range(ver, start_inc=None, start_exc=None, end_inc=None, end_exc=None, exact=None):
    """
    Возвращает True, если версия `ver` попадает в указанные границы/точное совпадение.
    ВАЖНОЕ ИЗМЕНЕНИЕ: если НЕТ НИ ОДНОЙ ГРАНИЦЫ И НЕТ exact (т.е. CPE '...:version:*:...'),
    мы считаем такой диапазон НЕИНФОРМАТИВНЫМ и возвращаем False (чтобы отсечь «шумные» CVE).
    """
    ver = _norm_ver(ver)

    # Если нет НИ одного ограничения — считаем, что диапазон неинформативен → не матчим
    has_constraint = bool(
        (exact is not None and exact != "*") or
        start_inc or start_exc or end_inc or end_exc
    )
    if not has_constraint:
        return False

    if exact and exact != "*" and _cmp_ver(ver, exact) != 0:
        return False
    if start_inc and _cmp_ver(ver, start_inc) < 0:
        return False
    if start_exc and _cmp_ver(ver, start_exc) <= 0:
        return False
    if end_inc and _cmp_ver(ver, end_inc) > 0:
        return False
    if end_exc and _cmp_ver(ver, end_exc) >= 0:
        return False
    return True


def _format_range(start_inc=None, start_exc=None, end_inc=None, end_exc=None, exact=None):
    if exact and exact != "*":
        return f"== {exact}"
    bounds = []
    if start_inc:
        bounds.append(f">= {start_inc}")
    if start_exc:
        bounds.append(f"> {start_exc}")
    if end_inc:
        bounds.append(f"<= {end_inc}")
    if end_exc:
        bounds.append(f"< {end_exc}")
    return " and ".join(bounds) if bounds else "(unspecified)"

async def nvd_fetch_all(session, vendor, product, api_key=None, timeout=25):
    """
    Fetch all CVEs for vendor/product using virtualMatchString wildcard CPE.
    Returns list of vulnerability items (raw NVD objects).
    """
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    vulns = []
    start_idx = 0
    results_per_page = 2000
    vms = f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*"
    params_base = {
        "virtualMatchString": vms,
        "resultsPerPage": str(results_per_page),
        "startIndex": str(start_idx),
    }
    while True:
        params = dict(params_base)
        params["startIndex"] = str(start_idx)
        url = NVD_BASE + "?" + "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
        try:
            async with session.get(url, headers=headers, timeout=timeout) as r:
                if r.status == 404:
                    # no results for this vms; break
                    return vulns
                if r.status >= 400:
                    print(f"[!] NVD query failed ({r.status}) for params={{'virtualMatchString': '{vms}'}}")
                    return vulns
                data = await r.json(content_type=None)
        except Exception as e:
            print(f"[!] NVD query error for {vendor}:{product}: {e}")
            return vulns
        arr = data.get("vulnerabilities") or []
        if not isinstance(arr, list):
            arr = []
        vulns.extend(arr)
        total = int(data.get("totalResults") or 0)
        start_idx += results_per_page
        if start_idx >= total or not arr:
            break
        # be gentle
        await asyncio.sleep(0.2)
    return vulns

def _extract_metrics(cve_obj):
    """
    Returns (score, severity, privilegesRequired, userInteraction, attackVector)
    Prefers CVSS v3.1 -> v3.0 -> v2 (PR/UI/AV only for v3.* if present).
    """
    cve = cve_obj.get("cve", {})
    metrics = cve.get("metrics", {})
    score = None; severity = None; pr = None; ui = None; av = None

    def pick_v3(arr_name):
        nonlocal score, severity, pr, ui, av
        arr = metrics.get(arr_name) or []
        if not arr:
            return False
        m = arr[0]  # take the first
        data = m.get("cvssData", {})
        score = data.get("baseScore", m.get("cvssData", {}).get("baseScore"))
        severity = m.get("baseSeverity", m.get("baseSeverity"))
        pr = data.get("privilegesRequired")
        ui = data.get("userInteraction")
        av = data.get("attackVector")
        return True

    if pick_v3("cvssMetricV31"):
        return score, severity, pr, ui, av
    if pick_v3("cvssMetricV30"):
        return score, severity, pr, ui, av

    # CVSS v2 fallback
    arr2 = metrics.get("cvssMetricV2") or []
    if arr2:
        m = arr2[0]
        score = (m.get("cvssData") or {}).get("baseScore")
        severity = m.get("baseSeverity")
    return score, severity, pr, ui, av

def _extract_cve_title(cve_obj):
    cve = cve_obj.get("cve", {})
    titles = cve.get("titles") or []
    for t in titles:
        if t.get("lang") == "en" and t.get("title"):
            return t["title"].strip()
    # fallback: короткая выжимка из описания
    descs = cve.get("descriptions") or []
    for d in descs:
        if d.get("lang") == "en" and d.get("value"):
            txt = d["value"].strip()
            # первые 120 символов без перевода строки
            txt = re.sub(r"\s+", " ", txt)[:120]
            return txt
    return ""

def _poc_links_from_nvd(cve_obj):
    """
    Собираем ссылки на PoC/эксплойты из NVD (cve.references).
    Берём те, у которых теги содержат Exploit / Proof of Concept,
    либо очевидные домены (github, exploit-db, packetstorm, seclists и т.д.).
    Возвращаем список словарей: {"source": "...", "url": "..."}.
    """
    out = []
    cve = cve_obj.get("cve", {})
    refs = cve.get("references") or []
    # NVD 2.0: каждый ref: {"url": "...", "source": "...", "tags": [...]}
    for ref in refs:
        url = (ref.get("url") or "").strip()
        if not url:
            continue
        tags = [str(t).lower() for t in (ref.get("tags") or [])]
        host = ""
        try:
            from urllib.parse import urlparse
            host = (urlparse(url).netloc or "").lower()
        except Exception:
            pass
        good_domain = any(d in host for d in [
            "github.com", "gitlab.com", "gist.github.com",
            "exploit-db.com", "packetstormsecurity.com",
            "seclists.org", "ssd-disclosure", "huntr.dev",
            "projectdiscovery.io", "nuclei-templates"
        ])
        has_tag = any(t in tags for t in ["exploit", "proof of concept", "poc"])
        if has_tag or good_domain:
            label = ref.get("source") or host or "reference"
            out.append({"source": label, "url": url})
    # dedup по URL
    seen = set(); dedup = []
    for it in out:
        if it["url"] in seen:
            continue
        seen.add(it["url"])
        dedup.append(it)
    return dedup


def _search_links_for_cve(cve_id: str):
    """
    «Умные» поисковые ссылки — всегда безопасный fallback,
    даже если прямых PoC не нашли.
    """
    cid = (cve_id or "").strip()
    if not cid:
        return []
    return [
        {"source": "GitHub search", "url": f"https://github.com/search?q={cid}"},
        {"source": "Exploit-DB search", "url": f"https://www.exploit-db.com/search?cve={cid}"},
        {"source": "Packet Storm search", "url": f"https://packetstormsecurity.com/search/?q={cid}"},
        {"source": "Nuclei templates", "url": f"https://github.com/search?q={cid}+repo:projectdiscovery/nuclei-templates"},
    ]


def _is_cve_unauth(cve_obj):
    """
    Грубая, но практичная эвристика:
    - ключевые слова в описании: unauthenticated, pre-auth, without authentication и т.п.
    - CVSS v3.* с PrivilegesRequired == NONE (часто «pre-auth»)
    """
    # словари
    kw = [
        r"unauthenticated", r"pre[-\s]?auth", r"without authentication",
        r"no authentication required", r"no auth required", r"preauthentication",
        r"pre authentication", r"before authentication"
    ]
    cve = cve_obj.get("cve", {})
    descs = cve.get("descriptions") or []
    text = " ".join([d.get("value","") for d in descs]).lower()
    if any(re.search(k, text, re.I) for k in kw):
        return True

    score, severity, pr, ui, av = _extract_metrics(cve_obj)
    if (pr or "").upper() == "NONE":
        return True
    return False


def _cpe_version_from_criteria(criteria: str) -> str:
    # cpe:2.3:a:vendor:product:version:update:...
    try:
        parts = criteria.split(":")
        if len(parts) >= 6:
            return parts[5]
    except Exception:
        pass
    return "*"

def _iter_cpe_ranges(cve_obj, wanted_vendor_product=None):
    """
    Yield tuples of version range dicts for each vulnerable cpeMatch.
    Each item: (vendor, product, exact, start_inc, start_exc, end_inc, end_exc)
    """
    cve = cve_obj.get("cve", {})
    configs = cve.get("configurations") or []
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                crit = match.get("criteria", "")
                # filter by vendor/product if asked
                if wanted_vendor_product:
                    try:
                        parts = crit.split(":")
                        if len(parts) >= 5:
                            vndr, prod = parts[3], parts[4]
                            if (vndr, prod) not in wanted_vendor_product:
                                continue
                    except Exception:
                        pass
                exact = _cpe_version_from_criteria(crit)
                yield (
                    crit.split(":")[3] if len(crit.split(":"))>4 else None, # vendor
                    crit.split(":")[4] if len(crit.split(":"))>5 else None, # product
                    match.get("versionStartIncluding"),
                    match.get("versionStartExcluding"),
                    match.get("versionEndIncluding"),
                    match.get("versionEndExcluding"),
                    exact
                )

def filter_cves_for_version(vulns, product_version, vendors_products):
    """
    Возвращает список словарей:
      { id, title, published, score, severity, affected, description, unauth, poc:[{source,url},...] }

    Правила:
    - Берём только CPE-правила с явными ограничителями (точная версия или start/end):
      записи с 'version:*' и без границ отсеиваются (_ver_in_range это делает).
    - Для Microsoft Exchange дополнительно сверяем «линию»:
        14.x → 2010, 15.00 → 2013, 15.01 → 2016, 15.02 → 2019.
      Если у правила линейка другая — отбрасываем.
    - Если правило задаёт ТОЛЬКО линейку (exact='2010') без числовых границ —
      считаем совпадением, если линейки равны.
    """
    out = []
    pv = _norm_ver(product_version)
    my_exch_track = _exchange_track_from_build(pv)  # None для не-Exchange или если формат странный

    for v in (vulns or []):
        cve_id = (v.get("cve") or {}).get("id")
        published = (v.get("cve") or {}).get("published")

        # Заголовок/описание
        descs = ((v.get("cve") or {}).get("descriptions") or [])
        description = ""
        for d in descs:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        title = _extract_cve_title(v)
        score, severity, pr, ui, av = _extract_metrics(v)

        matched = False
        best_range = None

        for (vendor, product, start_inc, start_exc, end_inc, end_exc, exact) in _iter_cpe_ranges(v, vendors_products):
            is_exchange = (vendor == "microsoft" and product == "exchange_server")

            # --- Спец-логика по линейке для Exchange ---
            if is_exchange and my_exch_track:
                # Если любые границы/точная версия указывают на конкретную линейку, и она отлична от нашей — отбрасываем
                possible_tracks = set(
                    t for t in [
                        _exchange_track_from_bound(start_inc),
                        _exchange_track_from_bound(start_exc),
                        _exchange_track_from_bound(end_inc),
                        _exchange_track_from_bound(end_exc),
                        _exchange_track_from_bound(exact),
                    ] if t
                )
                if possible_tracks and (my_exch_track not in possible_tracks):
                    continue

                # Если exact — это ГОД (линейка), и нет других числовых ограничений → матч по линейке
                exact_is_track = bool(_exchange_track_from_bound(exact))
                has_numeric_bounds = any(
                    s and bool(re.search(r"\d+\.\d+", str(s)))
                    for s in (start_inc, start_exc, end_inc, end_exc)
                )
                if exact_is_track and not has_numeric_bounds:
                    if _exchange_track_from_bound(exact) == my_exch_track:
                        matched = True
                        best_range = (None, None, None, None, exact)
                        # Т.к. это «чистая линейка», можно не искать дальше
                        break
                    else:
                        continue  # другой трек

                # Иначе — проверяем обычным числовым сравнением, НО exact-трек не передаём как exact,
                # чтобы не требовать «14.x == 2010»
                exact_for_range = None if exact_is_track else (exact if exact and exact != "*" else None)
                if _ver_in_range(pv, start_inc, start_exc, end_inc, end_exc, exact_for_range):
                    matched = True
                    best_range = (start_inc, start_exc, end_inc, end_exc, exact)
                    # Если диапазон ограничен с обеих сторон — хватит
                    if (end_inc or end_exc) and (start_inc or start_exc):
                        break
                # иначе продолжаем перебирать другие cpeMatch
                continue

            # --- Обычные продукты (без спец-логики линейки) ---
            if _ver_in_range(pv, start_inc, start_exc, end_inc, end_exc, (exact if exact and exact != "*" else None)):
                matched = True
                best_range = (start_inc, start_exc, end_inc, end_exc, exact)
                if (end_inc or end_exc) and (start_inc or start_exc):
                    break

        if not matched:
            continue

        rng = _format_range(
            start_inc=best_range[0],
            start_exc=best_range[1],
            end_inc=best_range[2],
            end_exc=best_range[3],
            exact=(best_range[4] if best_range[4] and best_range[4] != "*" else None)
        )

        # PoC/эксплойты
        poc_links = _poc_links_from_nvd(v)
        poc_links.extend(_search_links_for_cve(cve_id))
        # dedup
        seen = set(); poc_final = []
        for it in poc_links:
            u = it.get("url")
            if not u or u in seen:
                continue
            seen.add(u)
            poc_final.append({"source": it.get("source") or "link", "url": u})

        out.append({
            "id": cve_id,
            "title": title,
            "published": published,
            "score": score,
            "severity": severity,
            "affected": rng,
            "description": description,
            "unauth": _is_cve_unauth(v),
            "poc": poc_final
        })

    def _safe_date(s):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    out.sort(key=lambda x: (_safe_date(x["published"]), x["score"] or 0.0), reverse=True)
    return out


async def enrich_cves(findings, args):
    """
    findings: {product: [(url, version), ...]}
    Returns: dict {
        "by_product_version": [
           {"product":"Apache Tomcat","version":"9.0.20","targets":[url...],
            "cves":[{id, published, score, severity, affected, description}, ...]}
        ]
    }
    """
    # Build target versions per product (skip unknown version)
    wanted = {}
    for product, items in findings.items():
        for url, ver in items:
            if ver and ver != "version not detected" and ver != "-":
                wanted.setdefault(product, {})
                wanted[product].setdefault(ver, set()).add(url)

    if not wanted:
        return {"by_product_version": []}

    # Fetch CVEs per product (union of vendors/products from map)
    results = []
    timeout = args.cve_timeout
    api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY") or None
    cve_conc = max(1, args.cve_concurrency)

    async def worker(prod, versions_dict):
        vp_list = CPE_MAP.get(prod, [])
        if not vp_list:
            return (prod, versions_dict, [])
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers={"User-Agent": DEFAULT_USER_AGENT}) as sess:
            if api_key:
                sess.headers.update({"apiKey": api_key})
            all_vulns = []
            # sequential per (vendor,product) to avoid API hammering
            for vendor, product in vp_list:
                vulns = await nvd_fetch_all(sess, vendor, product, api_key=api_key, timeout=timeout)
                all_vulns.extend(vulns)
            # dedup by cve id
            seen = set()
            dedup = []
            for v in all_vulns:
                cid = (v.get("cve") or {}).get("id")
                if cid and cid not in seen:
                    seen.add(cid); dedup.append(v)
        return (prod, versions_dict, dedup)

    # Run with bounded concurrency across products
    sem = asyncio.Semaphore(cve_conc)
    async def limited(prod, vers):
        async with sem:
            return await worker(prod, vers)

    tasks = [limited(p, v) for p, v in wanted.items()]
    fetched = await asyncio.gather(*tasks)

    # For each product version, filter relevant CVEs and attach
    out = []
    for prod, versions_dict, vulns in fetched:
        vp_candidates = CPE_MAP.get(prod, [])
        for ver, urls in versions_dict.items():
            filtered = filter_cves_for_version(vulns, ver, vp_candidates)
            # if max-per set (>0), trim
            max_per = args.cve_max_per
            if max_per and max_per > 0:
                filtered = filtered[:max_per]
            out.append({
                "product": prod,
                "version": ver,
                "targets": sorted(urls),
                "cves": filtered
            })
    # sort nicely by product then version
    out.sort(key=lambda x: (x["product"].lower(), _split_ver(x["version"])))
    return {"by_product_version": out}

# -------- CVE rendering --------

def print_cves_console(cve_summary, use_color=True):
    arr = cve_summary.get("by_product_version", [])
    if not arr:
        return

    # локальные ANSI (не меняем глобальный словарь, чтобы не ломать ничего)
    A = {
        "reset":"\x1b[0m","bold":"\x1b[1m",
        "green":"\x1b[32m","yellow":"\x1b[33m","red":"\x1b[31m",
        "cyan":"\x1b[36m","magenta":"\x1b[35m","gray":"\x1b[90m",
        "bg_yellow":"\x1b[43m"
    } if use_color else {k:"" for k in ["reset","bold","green","yellow","red","cyan","magenta","gray","bg_yellow"]}

    def style_cvss(score, severity):
        sev = (severity or "").upper()
        score_s = "-" if score is None else f"{score:.1f}"
        label = f"CVSS {score_s} {severity or '-'}"
        if score is not None and score >= 8.8:
            return f"{A['bold']}{A['red']}{label}{A['reset']}"
        if sev == "CRITICAL":
            return f"{A['bold']}{A['red']}{label}{A['reset']}"
        if sev == "HIGH":
            return f"{A['red']}{label}{A['reset']}"
        if sev == "MEDIUM":
            return f"{A['yellow']}{label}{A['reset']}"
        if sev == "LOW":
            return f"{A['green']}{label}{A['reset']}"
        return f"{A['gray']}{label}{A['reset']}"

    print("\n" + (f"{A['magenta']}{A['bold']}CVE{A['reset']}" if use_color else "CVE") + ":")

    by_prod = {}
    for item in arr:
        by_prod.setdefault(item["product"], []).append(item)

    for prod, items in by_prod.items():
        title = f"{prod}:"
        if use_color:
            title = f"{A['cyan']}{A['bold']}{prod}{A['reset']}:"
        print(title)
        items.sort(key=lambda x: _split_ver(x["version"]))
        for it in items:
            ver = it["version"]; cves = it["cves"]; urls = it["targets"]
            print(f"  {ver} ({len(cves)}):")
            for cv in cves:
                left = f"{cv['id']}"
                if cv.get("title"):
                    left += f" — {cv['title']}"
                right = style_cvss(cv.get("score"), cv.get("severity"))
                line = f"    • {left} — affected: {cv.get('affected') or '(unspecified)'} — {right}"
                if cv.get("unauth"):
                    # жёлтый фон + красный текст
                    line = f"{A['bg_yellow']}{A['red']}{line}{A['reset']}"
                print(line)
            if urls:
                print("    Targets:")
                for u in urls:
                    print(f"      - {u}")


def cves_to_markdown(cve_summary):
    arr = cve_summary.get("by_product_version", [])
    if not arr:
        return ""
    sev_emoji = {
        "CRITICAL": "🛑",
        "HIGH": "🔴",
        "MEDIUM": "🟠",
        "LOW": "🟢",
        None: "⚪️"
    }
    out = ["\n## CVE\n"]
    by_prod = {}
    for item in arr:
        by_prod.setdefault(item["product"], []).append(item)
    for prod, items in by_prod.items():
        out.append(f"### {prod}")
        items.sort(key=lambda x: _split_ver(x["version"]))
        for it in items:
            ver = it["version"]; cves = it["cves"]; urls = it["targets"]
            out.append(f"- **{ver}** — {len(cves)} CVE")
            for cv in cves:
                sev = (cv.get("severity") or "").upper() or None
                emoji = sev_emoji.get(sev, "⚪️")
                score = cv.get("score")
                score_s = f"{score:.1f}" if isinstance(score,(int,float)) else "-"
                aff = cv.get("affected") or "(unspecified)"
                title = f" — {cv['title']}" if cv.get("title") else ""
                unauth = " — 🟡 **UNAUTH**" if cv.get("unauth") else ""
                out.append(f"  - {emoji} **{cv['id']}**{title} · affected: **{aff}** · CVSS **{score_s} {cv.get('severity','-')}**{unauth}")
            if urls:
                out.append("  - Targets:")
                for u in urls:
                    out.append(f"    - `{u}`")
        out.append("")
    return "\n".join(out)

def save_html_report(path, rows, findings, cve_summary, generated_at=None, scanner_version=None):
    # ✅ фильтруем строки: в отчёт идут только цели с валидным HTTP-ответом
    rows_alive = [r for r in (rows or []) if _row_has_response(r)]

    generated_at = generated_at or now_iso()
    scanner_version = scanner_version or __VERSION__

    # --- CVE: (Product, Version) -> список CVE (включая PoC ссылки) ---
    bypv = {}
    for item in cve_summary.get("by_product_version", []):
        key = f"{item.get('product','')}|||{item.get('version','')}"
        cves_norm = []
        for cv in item.get("cves", []):
            cves_norm.append({
                "id": cv.get("id"),
                "title": cv.get("title") or "",
                "score": cv.get("score"),
                "severity": cv.get("severity") or "",
                "affected": cv.get("affected") or "",
                "description": cv.get("description") or "",
                "unauth": bool(cv.get("unauth")),
                "published": cv.get("published") or "",
                "poc": list(cv.get("poc") or [])  # список словарей {source,url}
            })
        bypv[key] = cves_norm
    cve_enabled = bool(bypv)


    rows_json = json.dumps(rows_alive, ensure_ascii=False)
    cve_map_json = json.dumps(bypv, ensure_ascii=False)
    cve_enabled_js = "true" if cve_enabled else "false"

    def esc(s: str) -> str:
        return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    findings_html = (
        "".join(
            f'<button type="button" class="tag tag-btn" data-prod="{esc(p)}">{esc(p)} '
            f'<span class="mono">({len(v)})</span></button>'
            for p, v in findings.items()
        ) or '<span class="muted">No findings.</span>'
    )
    cve_th = '<th data-col="cve" data-k="8">CVE</th>' if cve_enabled else ""

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>ForgeScan Report</title>
<style>
  :root {{
    --bg: #0b1020; --card: rgba(255,255,255,0.08); --card-2: rgba(255,255,255,0.06);
    --text: #e7ecf3; --muted: #9fb0c8; --accent: #7cc7ff;
    --green: #4ade80; --yellow: #fde047; --red: #ef4444;
    --glass: rgba(255,255,255,0.1); --ring: rgba(124,199,255,0.35);
  }}
  html,body {{
    background: radial-gradient(1200px 800px at 10% -10%, #1a2a4a 0%, #0b1020 35%, #070b13 100%);
    color: var(--text); font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Inter, Arial; margin: 0;
  }}
  .wrap {{ width: min(1200px, 94%); margin: 32px auto; }}
  .hero {{
    padding: 20px; border-radius: 16px; background: var(--glass); backdrop-filter: blur(10px);
    box-shadow: 0 10px 40px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05);
    border: 1px solid rgba(255,255,255,.12);
  }}
  h1 {{ margin: 0 0 8px 0; font-size: 26px; letter-spacing:.2px }}
  .meta {{ color: var(--muted); font-size: 13px }}

  .card {{
    border-radius: 16px; padding: 14px; background: var(--card); border:1px solid rgba(255,255,255,.1);
    box-shadow: 0 6px 30px rgba(0,0,0,.3), inset 0 1px 0 rgba(255,255,255,.04);
  }}
  .block {{ margin-top: 14px; }}
  .toolbar {{ display:flex; gap:12px; align-items:center; flex-wrap:wrap; }}
  .search {{ flex:1 1 260px; min-width:0; position:relative; z-index:5; }}
  .search input {{
    width:100%; padding:10px 12px; border-radius:12px; background: var(--card-2); color:var(--text);
    border:1px solid rgba(255,255,255,.1); outline:none; position:relative; z-index:5;
  }}
  .tag {{
    display:inline-flex; align-items:center; gap:6px; padding:6px 10px; border-radius: 999px;
    background: var(--card-2); color: var(--muted); font-size:12px; margin:4px 6px 0 0; white-space:nowrap;
    border:1px solid rgba(255,255,255,.1);
  }}
  .tag-btn {{ cursor:pointer; transition: box-shadow .15s ease, transform .03s ease; }}
  .tag-btn:active {{ transform: translateY(1px) }}
  .tag-btn.active {{ box-shadow: 0 0 0 2px var(--ring) inset, 0 0 0 1px rgba(124,199,255,.55) inset; color:#cfeaff }}

  table {{ width:100%; border-collapse: collapse; font-size:14px; table-layout: fixed }}
  th,td {{ padding: 10px 8px; border-bottom:1px dashed rgba(255,255,255,.08); vertical-align: top }}
  th {{
    text-align:left; color: var(--muted); cursor:pointer; position:sticky; top:0;
    background:linear-gradient(180deg, rgba(11,16,32,.95), rgba(11,16,32,.65));
    backdrop-filter: blur(6px); z-index: 2;
  }}

  /* ширины */
  th[data-col="target"], td[data-col="target"] {{ width: 22%; }}
  th[data-col="product"], td[data-col="product"] {{ width: 13%; }}
  th[data-col="version"], td[data-col="version"] {{ width: 9%; }}
  th[data-col="vendor"], td[data-col="vendor"] {{ width: 10%; }}
  th[data-col="conf"], td[data-col="conf"] {{ width: 7%; }}
  th[data-col="http"], td[data-col="http"] {{ width: 7%; }}
  th[data-col="server"], td[data-col="server"] {{ width: 12%; }}
  th[data-col="title"], td[data-col="title"] {{ width: 12%; }}
  th[data-col="cve"], td[data-col="cve"] {{ width: 8%; }}

  @media (max-width: 900px) {{
    th[data-col="server"], td[data-col="server"] {{ display:none }}
    th[data-col="vendor"], td[data-col="vendor"] {{ display:none }}
  }}
  @media (max-width: 700px) {{
    th[data-col="title"], td[data-col="title"] {{ display:none }}
  }}

  tbody tr:hover {{ background: rgba(255,255,255,.04); }}
  .pill {{ display:inline-flex; padding:2px 8px; border-radius:999px; font-size:12px; border:1px solid rgba(255,255,255,.15) }}
  .ok {{ color: var(--green) }} .warn {{ color: var(--yellow) }} .bad {{ color: var(--red) }}
  .muted {{ color: var(--muted) }} .h2 {{ font-weight:600; margin:0 0 8px 0; font-size:18px }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; }}

  /* CVE раскрывашка + ссылки */
  .cve-btn {{ display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:10px;
    border:1px solid rgba(255,255,255,.18); background: var(--card-2); user-select:none; cursor:pointer; }}
  .cve-btn .carat {{ transition: transform .18s ease; display:inline-block }}
  .cve-btn.open .carat {{ transform: rotate(180deg) }}
  tr.cve-expand > td {{ padding: 0; background: rgba(255,255,255,.035) }}
  .cve-panel {{ padding: 12px 12px 14px 12px; }}
  .cve-table {{ width:100%; border-collapse: collapse; font-size:13px }}
  .cve-table th, .cve-table td {{ padding:8px 6px; border-bottom:1px dashed rgba(255,255,255,.08) }}
  .sev-critical {{ color: var(--red); font-weight:600 }}
  .sev-high {{ color: var(--red) }}
  .sev-medium {{ color: var(--yellow) }}
  .sev-low {{ color: var(--green) }}
  .badge-unauth {{
    display:inline-block; margin-left:6px; padding:2px 6px; border-radius:999px;
    background: rgba(253,224,71,.25); border:1px solid rgba(253,224,71,.5); color:#ff4d4d; font-size:11px
  }}
  details.cve-detail > summary {{ list-style:none; cursor:pointer; outline:none; }}
  details.cve-detail > summary::-webkit-details-marker {{ display:none; }}
  details.cve-detail[open] > summary .mini-carat {{ transform: rotate(90deg) }}
  .mini-carat {{ display:inline-block; width:0; height:0; border-top:5px solid transparent; border-bottom:5px solid transparent;
    border-left:6px solid var(--muted); margin-right:6px; transition: transform .18s ease }}
  .desc-box {{ margin-top:6px; padding:8px; background: var(--card-2); border:1px solid rgba(255,255,255,.12); border-radius:10px }}

  .poc-list {{ list-style:none; padding-left:0; margin:8px 0 0 0 }}
  .poc-list li {{ margin:6px 0 }}
  .poc-list a {{ color: var(--accent); text-decoration:none; border-bottom:1px dotted rgba(124,199,255,.4) }}
  .poc-list a:hover {{ border-bottom-color: transparent; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>ForgeScan Report</h1>
    <div class="meta">Generated <span class="mono">{generated_at}</span> · Scanner v{scanner_version}</div>
    <div class="meta">Rows: {len(rows)} · Products: {len(findings)}</div>
  </div>

  <div class="block card">
    <div class="h2">Findings</div>
    <div id="findings" class="tags">{findings_html}</div>
  </div>

  <div class="block card">
    <div class="toolbar">
      <div class="search"><input id="q" placeholder="Search in table (target, product, version, title)…"></div>
      <div class="tag">HTTP: <span id="stat-ok" class="ok">0</span></div>
      <div class="tag">3xx/4xx/5xx: <span id="stat-bad" class="bad">0</span></div>
    </div>

    <table id="tbl">
      <thead>
        <tr>
          <th data-col="target" data-k="0">Target</th>
          <th data-col="product" data-k="1">Product</th>
          <th data-col="version" data-k="2">Version</th>
          <th data-col="vendor" data-k="3">Vendor</th>
          <th data-col="conf" data-k="4">Confidence</th>
          <th data-col="http" data-k="5">HTTP</th>
          <th data-col="server" data-k="6">Server</th>
          <th data-col="title" data-k="7">Title</th>
          {cve_th}
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<script>
const ROWS = {rows_json};
const CVE_MAP = {cve_map_json};
const CVE_ENABLED = {cve_enabled_js};
const DATA = {{ rows: ROWS, cveMap: CVE_MAP, cveEnabled: CVE_ENABLED }};

function keyFor(row) {{
  const prod = (row[1]||"").trim();
  const ver  = (row[2]||"").trim();
  return prod + "|||" + ver;
}}
function getCves(row) {{
  if (!DATA.cveEnabled) return [];
  const key = keyFor(row);
  return DATA.cveMap[key] || [];
}}
function sevRank(sev) {{
  const s = (sev||"").toUpperCase();
  if (s === "CRITICAL") return 4;
  if (s === "HIGH") return 3;
  if (s === "MEDIUM") return 2;
  if (s === "LOW") return 1;
  return 0;
}}

function buildCvePanel(cves) {{
  const sorted = cves.slice().sort((a,b) => {{
    const r = sevRank(b.severity) - sevRank(a.severity);
    if (r !== 0) return r;
    return (b.score||0) - (a.score||0);
  }});

  let html = '<div class="cve-panel">';
  html += '<table class="cve-table"><thead><tr><th style="width:18%">CVE</th><th>Title</th><th style="width:12%">CVSS</th><th style="width:14%">Severity</th></tr></thead><tbody>';

  for (const cv of sorted) {{
    const sev = (cv.severity||"-").toUpperCase();
    const sevCls = sev === "CRITICAL" ? "sev-critical" : (sev === "HIGH" ? "sev-high" : (sev === "MEDIUM" ? "sev-medium" : "sev-low"));
    const score = (typeof cv.score === "number") ? cv.score.toFixed(1) : "-";
    const unauth = cv.unauth ? '<span class="badge-unauth">UNAUTH</span>' : '';
    const title = (cv.title||"").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    const desc  = (cv.description||"").replace(/</g,"&lt;").replace(/>/g,"&gt;");
    const affected = (cv.affected||"").replace(/</g,"&lt;").replace(/>/g,"&gt;");

    const poc = Array.isArray(cv.poc) ? cv.poc : [];
    let pocHtml = '';
    if (poc.length) {{
      pocHtml = '<div class="muted" style="margin-top:8px;">PoC / Exploits</div><ul class="poc-list">';
      for (const p of poc) {{
        const src = (p.source||'link').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const url = (p.url||'#');
        let host = '';
        try {{ host = (new URL(url, window.location.href)).host; }} catch (e) {{}}
        pocHtml += '<li><a href="'+url+'" target="_blank" rel="noopener">'+src+(host?(' — '+host):'')+'</a></li>';
      }}
      pocHtml += '</ul>';
    }}

    html += '<tr><td class="mono">'+cv.id+'</td><td>';
    html += '<details class="cve-detail"><summary><span class="mini-carat"></span>'+title+'</summary>';
    html += '<div class="desc-box"><div class="mono muted" style="margin-bottom:6px;">affected: '+(affected||'(unspecified)')+'</div>'+desc+pocHtml+'</div>';
    html += '</details>';
    html += '</td><td>'+score+'</td><td class="'+sevCls+'">'+sev+unauth+'</td></tr>';
  }}

  html += '</tbody></table></div>';
  return html;
}}

/* ----- таблица ----- */
let current = DATA.rows.slice();
let lastSortKey = null;

function render(rows) {{
  const tb = document.querySelector("#tbl tbody");
  tb.innerHTML = "";
  let ok=0, bad=0;
  rows.forEach(r => {{
    const tr = document.createElement("tr");
    const code = parseInt(r[5],10)||0;
    if (code>=200 && code<300) ok++; else bad++;

    // первые 8 колонок
    r.forEach((c,i)=> {{
      const td=document.createElement("td");
      td.dataset.col = ["target","product","version","vendor","conf","http","server","title"][i];
      td.textContent=String(c);
      if (i===2 && c && c!=="-" && c!=="version not detected") td.classList.add("ok");
      if (i===5) {{
        if (code>=200 && code<300) td.classList.add("ok");
        else if (code>=300 && code<400) td.classList.add("warn");
        else td.classList.add("bad");
      }}
      tr.appendChild(td);
    }});

    // колонка CVE
    if (DATA.cveEnabled) {{
      const td = document.createElement("td");
      td.dataset.col = "cve";
      const cves = getCves(r);
      const count = cves.length;
      const btn = document.createElement("span");
      btn.className = "cve-btn";
      btn.innerHTML = '<span class="carat">▼</span><span class="mono">'+count+'</span>';
      if (count === 0) {{
        btn.style.opacity = .55;
        btn.style.cursor = "default";
      }} else {{
        btn.addEventListener("click", () => {{
          const already = tr.nextElementSibling && tr.nextElementSibling.classList.contains("cve-expand");
          if (already) {{
            tr.nextElementSibling.remove();
            btn.classList.remove("open");
            return;
          }}
          if (tr.parentElement) {{
            const ex = tr.parentElement.querySelector("tr.cve-expand");
            if (ex) ex.remove();
            const opened = tr.parentElement.querySelector(".cve-btn.open");
            if (opened) opened.classList.remove("open");
          }}
          const exp = document.createElement("tr");
          exp.className = "cve-expand";
          const tdx = document.createElement("td");
          const colSpan = tr.children.length; // все колонки
          tdx.colSpan = colSpan;
          tdx.innerHTML = buildCvePanel(cves);
          exp.appendChild(tdx);
          tr.after(exp);
          btn.classList.add("open");
        }});
      }}
      td.appendChild(btn);
      tr.appendChild(td);
    }}

    tb.appendChild(tr);
  }});
  document.getElementById("stat-ok").textContent = ok;
  document.getElementById("stat-bad").textContent = bad;
}}

function sortCurrent(k) {{
  lastSortKey = k;
  current.sort((a,b) => {{
    if (DATA.cveEnabled && k===8) {{
      const ca = getCves(a).length, cb = getCves(b).length;
      return cb - ca; // по убыванию CVE
    }}
    return String(a[k]).localeCompare(String(b[k]), undefined, {{numeric:true}});
  }});
}}

render(current);

/* ----- фильтры: поиск + плашки Findings ----- */
const ACTIVE = new Set();

function applyFilters() {{
  const q = (document.getElementById('q').value||"").toLowerCase();
  let base = DATA.rows.slice();
  if (ACTIVE.size) {{
    base = base.filter(r => ACTIVE.has((r[1]||"").trim()));
  }}
  if (q) {{
    base = base.filter(r => r.join(" ").toLowerCase().includes(q));
  }}
  current = base;
  if (lastSortKey !== null) sortCurrent(lastSortKey);
  render(current);
}}

document.getElementById("q").addEventListener("input", applyFilters);

document.querySelectorAll("#findings .tag-btn").forEach(btn => {{
  btn.addEventListener("click", () => {{
    const p = btn.dataset.prod || "";
    if (ACTIVE.has(p)) {{
      ACTIVE.delete(p);
      btn.classList.remove("active");
    }} else {{
      ACTIVE.add(p);
      btn.classList.add("active");
    }}
    applyFilters();
  }});
}});

/* сортировка по заголовкам */
document.querySelectorAll("#tbl thead th").forEach(th => {{
  th.addEventListener("click", () => {{
    const k = parseInt(th.dataset.k,10);
    sortCurrent(k);
    render(current);
  }});
}});
</script>
</body>
</html>
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def generate_cve_html_blocks(cve_summary):
    """
    Возвращает HTML блок(и) со списками CVE per product/version.
    """
    arr = cve_summary.get("by_product_version", [])
    if not arr:
        return '<div class="muted">No CVEs.</div>'

    # сгруппируем по продукту
    by_prod = {}
    for item in arr:
        by_prod.setdefault(item["product"], []).append(item)

    chunks = []
    for prod, items in by_prod.items():
        items.sort(key=lambda x: _split_ver(x["version"]))
        buf = [f'<div class="card" style="background:var(--card-2); margin-top:10px;"><div class="h2">{prod}</div>']
        for it in items:
            ver = it["version"]; cves = it.get("cves",[]); urls = it.get("targets",[])
            buf.append(f'<div class="muted" style="margin:6px 0 2px 0;">{ver} — {len(cves)} CVE</div>')
            if cves:
                buf.append('<ul class="cvelist">')
                for cv in cves:
                    score = cv.get("score")
                    sev = (cv.get("severity") or "").upper()
                    cls = []
                    if score is not None and score >= 8.8: cls.append("sev-critical")
                    if cv.get("unauth"): cls.append("unauth")
                    title = (cv.get("title") or "").replace("<","&lt;").replace(">","&gt;")
                    aff = cv.get("affected") or "(unspecified)"
                    score_s = "-" if score is None else f"{score:.1f}"
                    li = f'<li class="{" ".join(cls)}"><span class="mono">{cv["id"]}</span>{(" — "+title) if title else ""}<br><span class="muted">affected: {aff} · CVSS {score_s} {sev or "-"}</span></li>'
                    buf.append(li)
                buf.append('</ul>')
            if urls:
                buf.append('<div class="muted" style="margin-top:6px;">Targets:</div><div class="mono" style="font-size:12px;">' + "<br>".join(urls) + "</div>")
        buf.append("</div>")
        chunks.append("".join(buf))
    return "".join(chunks)

def print_findings_console(findings, use_color=True):
    """
    Печатает сводку Findings в консоль.
    Ожидает результат из build_findings({product: [(url, version), ...]}).
    """
    if not findings:
        return

    # локальные ANSI (не трогаем глобальный словарь)
    if use_color:
        c = ANSI
    else:
        c = {k: "" for k in ANSI}

    title = "Findings"
    if use_color:
        title = f"{c['magenta']}{c['bold']}Findings{c['reset']}"
    print("\n" + title + ":")

    # product -> [(url, version), ...]
    for product, items in findings.items():
        header = f"{product} ({len(items)}):"
        if use_color:
            header = f"{c['cyan']}{c['bold']}{product}{c['reset']} ({len(items)}):"
        print(header)

        for url, ver in items:
            if ver and ver != "version not detected":
                vdisp = ver if not use_color else f"{c['green']}{ver}{c['reset']}"
            else:
                vdisp = "version not detected" if not use_color else f"{c['gray']}version not detected{c['reset']}"
            print(f"  • {url} — {vdisp}")


# ---------------- main scan flow ----------------

async def run_scan(args):
    raw_lines = []

    # 1) цели из -t/--targets (CIDR/hosts/IPs)
    if args.targets:
        raw_lines.extend(expand_cli_targets(args.targets))

    # 2) цели из файла, если файл существует (сохраняем старую семантику)
    file_exists = os.path.exists(args.input)
    if file_exists:
        with open(args.input, "r", encoding="utf-8") as f:
            raw_lines.extend([ln.rstrip("\n") for ln in f])

    if not raw_lines:
        print("No targets provided. Use -i file or -t CIDR/IP/host ...", file=sys.stderr)
        return 2

    # доп. порты из -p
    extra_ports = _split_csv_ports(args.ports) if getattr(args, "ports", None) else []

    targets = normalize_targets(raw_lines, ports=extra_ports if extra_ports else None)
    if not targets:
        print("No valid targets after normalization.", file=sys.stderr)
        return 2

    # Prepare formats and live rendering
    fmts = [x.strip().lower() for x in args.format.split(",")]
    live_enabled = (sys.stdout.isatty() and ("table" in fmts))
    results = []
    live_rows = []
    seen_live = set()
    total = len(targets)
    headers = ["Target","Product","Version","Vendor","Confidence","HTTP","Server","Title"]
    if live_enabled:
        sys.stdout.write("\x1b[?25l")
        sys.stdout.flush()
    try:
        async with Scanner(args) as sc:
            tasks = [asyncio.create_task(sc.scan_one(t)) for t in targets]
            done = 0
            for fut in asyncio.as_completed(tasks):
                r = await fut
                results.append(r)
                done += 1
                if live_enabled:
                    best = r.get("best") or {}
                    name = best.get("name","") or "-"
                    version = best.get("version","")
                    version = (None if str(version).strip()=="." else version)
                    version = version if version else ("version not detected" if name else "-")
                    vendor = best.get("vendor","") or "-"
                    conf = best.get("confidence","") or "-"
                    status = r.get("status","") or "-"
                    server = r.get("server","") or "-"
                    title = (r.get("title","") or "-")[:60]
                    hu = human_url(r.get("final_url") or r.get("input"))
                    if hu not in seen_live:
                        seen_live.add(hu)
                        live_rows.append([hu, name, version, vendor, str(conf), str(status), server, title])
                    render_live_table(live_rows, headers, done, total, args.color)
                else:
                    sys.stdout.write("\r" + render_progress_line(done, total, args.color))
                    sys.stdout.flush()
            if not live_enabled:
                sys.stdout.write("\n")
                sys.stdout.flush()

    finally:
        if live_enabled:
            sys.stdout.write("\x1b[?25h\n")
            sys.stdout.flush()

    rows = []
    seen_final = set()
    for r in results:
        best = r.get("best") or {}
        name = best.get("name","") or ""
        version = best.get("version","") or ""
        vendor = best.get("vendor","") or ""
        conf = best.get("confidence","") or ""
        status = r.get("status","") or ""
        server = r.get("server","") or ""
        title = r.get("title","") or ""
        display_version = (None if str(version).strip() == "." else version)
        display_version = display_version if display_version else ("version not detected" if name else "-")
        hu = human_url(r.get("final_url") or r.get("input"))
        if hu in seen_final:
            continue
        seen_final.add(hu)
        rows.append([hu,
                     name or "-", display_version, vendor or "-", str(conf) if conf else "-",
                     str(status) if status else "-", server or "-", title[:60] or "-"])

    findings = build_findings(rows)

    cve_summary = {"by_product_version": []}
    if args.cve:
        cve_summary = await enrich_cves(findings, args)

    os.makedirs(args.outdir, exist_ok=True)

    # table (static) если не live
    if "table" in fmts and not live_enabled:
        print(fmt_table(rows, headers, colorize=colorize_factory(args.color)))

    # Findings
    print_findings_console(findings, use_color=args.color)

    # CVE
    if args.cve:
        print_cves_console(cve_summary, use_color=args.color)

    # Save JSON / CSV / MD
    if "json" in fmts:
        payload = {"generated_at": now_iso(),
                   "scanner":{"name":"ForgeScan","version":__VERSION__},
                   "results": results,
                   "summary": findings_to_json(findings),
                   "vulnerabilities": cve_summary}
        save_json(os.path.join(args.outdir,"report.json"), payload)
        print(f"[+] JSON saved to {os.path.join(args.outdir,'report.json')}")
    if "csv" in fmts:
        save_csv(os.path.join(args.outdir,"report.csv"), rows, headers)
        print(f"[+] CSV saved to {os.path.join(args.outdir,'report.csv')}")
    if "md" in fmts or "markdown" in fmts:
        md = "# ForgeScan Report\n\nGenerated: {}\n\n".format(now_iso()) + render_md(rows, headers)
        md += findings_to_markdown(findings)
        if args.cve:
            md += cves_to_markdown(cve_summary)
        with open(os.path.join(args.outdir,"report.md"),"w",encoding="utf-8") as f:
            f.write(md)
        print(f"[+] Markdown saved to {os.path.join(args.outdir,'report.md')}")

    # NEW: HTML report
    if getattr(args, "html", False):
        html_path = os.path.join(args.outdir, "report.html")
        save_html_report(html_path, rows, findings, cve_summary, generated_at=now_iso(), scanner_version=__VERSION__)
        print(f"[+] HTML saved to {html_path}")

    return 0


def build_parser():
    p = argparse.ArgumentParser(description="ForgeScan v2.1 — Massive Web Vendor & Version Scanner (single file)")
    p.add_argument("-i","--input", default="List.txt", help="Input file (default: List.txt)")
    p.add_argument("-o","--outdir", default=".", help="Output directory (default: current)")
    p.add_argument("-f","--format", default="table,json,csv,md", help="Formats: table,json,csv,md")
    p.add_argument("--concurrency", type=int, default=200, help="Max concurrent HTTP (default: 200)")
    p.add_argument("--probe-concurrency", type=int, default=6, help="Per-host probe concurrency (default: 6)")
    p.add_argument("--http-timeout", type=int, default=20, help="HTTP total timeout seconds (default: 20)")
    p.add_argument("-k","--insecure", action="store_true", default=True, help="Disable TLS verification (default: on)")
    p.add_argument("-A","--user-agent", default=DEFAULT_USER_AGENT, help="Custom User-Agent")
    p.add_argument("--no-probes", dest="probes", action="store_false", help="Disable extra probes for speed")
    p.add_argument("--verify-tls", action="store_true", help="Enable TLS verification (overrides -k)")
    p.add_argument("--selftest", action="store_true", help="Run local parsing self-test and exit")
    p.add_argument("--list-products", action="store_true", help="List built-in products and exit")
    p.add_argument("--color", action="store_true", help="Enable colorized output")
    p.add_argument("--dump-gitlab-html", action="store_true", help="Dump fetched HTML for pages that look like GitLab into OUTDIR/gitlab_<host>_<port>.html")
    # CVE args
    p.add_argument("--cve", action="store_true", help="Enrich results with CVEs from NVD 2.0")
    p.add_argument("--nvd-api-key", dest="nvd_api_key", default=None, help="NVD API key (or env NVD_API_KEY)")
    p.add_argument("--cve-timeout", type=int, default=30, help="Timeout for NVD requests (seconds)")
    p.add_argument("--cve-concurrency", type=int, default=2, help="Max concurrent NVD product queries")
    p.add_argument("--cve-max-per", type=int, default=0, help="Max CVEs per product+version (0 = unlimited)")
    # NEW:
    p.add_argument("--html", action="store_true", help="Generate interactive glassmorphic HTML report (report.html)")
    p.add_argument("-p","--ports", default="", help="Extra ports to probe (comma-separated). For each port tries both http and https, e.g. 8080,8443")
    p.add_argument("-t","--targets", nargs="+", help="Targets (space-separated): IPs/hosts and/or CIDR ranges, e.g. 172.16.0.0/16 10.0.0.0/8")
    return p


SELFTEST_SAMPLES = [
    ("Jenkins & K8s",
     "<title>Jenkins</title>\nX-Jenkins: 2.414\n<script>window.__APP_VERSION__='1.2.3'</script>\nKubernetes v1.25.3"),
    ("Grafana",
     "<title>Grafana</title>\ngrafanaBootData={\"meta\":{\"buildInfo\":{\"version\":\"10.3.1\"}}}"),
    ("OWA/Exchange",
     "<title>Outlook Web App</title>\n<meta name=\"generator\" content=\"Microsoft Exchange\">\nX-OWA-Version: 15.1.2507.20"),
    ("Nexus/Artifactory",
     "<title>Nexus Repository Manager</title>\nVersion: 3.66.0\n<a href=\"/service/rest/v1/status\">status</a>"),
    ("phpMyAdmin vs Sonar (404 trap)",
     "<title>phpMyAdmin</title>\n<body>phpMyAdmin login</body>"),
    ("FortiGate login",
     "<title>Login - FortiGate</title>\n<body>FortiOS v7.2.3 build1234</body>"),
    ("HP LaserJet",
     "<title>Embedded Web Server - HP LaserJet Pro MFP M426dw</title>\n<body>Firmware Revision: 230609_094413</body>")
]

def run_selftest():
    print("[*] ForgeScan v2.1 self-test:")
    fp = FingerprintEngine(SIGNATURES, GENERIC_VERSION_REGEX)
    # Simulate a 404 at /api/server/version to ensure no Sonar false positive
    probes = {"/api/server/version": {"status":404, "headers":{}, "text":"Not Found 404", "json": None}}
    for name, html in SELFTEST_SAMPLES:
        ctx = {
            "url":"http://test/",
            "status":200,
            "headers":{"x-jenkins":"2.414","server":"nginx/1.25"},
            "headers_join":"x-jenkins: 2.414\nserver: nginx/1.25",
            "cookies":["SVPNCOOKIE=1", "ccsrftoken=abc"],
            "title":extract_title(html) or name,
            "meta":{"generator":"Microsoft Exchange"} if "Exchange" in html else {},
            "meta_join": "",
            "body_text": html,
            "probes": probes if "phpMyAdmin" in html else {},
            "favicon_mmh3": None,
            "assets": re.findall(r'(?:src|href)=["\']([^"\']+)', html, re.I),
        }
        res = fp.match(ctx)
        best = res[0] if res else {}
        print(f"  - {name:22} -> {best.get('name','-')} {best.get('version') or '(version not detected)'} [{best.get('confidence','-')}]")
    print("[*] Done.")

def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.list_products:
        names = sorted({s["name"] for s in SIGNATURES})
        print("Built-in products ({}):".format(len(names)))
        print(", ".join(names))
        sys.exit(0)
    if args.selftest:
        run_selftest()
        sys.exit(0)
    try:
        code = asyncio.run(run_scan(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr); code = 130
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr); code = 1
    sys.exit(code)

if __name__ == "__main__":
    main()
