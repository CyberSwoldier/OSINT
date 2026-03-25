#!/usr/bin/env python3
"""
OSINT Correlation Engine — Pure Data Layer
No rich / no terminal rendering — all output is dict/dataclass.
Rendering is handled by the Streamlit UI (app.py).
"""

import os, re, sys, json, socket, hashlib, time, requests
from datetime import datetime
from typing    import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote
from collections import defaultdict

import dns.resolver
import whois
import phonenumbers
from phonenumbers import geocoder, carrier, timezone as pn_timezone


# ── Correlation Graph ──────────────────────────────────────────────────────────

@dataclass
class Entity:
    etype:      str
    value:      str
    source:     str
    confidence: float = 1.0
    attributes: Dict = field(default_factory=dict)

@dataclass
class Relation:
    src:    str
    rel:    str
    dst:    str
    source: str

class CorrelationGraph:
    def __init__(self):
        self.entities:  Dict[str, Entity] = {}
        self.relations: List[Relation]    = []
        self._seen_rel: Set[str]          = set()

    def add(self, entity: Entity):
        key = f"{entity.etype}:{entity.value}"
        if key not in self.entities:
            self.entities[key] = entity
        else:
            self.entities[key].attributes.update(entity.attributes)

    def relate(self, src: str, rel: str, dst: str, source: str = ""):
        key = f"{src}|{rel}|{dst}"
        if key not in self._seen_rel:
            self._seen_rel.add(key)
            self.relations.append(Relation(src, rel, dst, source))

    def neighbours(self, value: str) -> List[Tuple[str, str, str]]:
        result = []
        for r in self.relations:
            if r.src == value:
                result.append((r.rel, r.dst, "→"))
            elif r.dst == value:
                result.append((r.rel, r.src, "←"))
        return result

    @staticmethod
    def _guess_type(val: str) -> str:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', val):  return "ip"
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', val):      return "email"
        if re.match(r'^\+?\d[\d\s\-()]{6,}$', val):     return "phone"
        if re.match(r'^https?://', val):                 return "url"
        if '.' in val:                                   return "domain"
        return "username"


# ── Shared HTTP helper ─────────────────────────────────────────────────────────

def _get(url, params=None, headers=None, timeout=10) -> Optional[dict]:
    try:
        r = requests.get(url, params=params, headers=headers,
                         timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — IP Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class IPIntelligence:

    THREAT_CATEGORIES = {
        1:"DNS Compromise", 2:"DNS Poisoning", 3:"Fraud Orders",
        4:"DDoS Attack", 5:"FTP Brute-Force", 6:"Ping of Death",
        7:"Phishing", 8:"Fraud VoIP", 9:"Open Proxy", 10:"Web Spam",
        11:"Email Spam", 14:"Port Scan", 15:"Hacking", 16:"SQL Injection",
        17:"Spoofing", 18:"Brute-Force", 19:"Bad Web Bot",
        20:"Exploited Host", 21:"Web App Attack", 22:"SSH", 23:"IoT Targeted",
    }

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, ip: str) -> dict:
        result = {"ip": ip, "timestamp": datetime.utcnow().isoformat()}
        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {
                ex.submit(self._geo,    ip): "geo",
                ex.submit(self._rdns,   ip): "rdns",
                ex.submit(self._abuse,  ip): "abuse",
                ex.submit(self._vt,     ip): "vt",
                ex.submit(self._shodan, ip): "shodan",
                ex.submit(self._bgp,    ip): "bgp",
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:   result[key] = fut.result()
                except: result[key] = {}
        self._correlate(ip, result)
        return result

    def _geo(self, ip: str) -> dict:
        d = _get(f"https://ipinfo.io/{ip}/json")
        if d:
            return {
                "country":      d.get("country"),
                "country_name": self._country_name(d.get("country", "")),
                "region":       d.get("region"),
                "city":         d.get("city"),
                "org":          d.get("org"),
                "asn":          d.get("org", "").split()[0] if d.get("org") else None,
                "isp":          " ".join(d.get("org","").split()[1:]) if d.get("org") else None,
                "hostname":     d.get("hostname"),
                "loc":          d.get("loc"),
                "timezone":     d.get("timezone"),
                "anycast":      d.get("anycast", False),
            }
        return {}

    def _rdns(self, ip: str) -> dict:
        try:
            rev  = dns.reversename.from_address(ip)
            r    = dns.resolver.Resolver(configure=False)
            r.nameservers = ["8.8.8.8", "1.1.1.1"]
            r.lifetime = 4
            rdns = str(r.resolve(rev, "PTR")[0]).rstrip(".")
            return {"ptr": rdns}
        except Exception:
            return {"ptr": None}

    def _abuse(self, ip: str) -> dict:
        if not self.config.get("abuseipdb_api_key"):
            return {}
        d = _get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": self.config["abuseipdb_api_key"],
                     "Accept": "application/json"},
        )
        if d and d.get("data"):
            data = d["data"]
            cats = list({c for rep in data.get("reports", [])
                         for c in rep.get("categories", [])})
            return {
                "score":          data.get("abuseConfidenceScore", 0),
                "total_reports":  data.get("totalReports", 0),
                "last_reported":  data.get("lastReportedAt"),
                "usage_type":     data.get("usageType"),
                "isp":            data.get("isp"),
                "domain":         data.get("domain"),
                "is_tor":         data.get("isTor", False),
                "is_public":      data.get("isPublic", True),
                "attack_types":   [self.THREAT_CATEGORIES.get(c, str(c)) for c in cats],
                "recent_reports": data.get("reports", [])[:5],
            }
        return {}

    def _vt(self, ip: str) -> dict:
        if not self.config.get("virustotal_api_key"):
            return {}
        d = _get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": self.config["virustotal_api_key"]},
        )
        if d and d.get("data"):
            attr  = d["data"].get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "as_owner":   attr.get("as_owner"),
                "country":    attr.get("country"),
                "asn":        attr.get("asn"),
                "network":    attr.get("network"),
                "tags":       attr.get("tags", []),
                "reputation": attr.get("reputation", 0),
            }
        return {}

    def _shodan(self, ip: str) -> dict:
        if not self.config.get("shodan_api_key"):
            return {}
        d = _get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": self.config["shodan_api_key"]},
        )
        if d:
            services = []
            for item in d.get("data", []):
                services.append({
                    "port":     item.get("port"),
                    "protocol": item.get("transport"),
                    "service":  item.get("_shodan", {}).get("module"),
                    "product":  item.get("product"),
                    "version":  item.get("version"),
                    "banner":   (item.get("data", "") or "")[:200].strip(),
                    "ssl":      bool(item.get("ssl")),
                    "tags":     item.get("tags", []),
                })
            return {
                "os":          d.get("os"),
                "hostnames":   d.get("hostnames", []),
                "ports":       sorted(d.get("ports", [])),
                "services":    services,
                "vulns":       list(d.get("vulns", {}).keys()),
                "tags":        d.get("tags", []),
                "org":         d.get("org"),
                "isp":         d.get("isp"),
                "last_update": d.get("last_update"),
            }
        return {}

    def _bgp(self, ip: str) -> dict:
        d = _get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}")
        if d and d.get("data"):
            data = d["data"]
            return {
                "prefix": data.get("resource"),
                "asns": [{"asn": a.get("asn"), "holder": a.get("holder")}
                         for a in data.get("asns", [])],
            }
        return {}

    def _correlate(self, ip: str, r: dict):
        geo    = r.get("geo",    {})
        abuse  = r.get("abuse",  {})
        shodan = r.get("shodan", {})
        rdns   = r.get("rdns",   {})

        self.graph.add(Entity("ip", ip, "ip_investigation",
                              attributes={"country": geo.get("country"),
                                          "isp": geo.get("isp"),
                                          "abuse_score": abuse.get("score", 0),
                                          "os": shodan.get("os")}))
        if geo.get("asn"):
            self.graph.add(Entity("asn", geo["asn"], "ip_investigation",
                                  attributes={"isp": geo.get("isp")}))
            self.graph.relate(ip, "belongs_to_asn", geo["asn"], "ipinfo")
        if rdns.get("ptr"):
            self.graph.add(Entity("domain", rdns["ptr"], "rdns"))
            self.graph.relate(ip, "reverse_dns", rdns["ptr"], "rdns")
        if abuse.get("domain"):
            self.graph.add(Entity("domain", abuse["domain"], "abuseipdb"))
            self.graph.relate(ip, "associated_domain", abuse["domain"], "abuseipdb")
        for hn in shodan.get("hostnames", []):
            self.graph.add(Entity("domain", hn, "shodan"))
            self.graph.relate(ip, "hostname", hn, "shodan")
        if geo.get("country"):
            self.graph.relate(ip, "geolocated_in", geo["country"], "ipinfo")

    @staticmethod
    def _country_name(code: str) -> str:
        names = {
            "US":"United States","GB":"United Kingdom","DE":"Germany",
            "FR":"France","RU":"Russia","CN":"China","NL":"Netherlands",
            "SE":"Sweden","NO":"Norway","FI":"Finland","DK":"Denmark",
            "EE":"Estonia","LV":"Latvia","LT":"Lithuania","PT":"Portugal",
            "PL":"Poland","UA":"Ukraine","BR":"Brazil","IN":"India",
            "IR":"Iran","KP":"North Korea","RO":"Romania",
        }
        return names.get((code or "").upper(), code) if code else ""


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — Domain / URL Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class DomainIntelligence:

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, target: str) -> dict:
        url_mode = target.startswith("http")
        domain   = urlparse(target).netloc.lstrip("www.") if url_mode else target.lstrip("www.")
        result   = {"domain": domain, "url": target if url_mode else None,
                    "timestamp": datetime.utcnow().isoformat()}

        with ThreadPoolExecutor(max_workers=6) as ex:
            futures = {
                ex.submit(self._whois,      domain):                  "whois",
                ex.submit(self._dns,        domain):                  "dns",
                ex.submit(self._ct,         domain):                  "ct",
                ex.submit(self._vt_domain,  domain):                  "vt",
                ex.submit(self._urlscan,    target if url_mode else domain): "urlscan",
                ex.submit(self._resolve_ips,domain):                  "ips",
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:   result[key] = fut.result()
                except: result[key] = {}

        self._correlate(domain, result)
        return result

    def _whois(self, domain: str) -> dict:
        try:
            w = whois.whois(domain)
            created = w.creation_date
            if isinstance(created, list): created = created[0]
            updated = w.updated_date
            if isinstance(updated, list): updated = updated[0]
            expires = w.expiration_date
            if isinstance(expires, list): expires = expires[0]
            age = (datetime.utcnow() - created).days if isinstance(created, datetime) else None
            priv_kw = ["proxy","guard","private","redacted","withheld","protect"]
            is_priv = any(k in str(w.org or "").lower() + str(w.name or "").lower()
                          for k in priv_kw)
            return {
                "registrar":    w.registrar,
                "created":      str(created)[:10] if created else None,
                "updated":      str(updated)[:10] if updated else None,
                "expires":      str(expires)[:10] if expires else None,
                "age_days":     age,
                "name_servers": [ns.lower() for ns in (w.name_servers or [])],
                "registrant":   w.org or w.name,
                "country":      w.country,
                "privacy":      is_priv,
                "status":       w.status if isinstance(w.status, list) else [w.status],
            }
        except Exception as e:
            return {"error": str(e)}

    def _dns(self, domain: str) -> dict:
        records = {}
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = ["8.8.8.8", "1.1.1.1"]
            r.lifetime = 6
        except Exception:
            r = dns.resolver.default_resolver
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]:
            try:
                answers = r.resolve(domain, rtype)
                records[rtype] = [str(x) for x in answers]
            except Exception:
                pass
        try:
            ans = r.resolve(f"_dmarc.{domain}", "TXT")
            records["DMARC"] = [str(x) for x in ans]
        except Exception:
            pass
        has_spf   = any("v=spf1" in (v or "") for v in records.get("TXT", []))
        has_dmarc = bool(records.get("DMARC"))
        return {"records": records, "has_spf": has_spf, "has_dmarc": has_dmarc}

    def _ct(self, domain: str) -> dict:
        try:
            d = _get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
            if d:
                subdomains, issuers = set(), []
                for entry in d[:100]:
                    for name in entry.get("name_value","").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and domain in name:
                            subdomains.add(name)
                    issuers.append(entry.get("issuer_name",""))
                return {
                    "subdomains": sorted(subdomains)[:50],
                    "cert_count": len(d),
                    "issuers":    list(set(i for i in issuers if i))[:10],
                }
        except Exception:
            pass
        return {}

    def _vt_domain(self, domain: str) -> dict:
        if not self.config.get("virustotal_api_key"):
            return {}
        d = _get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                 headers={"x-apikey": self.config["virustotal_api_key"]})
        if d and d.get("data"):
            attr  = d["data"].get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "categories": list(attr.get("categories", {}).values()),
                "reputation": attr.get("reputation", 0),
                "tags":       attr.get("tags", []),
            }
        return {}

    def _urlscan(self, target: str) -> dict:
        try:
            netloc = urlparse(target).netloc or target
            d = _get(f"https://urlscan.io/api/v1/search/?q=domain:{netloc}&size=1")
            if d and d.get("results"):
                r0 = d["results"][0]
                return {
                    "last_scan":  r0.get("task", {}).get("time"),
                    "screenshot": r0.get("screenshot"),
                    "verdict":    r0.get("verdicts", {}).get("overall", {}),
                    "ips":        r0.get("page", {}).get("ip"),
                    "server":     r0.get("page", {}).get("server"),
                    "title":      r0.get("page", {}).get("title"),
                    "asn":        r0.get("page", {}).get("asn"),
                    "asnname":    r0.get("page", {}).get("asnname"),
                    "country":    r0.get("page", {}).get("country"),
                }
        except Exception:
            pass
        return {}

    def _resolve_ips(self, domain: str) -> dict:
        ips = []
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = ["8.8.8.8", "1.1.1.1"]
            r.lifetime = 5
            answers = r.resolve(domain, "A")
            ips = [str(x) for x in answers]
        except Exception:
            pass
        ip_info = {}
        for ip in ips[:3]:
            d = _get(f"https://ipinfo.io/{ip}/json")
            if d:
                ip_info[ip] = {"country": d.get("country"),
                                "org": d.get("org"),
                                "city": d.get("city")}
        return {"ips": ips, "ip_details": ip_info}

    def _correlate(self, domain: str, r: dict):
        whois_ = r.get("whois", {})
        ips    = r.get("ips",   {})
        ct     = r.get("ct",    {})
        self.graph.add(Entity("domain", domain, "domain_investigation",
                              attributes={"age_days": whois_.get("age_days"),
                                          "registrar": whois_.get("registrar")}))
        for ip in ips.get("ips", []):
            self.graph.add(Entity("ip", ip, "dns_resolution"))
            self.graph.relate(domain, "resolves_to", ip, "DNS")
        for ns in whois_.get("name_servers", []):
            self.graph.add(Entity("domain", ns, "whois"))
            self.graph.relate(domain, "uses_nameserver", ns, "WHOIS")
        for sd in ct.get("subdomains", [])[:10]:
            self.graph.add(Entity("domain", sd, "cert_transparency"))
            self.graph.relate(domain, "has_subdomain", sd, "crt.sh")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 — Email Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class EmailIntelligence:

    DISPOSABLE = {"tempmail.com","guerrillamail.com","10minutemail.com",
                  "mailinator.com","throwaway.email","temp-mail.org",
                  "fakeinbox.com","trashmail.com","maildrop.cc",
                  "getnada.com","mohmal.com","yopmail.com"}
    FREE       = {"gmail.com","yahoo.com","outlook.com","hotmail.com",
                  "aol.com","icloud.com","protonmail.com","gmx.com",
                  "yandex.com","zoho.com","live.com","me.com",
                  "proton.me","tutanota.com","fastmail.com"}
    ROLES      = {"admin","info","support","sales","contact","help",
                  "noreply","no-reply","postmaster","webmaster",
                  "security","abuse","root","hello","team"}

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, email: str) -> dict:
        result = {"email": email, "timestamp": datetime.utcnow().isoformat()}
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {
                ex.submit(self._validate,        email):               "validation",
                ex.submit(self._hibp,            email):               "breaches",
                ex.submit(self._pastes,          email):               "pastes",
                ex.submit(self._emailrep,        email):               "reputation",
                ex.submit(self._platform_probe,  email.split("@")[0]): "platforms",
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:   result[key] = fut.result()
                except: result[key] = {} if key != "breaches" else []
        self._correlate(email, result)
        return result

    def _validate(self, email: str) -> dict:
        parts  = email.split("@")
        domain = parts[1]
        user   = parts[0]
        mx_ok  = False
        try:
            r = dns.resolver.Resolver(configure=False)
            r.nameservers = ["8.8.8.8", "1.1.1.1"]
            r.lifetime = 5
            r.resolve(domain, "MX")
            mx_ok = True
        except Exception:
            pass
        return {
            "format_valid":  bool(re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email)),
            "mx_valid":      mx_ok,
            "domain":        domain,
            "username":      user,
            "disposable":    domain.lower() in self.DISPOSABLE,
            "free_provider": domain.lower() in self.FREE,
            "role_account":  user.lower() in self.ROLES,
        }

    def _hibp(self, email: str) -> list:
        if not self.config.get("hibp_api_key"):
            return []
        d = _get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            headers={"hibp-api-key": self.config["hibp_api_key"],
                     "User-Agent": "OSINT-Engine"},
        )
        if d:
            return [{"name": b.get("Name"), "date": b.get("BreachDate"),
                     "pwn_count": b.get("PwnCount"),
                     "data_classes": b.get("DataClasses", []),
                     "sensitive": b.get("IsSensitive", False),
                     "verified": b.get("IsVerified", False)} for b in d]
        return []

    def _pastes(self, email: str) -> list:
        if not self.config.get("hibp_api_key"):
            return []
        d = _get(
            f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}",
            headers={"hibp-api-key": self.config["hibp_api_key"],
                     "User-Agent": "OSINT-Engine"},
        )
        return d or []

    def _emailrep(self, email: str) -> dict:
        d = _get(f"https://emailrep.io/{email}",
                 headers={"User-Agent": "OSINT-Engine"})
        if d:
            det = d.get("details", {})
            return {
                "reputation":        d.get("reputation"),
                "suspicious":        d.get("suspicious", False),
                "references":        d.get("references", 0),
                "blacklisted":       det.get("blacklisted", False),
                "malicious_activity":det.get("malicious_activity", False),
                "spam":              det.get("spam", False),
                "spoofing":          det.get("spoofing", False),
                "profiles":          det.get("profiles", []),
                "first_seen":        det.get("first_seen"),
                "last_seen":         det.get("last_seen"),
            }
        return {}

    def _platform_probe(self, username: str) -> dict:
        urls = {
            "GitHub":      f"https://github.com/{username}",
            "Twitter/X":   f"https://twitter.com/{username}",
            "Instagram":   f"https://instagram.com/{username}",
            "Reddit":      f"https://reddit.com/user/{username}",
            "LinkedIn":    f"https://linkedin.com/in/{username}",
            "Medium":      f"https://medium.com/@{username}",
            "Pinterest":   f"https://pinterest.com/{username}",
            "YouTube":     f"https://youtube.com/@{username}",
            "TikTok":      f"https://tiktok.com/@{username}",
            "Twitch":      f"https://twitch.tv/{username}",
            "Steam":       f"https://steamcommunity.com/id/{username}",
            "Keybase":     f"https://keybase.io/{username}",
            "HackerNews":  f"https://news.ycombinator.com/user?id={username}",
            "Patreon":     f"https://patreon.com/{username}",
            "Linktree":    f"https://linktr.ee/{username}",
        }
        found = {}
        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(self._check_url, url): name
                       for name, url in urls.items()}
            for fut in as_completed(futures):
                name = futures[fut]
                try:
                    if fut.result():
                        found[name] = urls[name]
                except Exception:
                    pass
        return found

    @staticmethod
    def _check_url(url: str) -> bool:
        try:
            r = requests.head(url, timeout=4, allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0"})
            return r.status_code == 200
        except Exception:
            return False

    def _correlate(self, email: str, r: dict):
        v    = r.get("validation", {})
        plat = r.get("platforms",  {})
        rep  = r.get("reputation", {})
        self.graph.add(Entity("email", email, "email_investigation",
                              attributes={"domain": v.get("domain"),
                                          "suspicious": rep.get("suspicious")}))
        if v.get("domain"):
            self.graph.add(Entity("domain", v["domain"], "email_domain"))
            self.graph.relate(email, "hosted_on", v["domain"], "email")
        if v.get("username"):
            self.graph.add(Entity("username", v["username"], "email_split"))
            self.graph.relate(email, "username_is", v["username"], "email")
        for platform in plat:
            self.graph.relate(v.get("username", email), "found_on", platform, "platform_probe")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — Phone Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class PhoneIntelligence:

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, phone: str) -> dict:
        result  = {"phone": phone, "timestamp": datetime.utcnow().isoformat()}
        parsed  = self._parse(phone)
        result["parsed"] = parsed
        with ThreadPoolExecutor(max_workers=3) as ex:
            futures = {
                ex.submit(self._numverify,    phone): "numverify",
                ex.submit(self._whatsapp,     phone): "platforms",
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:   result[key] = fut.result()
                except: result[key] = {}
        self._correlate(phone, parsed, result)
        return result

    def _parse(self, phone: str) -> dict:
        try:
            p       = phonenumbers.parse(phone, None)
            valid   = phonenumbers.is_valid_number(p)
            geo_str = geocoder.description_for_number(p, "en")
            carr    = carrier.name_for_number(p, "en")
            tzs     = list(pn_timezone.time_zones_for_number(p))
            ltype   = phonenumbers.number_type(p)
            type_map = {0:"Fixed Line",1:"Mobile",2:"Fixed or Mobile",
                        3:"Toll Free",4:"Premium Rate",6:"VOIP",
                        7:"Personal Number",27:"Unknown"}
            return {
                "valid":           valid,
                "country_code":    p.country_code,
                "national_number": str(p.national_number),
                "e164":            phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164),
                "international":   phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "national":        phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.NATIONAL),
                "geo_description": geo_str,
                "carrier":         carr,
                "timezones":       tzs,
                "line_type":       type_map.get(ltype, "Unknown"),
                "region":          phonenumbers.region_code_for_number(p),
            }
        except Exception as e:
            return {"error": str(e)}

    def _numverify(self, phone: str) -> dict:
        if not self.config.get("numverify_api_key"):
            return {}
        d = _get("http://apilayer.net/api/validate",
                 params={"access_key": self.config["numverify_api_key"],
                         "number": phone, "format": 1})
        if d and d.get("valid"):
            return {"carrier": d.get("carrier"), "line_type": d.get("line_type"),
                    "location": d.get("location"), "country_name": d.get("country_name")}
        return {}

    def _whatsapp(self, phone: str) -> dict:
        clean = re.sub(r'[^\d+]', '', phone)
        found = {}
        try:
            r = requests.head(f"https://wa.me/{clean.lstrip('+')}",
                              timeout=4, allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                found["WhatsApp"] = f"https://wa.me/{clean.lstrip('+')}"
        except Exception:
            pass
        return found

    def _correlate(self, phone: str, parsed: dict, r: dict):
        self.graph.add(Entity("phone", phone, "phone_investigation",
                              attributes={"carrier": parsed.get("carrier"),
                                          "line_type": parsed.get("line_type"),
                                          "country": parsed.get("region")}))
        if parsed.get("region"):
            self.graph.relate(phone, "registered_in", parsed["region"], "phonenumbers")
        if parsed.get("carrier"):
            self.graph.relate(phone, "carrier", parsed["carrier"], "phonenumbers")
        for plat in r.get("platforms", {}):
            self.graph.relate(phone, "linked_to", plat, "platform_probe")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5 — Username Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class UsernameIntelligence:

    PLATFORMS = {
        "GitHub":       "https://github.com/{}",
        "Twitter/X":    "https://twitter.com/{}",
        "Instagram":    "https://instagram.com/{}",
        "Facebook":     "https://facebook.com/{}",
        "Reddit":       "https://reddit.com/user/{}",
        "LinkedIn":     "https://linkedin.com/in/{}",
        "Medium":       "https://medium.com/@{}",
        "Pinterest":    "https://pinterest.com/{}",
        "YouTube":      "https://youtube.com/@{}",
        "TikTok":       "https://tiktok.com/@{}",
        "Twitch":       "https://twitch.tv/{}",
        "Steam":        "https://steamcommunity.com/id/{}",
        "Keybase":      "https://keybase.io/{}",
        "HackerNews":   "https://news.ycombinator.com/user?id={}",
        "DeviantArt":   "https://{}.deviantart.com",
        "Behance":      "https://behance.net/{}",
        "Dribbble":     "https://dribbble.com/{}",
        "Vimeo":        "https://vimeo.com/{}",
        "SoundCloud":   "https://soundcloud.com/{}",
        "Spotify":      "https://open.spotify.com/user/{}",
        "Patreon":      "https://patreon.com/{}",
        "Linktree":     "https://linktr.ee/{}",
        "Venmo":        "https://venmo.com/{}",
        "CashApp":      "https://cash.app/${}",
        "Substack":     "https://{}.substack.com",
        "About.me":     "https://about.me/{}",
        "ProductHunt":  "https://producthunt.com/@{}",
        "AngelList":    "https://angel.co/{}",
        "GitLab":       "https://gitlab.com/{}",
        "Bitbucket":    "https://bitbucket.org/{}",
        "StackOverflow":"https://stackoverflow.com/users/{}",
        "Flickr":       "https://flickr.com/people/{}",
        "Tumblr":       "https://{}.tumblr.com",
        "Xbox":         "https://xboxgamertag.com/search/{}",
        "PSN":          "https://psnprofiles.com/{}",
    }

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, username: str) -> dict:
        result = {"username": username, "timestamp": datetime.utcnow().isoformat()}
        found  = {}
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(self._check, tmpl.format(username)): (name, tmpl.format(username))
                       for name, tmpl in self.PLATFORMS.items()}
            for fut in as_completed(futures):
                name, url = futures[fut]
                try:
                    if fut.result():
                        found[name] = url
                except Exception:
                    pass
        result["found"]        = found
        result["profile_data"] = self._github_profile(username) if "GitHub" in found else {}
        self._correlate(username, result)
        return result

    @staticmethod
    def _check(url: str) -> bool:
        try:
            r = requests.head(url, timeout=4, allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0"})
            return r.status_code == 200
        except Exception:
            return False

    def _github_profile(self, username: str) -> dict:
        d = _get(f"https://api.github.com/users/{username}")
        if d:
            return {"name": d.get("name"), "bio": d.get("bio"),
                    "location": d.get("location"), "company": d.get("company"),
                    "blog": d.get("blog"), "email": d.get("email"),
                    "followers": d.get("followers"), "repos": d.get("public_repos"),
                    "created_at": d.get("created_at"),
                    "twitter": d.get("twitter_username")}
        return {}

    def _correlate(self, username: str, r: dict):
        self.graph.add(Entity("username", username, "username_investigation"))
        gh = r.get("profile_data", {})
        if gh.get("email"):
            self.graph.add(Entity("email", gh["email"], "github_profile"))
            self.graph.relate(username, "email_exposed_on", gh["email"], "GitHub")
        if gh.get("location"):
            self.graph.relate(username, "location", gh["location"], "GitHub")
        if gh.get("twitter"):
            self.graph.relate(username, "also_twitter", gh["twitter"], "GitHub")
        if gh.get("blog"):
            self.graph.add(Entity("url", gh["blog"], "github_profile"))
            self.graph.relate(username, "personal_site", gh["blog"], "GitHub")
        for platform in r.get("found", {}):
            self.graph.relate(username, "found_on", platform, "platform_scan")
