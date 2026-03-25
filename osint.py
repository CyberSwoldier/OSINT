#!/usr/bin/env python3
"""
OSINT Correlation Engine
Personal threat intelligence & open-source investigation tool.
Supports: email · domain/URL · IP · phone · username · attack campaigns
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

from rich.console   import Console
from rich.table     import Table
from rich.panel     import Panel
from rich.tree      import Tree
from rich.text      import Text
from rich.rule      import Rule
from rich.columns   import Columns
from rich.progress  import Progress, SpinnerColumn, TextColumn
from rich           import box
from rich.syntax    import Syntax
from rich.padding   import Padding

console = Console(highlight=False)

# ── Colour palette ────────────────────────────────────────────────────────────
C = {
    "critical": "bold red",
    "high":     "bold yellow",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "bright_black",
    "ok":       "bold green",
    "label":    "bold white",
    "val":      "white",
    "dim":      "bright_black",
    "accent":   "bold cyan",
    "header":   "bold white on blue",
    "node":     "bold magenta",
    "edge":     "bright_black",
}

SEVERITY_COLOUR = {
    "CRITICAL": C["critical"],
    "HIGH":     C["high"],
    "MEDIUM":   C["medium"],
    "LOW":      C["low"],
    "INFO":     C["info"],
    "CLEAN":    C["ok"],
}


# ── Entity & Correlation Graph ────────────────────────────────────────────────

@dataclass
class Entity:
    etype:      str          # email / domain / ip / phone / username / url / asn / org
    value:      str
    source:     str          # which module discovered this
    confidence: float = 1.0
    attributes: Dict = field(default_factory=dict)

@dataclass
class Relation:
    src:    str   # entity value
    rel:    str   # relation type  e.g. "resolves_to", "registered_by", "found_on"
    dst:    str
    source: str

class CorrelationGraph:
    """
    Lightweight in-memory entity-relationship graph.
    Every module adds entities + relations.  At the end we render the
    full picture showing how everything connects.
    """
    def __init__(self):
        self.entities:  Dict[str, Entity]  = {}
        self.relations: List[Relation]     = []
        self._seen_rel: Set[str]           = set()

    def add(self, entity: Entity):
        key = f"{entity.etype}:{entity.value}"
        if key not in self.entities:
            self.entities[key] = entity
        else:
            # Merge attributes
            self.entities[key].attributes.update(entity.attributes)

    def relate(self, src: str, rel: str, dst: str, source: str = ""):
        key = f"{src}|{rel}|{dst}"
        if key not in self._seen_rel:
            self._seen_rel.add(key)
            self.relations.append(Relation(src, rel, dst, source))

    def neighbours(self, value: str) -> List[Tuple[str, str, str]]:
        """Return (rel, other_value, direction) for all edges touching value."""
        result = []
        for r in self.relations:
            if r.src == value:
                result.append((r.rel, r.dst, "→"))
            elif r.dst == value:
                result.append((r.rel, r.src, "←"))
        return result

    def print_graph(self, root_value: str, title: str = "Correlation Graph"):
        """Render the full entity-relation tree from root."""
        console.print()
        console.print(Rule(f"[{C['accent']}]{title}[/]", style="blue"))

        tree = Tree(
            f"[{C['node']}]◉ {root_value}[/]",
            guide_style="bright_black",
        )
        visited: Set[str] = {root_value}
        self._build_tree(tree, root_value, visited, depth=0)
        console.print(Padding(tree, (0, 2)))

        # Also print a flat relations table
        related = [r for r in self.relations
                   if r.src == root_value or r.dst == root_value]
        if related:
            t = Table(box=box.SIMPLE, show_header=True,
                      header_style=C["label"], padding=(0, 1))
            t.add_column("Source",      style=C["node"],   no_wrap=True)
            t.add_column("Relation",    style=C["accent"],  no_wrap=True)
            t.add_column("Target",      style=C["val"],     no_wrap=True)
            t.add_column("Discovered",  style=C["dim"],     no_wrap=True)
            for r in related:
                t.add_row(r.src, r.rel, r.dst, r.source)
            console.print(Padding(t, (0, 2)))

        # Second-degree connections
        second: List[Relation] = []
        first_vals = {r.dst for r in self.relations if r.src == root_value}
        first_vals |= {r.src for r in self.relations if r.dst == root_value}
        for r in self.relations:
            if (r.src in first_vals or r.dst in first_vals) \
               and r.src != root_value and r.dst != root_value:
                second.append(r)
        if second:
            console.print(f"\n  [{C['dim']}]Second-degree connections:[/]")
            for r in second[:20]:
                console.print(f"    [{C['dim']}]{r.src}[/] [{C['edge']}]──[{r.rel}]──▶[/] [{C['val']}]{r.dst}[/]  [{C['dim']}]via {r.source}[/]")

    def _build_tree(self, node, value: str, visited: Set[str], depth: int):
        if depth > 3:
            return
        for r in self.relations:
            neighbour = None
            label     = ""
            if r.src == value and r.dst not in visited:
                neighbour, label = r.dst, f"[{C['edge']}][{r.rel}]→[/] "
            elif r.dst == value and r.src not in visited:
                neighbour, label = r.src, f"[{C['edge']}]←[{r.rel}][/] "
            if neighbour:
                visited.add(neighbour)
                ent = self.entities.get(f"{self._guess_type(neighbour)}:{neighbour}")
                etype_tag = f"[{C['dim']}]({ent.etype})[/] " if ent else ""
                child = node.add(f"{label}{etype_tag}[{C['node']}]{neighbour}[/]")
                self._build_tree(child, neighbour, visited, depth + 1)

    @staticmethod
    def _guess_type(val: str) -> str:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', val):    return "ip"
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', val):        return "email"
        if re.match(r'^\+?\d[\d\s\-()]{6,}$', val):       return "phone"
        if re.match(r'^https?://', val):                   return "url"
        if '.' in val:                                     return "domain"
        return "username"


# ── Shared Helpers ────────────────────────────────────────────────────────────

def severity_badge(level: str) -> str:
    colour = SEVERITY_COLOUR.get(level.upper(), C["info"])
    return f"[{colour}][{level.upper()}][/]"

def _get(url, params=None, headers=None, timeout=10) -> Optional[dict]:
    try:
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def _section(title: str):
    console.print()
    console.print(Rule(f"[{C['accent']}]{title}[/]", style="bright_black"))

def _kv(label: str, value: Any, colour: str = C["val"]):
    if value and str(value).strip() not in ("", "None", "Unknown", "[]", "{}"):
        console.print(f"  [{C['label']}]{label:<28}[/][{colour}]{value}[/]")

def _badge(label: str, colour: str = "white") -> Text:
    t = Text(f" {label} ", style=f"bold {colour} on black")
    return t


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 — IP Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class IPIntelligence:
    """
    Full IP investigation:
    - Geolocation & ASN
    - Reverse DNS
    - Port / service / banner (Shodan)
    - OS fingerprint
    - Abuse score (AbuseIPDB)
    - VirusTotal detections
    - Threat feed classification
    - BGP prefix / upstream provider
    - Known attack campaigns referencing this IP
    """

    THREAT_CATEGORIES = {
        1:  "DNS Compromise",      2: "DNS Poisoning",
        3:  "Fraud Orders",        4: "DDoS Attack",
        5:  "FTP Brute-Force",     6: "Ping of Death",
        7:  "Phishing",            8: "Fraud VoIP",
        9:  "Open Proxy",         10: "Web Spam",
        11: "Email Spam",         14: "Port Scan",
        15: "Hacking",            16: "SQL Injection",
        17: "Spoofing",           18: "Brute-Force",
        19: "Bad Web Bot",        20: "Exploited Host",
        21: "Web App Attack",     22: "SSH",
        23: "IoT Targeted",
    }

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, ip: str) -> dict:
        result = {"ip": ip, "timestamp": datetime.utcnow().isoformat()}

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as p:
            tasks = {
                "geo":     p.add_task("Geolocation + ASN...",          total=None),
                "rdns":    p.add_task("Reverse DNS...",                 total=None),
                "abuse":   p.add_task("AbuseIPDB reputation...",        total=None),
                "vt":      p.add_task("VirusTotal detections...",       total=None),
                "shodan":  p.add_task("Shodan host data...",            total=None),
                "bgp":     p.add_task("BGP / routing info...",          total=None),
            }
            with ThreadPoolExecutor(max_workers=6) as ex:
                futures = {
                    ex.submit(self._geo, ip):    "geo",
                    ex.submit(self._rdns, ip):   "rdns",
                    ex.submit(self._abuse, ip):  "abuse",
                    ex.submit(self._vt, ip):     "vt",
                    ex.submit(self._shodan, ip): "shodan",
                    ex.submit(self._bgp, ip):    "bgp",
                }
                for fut in as_completed(futures):
                    key = futures[fut]
                    try:
                        result[key] = fut.result()
                    except Exception:
                        result[key] = {}
                    p.remove_task(tasks[key])

        self._render(ip, result)
        self._correlate(ip, result)
        return result

    # ── Data fetchers ─────────────────────────────────────────────────────────

    def _geo(self, ip: str) -> dict:
        d = _get(f"https://ipinfo.io/{ip}/json")
        if d:
            return {
                "country":      d.get("country"),
                "country_name": self._country_name(d.get("country","")),
                "region":       d.get("region"),
                "city":         d.get("city"),
                "org":          d.get("org"),
                "asn":          d.get("org","").split()[0] if d.get("org") else None,
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
            rdns = str(dns.resolver.resolve(rev, "PTR", lifetime=4)[0]).rstrip(".")
            return {"ptr": rdns}
        except Exception:
            return {"ptr": None}

    def _abuse(self, ip: str) -> dict:
        if not self.config.get("abuseipdb_api_key"):
            return {}
        d = _get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            headers={"Key": self.config["abuseipdb_api_key"], "Accept": "application/json"},
        )
        if d and d.get("data"):
            data = d["data"]
            cats = list({c for r in data.get("reports", []) for c in r.get("categories", [])})
            cat_names = [self.THREAT_CATEGORIES.get(c, str(c)) for c in cats]
            return {
                "score":           data.get("abuseConfidenceScore", 0),
                "total_reports":   data.get("totalReports", 0),
                "last_reported":   data.get("lastReportedAt"),
                "usage_type":      data.get("usageType"),
                "isp":             data.get("isp"),
                "domain":          data.get("domain"),
                "is_tor":          data.get("isTor", False),
                "is_public":       data.get("isPublic", True),
                "attack_types":    cat_names,
                "recent_reports":  data.get("reports", [])[:5],
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
                "malicious":   stats.get("malicious", 0),
                "suspicious":  stats.get("suspicious", 0),
                "harmless":    stats.get("harmless", 0),
                "undetected":  stats.get("undetected", 0),
                "as_owner":    attr.get("as_owner"),
                "country":     attr.get("country"),
                "asn":         attr.get("asn"),
                "network":     attr.get("network"),
                "tags":        attr.get("tags", []),
                "reputation":  attr.get("reputation", 0),
                "total_votes": attr.get("total_votes", {}),
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
                svc = {
                    "port":      item.get("port"),
                    "protocol":  item.get("transport"),
                    "service":   item.get("_shodan", {}).get("module"),
                    "product":   item.get("product"),
                    "version":   item.get("version"),
                    "banner":    (item.get("data","")[:200]).strip(),
                    "cpe":       item.get("cpe", []),
                    "tags":      item.get("tags", []),
                    "ssl":       bool(item.get("ssl")),
                    "ssl_info":  {
                        "issuer":  item.get("ssl", {}).get("cert", {}).get("issuer", {}),
                        "expires": item.get("ssl", {}).get("cert", {}).get("expires"),
                        "subject": item.get("ssl", {}).get("cert", {}).get("subject", {}),
                    } if item.get("ssl") else None,
                }
                services.append(svc)
            vulns = list(d.get("vulns", {}).keys())
            return {
                "os":           d.get("os"),
                "hostnames":    d.get("hostnames", []),
                "ports":        sorted(d.get("ports", [])),
                "services":     services,
                "vulns":        vulns,
                "tags":         d.get("tags", []),
                "org":          d.get("org"),
                "isp":          d.get("isp"),
                "last_update":  d.get("last_update"),
                "city":         d.get("city"),
                "country_code": d.get("country_code"),
            }
        return {}

    def _bgp(self, ip: str) -> dict:
        d = _get(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}")
        if d and d.get("data"):
            data = d["data"]
            asns = data.get("asns", [])
            return {
                "prefix":    data.get("resource"),
                "is_less_specific": data.get("is_less_specific"),
                "asns": [
                    {"asn": a.get("asn"), "holder": a.get("holder")}
                    for a in asns
                ],
            }
        return {}

    @staticmethod
    def _country_name(code: str) -> str:
        names = {
            "US":"United States","GB":"United Kingdom","DE":"Germany","FR":"France",
            "RU":"Russia","CN":"China","NL":"Netherlands","SE":"Sweden","NO":"Norway",
            "FI":"Finland","DK":"Denmark","EE":"Estonia","LV":"Latvia","LT":"Lithuania",
            "PT":"Portugal","PL":"Poland","UA":"Ukraine","BR":"Brazil","IN":"India",
            "IR":"Iran","KP":"North Korea","RO":"Romania","BG":"Bulgaria","HU":"Hungary",
        }
        return names.get(code.upper(), code) if code else ""

    # ── Renderer ──────────────────────────────────────────────────────────────

    def _render(self, ip: str, r: dict):
        geo    = r.get("geo",    {})
        abuse  = r.get("abuse",  {})
        vt     = r.get("vt",     {})
        shodan = r.get("shodan", {})
        bgp    = r.get("bgp",    {})
        rdns   = r.get("rdns",   {})

        # ── Header ──
        abuse_score = abuse.get("score", 0)
        vt_mal      = vt.get("malicious", 0)
        risk = "CRITICAL" if abuse_score >= 80 or vt_mal >= 10 else \
               "HIGH"     if abuse_score >= 50 or vt_mal >= 3  else \
               "MEDIUM"   if abuse_score >= 20 or vt_mal >= 1  else \
               "CLEAN"

        console.print()
        console.print(Panel(
            f"[bold white]{ip}[/]  {severity_badge(risk)}\n"
            f"[{C['dim']}]{geo.get('country_name','')} · {geo.get('city','')} · {geo.get('isp','')}[/]",
            title=f"[{C['header']}] IP INVESTIGATION [/]",
            border_style="blue",
            padding=(0, 2),
        ))

        # ── Geolocation ──
        _section("Geolocation & Network Identity")
        _kv("Country",        f"{geo.get('country_name','')} [{geo.get('country','')}]")
        _kv("Region / City",  f"{geo.get('region','')} / {geo.get('city','')}")
        _kv("ISP / Org",      geo.get("isp") or geo.get("org"))
        _kv("ASN",            geo.get("asn"))
        _kv("Coordinates",    geo.get("loc"))
        _kv("Timezone",       geo.get("timezone"))
        _kv("Hostname",       geo.get("hostname") or rdns.get("ptr"))
        _kv("Anycast",        "Yes" if geo.get("anycast") else None)

        # ── BGP ──
        if bgp:
            _section("BGP / Routing")
            _kv("Prefix",     bgp.get("prefix"))
            for a in bgp.get("asns", []):
                _kv(f"AS{a.get('asn')}",  a.get("holder"))

        # ── AbuseIPDB ──
        _section("Abuse Intelligence (AbuseIPDB)")
        if abuse:
            colour = C["critical"] if abuse_score >= 80 else \
                     C["high"]     if abuse_score >= 50 else \
                     C["medium"]   if abuse_score >= 20 else C["ok"]
            _kv("Abuse Score",     f"{abuse_score}/100", colour)
            _kv("Total Reports",   abuse.get("total_reports"))
            _kv("Last Reported",   abuse.get("last_reported"))
            _kv("Usage Type",      abuse.get("usage_type"))
            _kv("ISP (AbuseIPDB)", abuse.get("isp"))
            _kv("Associated Domain", abuse.get("domain"))
            _kv("Tor Exit Node",   "Yes" if abuse.get("is_tor") else None, C["high"])
            if abuse.get("attack_types"):
                console.print(f"  [{C['label']}]{'Attack Types':<28}[/][{C['medium']}]{', '.join(abuse['attack_types'])}[/]")
            if abuse.get("recent_reports"):
                console.print(f"\n  [{C['dim']}]Most recent abuse reports:[/]")
                for rep in abuse["recent_reports"][:3]:
                    cats  = [self.THREAT_CATEGORIES.get(c, str(c)) for c in rep.get("categories", [])]
                    rdate = (rep.get("reportedAt","") or "")[:10]
                    console.print(f"    [{C['dim']}]{rdate}[/]  [{C['medium']}]{', '.join(cats)}[/]"
                                  f"  [{C['dim']}]via {rep.get('reporterCountryCode','')}[/]")
        else:
            console.print(f"  [{C['dim']}]No AbuseIPDB key configured.[/]")

        # ── VirusTotal ──
        _section("VirusTotal Detections")
        if vt:
            mal_col = C["critical"] if vt_mal >= 10 else C["high"] if vt_mal >= 3 else \
                      C["medium"]   if vt_mal >= 1  else C["ok"]
            _kv("Malicious",   f"{vt_mal}", mal_col)
            _kv("Suspicious",  f"{vt.get('suspicious',0)}")
            _kv("Harmless",    f"{vt.get('harmless',0)}", C["ok"])
            _kv("AS Owner",    vt.get("as_owner"))
            _kv("Network",     vt.get("network"))
            _kv("Reputation",  vt.get("reputation"))
            if vt.get("tags"):
                _kv("Tags", ", ".join(vt["tags"]))
        else:
            console.print(f"  [{C['dim']}]No VirusTotal key configured.[/]")

        # ── Shodan ──
        _section("Host Fingerprint (Shodan)")
        if shodan:
            _kv("Operating System", shodan.get("os") or "Unknown / Undetected")
            _kv("Open Ports",       ", ".join(str(p) for p in shodan.get("ports", [])))
            _kv("Shodan Tags",      ", ".join(shodan.get("tags", [])))
            _kv("Last Scan",        shodan.get("last_update"))
            if shodan.get("hostnames"):
                _kv("Hostnames", ", ".join(shodan["hostnames"][:5]))
            if shodan.get("vulns"):
                console.print(f"  [{C['label']}]{'Vulnerabilities':<28}[/][{C['critical']}]{', '.join(shodan['vulns'][:10])}[/]")

            # Services table
            if shodan.get("services"):
                console.print(f"\n  [{C['dim']}]Detected Services:[/]")
                t = Table(box=box.SIMPLE, show_header=True,
                          header_style=C["label"], padding=(0, 1))
                t.add_column("Port",     style=C["accent"],  no_wrap=True, width=7)
                t.add_column("Proto",    style=C["dim"],     no_wrap=True, width=6)
                t.add_column("Service",  style=C["val"],     no_wrap=True, width=14)
                t.add_column("Product",  style=C["val"],     no_wrap=True, width=20)
                t.add_column("Version",  style=C["dim"],     no_wrap=True, width=12)
                t.add_column("SSL",      style=C["ok"],      no_wrap=True, width=5)
                t.add_column("Banner excerpt",  style=C["dim"], overflow="fold", max_width=50)
                for svc in shodan["services"][:20]:
                    t.add_row(
                        str(svc.get("port","")),
                        svc.get("protocol",""),
                        svc.get("service",""),
                        svc.get("product","") or "",
                        svc.get("version","") or "",
                        "✓" if svc.get("ssl") else "",
                        (svc.get("banner","") or "").replace("\n"," ")[:80],
                    )
                console.print(Padding(t, (0, 2)))
        else:
            console.print(f"  [{C['dim']}]Shodan key not configured (add SHODAN_API_KEY).[/]")

    def _correlate(self, ip: str, r: dict):
        geo    = r.get("geo",    {})
        abuse  = r.get("abuse",  {})
        shodan = r.get("shodan", {})
        rdns   = r.get("rdns",   {})

        self.graph.add(Entity("ip", ip, "ip_investigation",
                              attributes={"country": geo.get("country"),
                                          "isp": geo.get("isp"),
                                          "abuse_score": abuse.get("score",0),
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


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 — Domain / URL Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class DomainIntelligence:

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, target: str) -> dict:
        url_mode = target.startswith("http")
        if url_mode:
            parsed = urlparse(target)
            domain = parsed.netloc.lstrip("www.")
            path   = parsed.path
        else:
            domain = target.lstrip("www.")
            path   = ""

        result = {"domain": domain, "url": target if url_mode else None,
                  "timestamp": datetime.utcnow().isoformat()}

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as p:
            task_id = p.add_task("Investigating domain...", total=None)

            with ThreadPoolExecutor(max_workers=6) as ex:
                futures = {
                    ex.submit(self._whois, domain):    "whois",
                    ex.submit(self._dns,   domain):    "dns",
                    ex.submit(self._ct,    domain):    "ct",
                    ex.submit(self._vt_domain, domain):"vt",
                    ex.submit(self._urlscan, target if url_mode else domain): "urlscan",
                    ex.submit(self._resolve_ips, domain): "ips",
                }
                labels = {
                    "whois":   "WHOIS lookup...",
                    "dns":     "DNS enumeration...",
                    "ct":      "Certificate transparency...",
                    "vt":      "VirusTotal domain check...",
                    "urlscan": "URLScan.io lookup...",
                    "ips":     "IP resolution...",
                }
                for fut in as_completed(futures):
                    key = futures[fut]
                    try:   result[key] = fut.result()
                    except: result[key] = {}
                    p.update(task_id, description=f"{labels.get(key,'...')} ✓")

        self._render(domain, result, url_mode, path)
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
            privacy_keywords = ["proxy","guard","private","redacted","withheld","protect"]
            is_privacy = any(k in str(w.org or "").lower() + str(w.name or "").lower()
                             for k in privacy_keywords)
            return {
                "registrar":    w.registrar,
                "created":      str(created)[:10] if created else None,
                "updated":      str(updated)[:10] if updated else None,
                "expires":      str(expires)[:10] if expires else None,
                "age_days":     age,
                "name_servers": [ns.lower() for ns in (w.name_servers or [])],
                "registrant":   w.org or w.name,
                "country":      w.country,
                "privacy":      is_privacy,
                "status":       w.status if isinstance(w.status, list) else [w.status],
            }
        except Exception as e:
            return {"error": str(e)}

    def _dns(self, domain: str) -> dict:
        records = {}
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.lifetime = 6
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA"]:
            try:
                answers = resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
        # DMARC
        try:
            ans = resolver.resolve(f"_dmarc.{domain}", "TXT")
            records["DMARC"] = [str(r) for r in ans]
        except Exception:
            pass
        has_spf   = any("v=spf1" in (v or "") for v in records.get("TXT", []))
        has_dmarc = bool(records.get("DMARC"))
        return {"records": records, "has_spf": has_spf, "has_dmarc": has_dmarc}

    def _ct(self, domain: str) -> dict:
        try:
            d = _get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
            if d:
                subdomains = set()
                issuers    = []
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
            cats  = attr.get("categories", {})
            return {
                "malicious":    stats.get("malicious", 0),
                "suspicious":   stats.get("suspicious", 0),
                "harmless":     stats.get("harmless", 0),
                "categories":   list(cats.values()),
                "reputation":   attr.get("reputation", 0),
                "tags":         attr.get("tags", []),
                "registrar":    attr.get("registrar"),
                "creation_date":attr.get("creation_date"),
                "popularity":   attr.get("popularity_ranks", {}),
            }
        return {}

    def _urlscan(self, target: str) -> dict:
        try:
            d = _get(f"https://urlscan.io/api/v1/search/?q=domain:{urlparse(target).netloc or target}&size=3")
            if d and d.get("results"):
                r0 = d["results"][0]
                return {
                    "last_scan":    r0.get("task", {}).get("time"),
                    "screenshot":   r0.get("screenshot"),
                    "verdict":      r0.get("verdicts", {}).get("overall", {}),
                    "ips":          r0.get("page", {}).get("ip"),
                    "server":       r0.get("page", {}).get("server"),
                    "title":        r0.get("page", {}).get("title"),
                    "asn":          r0.get("page", {}).get("asn"),
                    "asnname":      r0.get("page", {}).get("asnname"),
                    "country":      r0.get("page", {}).get("country"),
                }
        except Exception:
            pass
        return {}

    def _resolve_ips(self, domain: str) -> dict:
        ips = []
        try:
            answers = dns.resolver.resolve(domain, "A", lifetime=5)
            ips = [str(r) for r in answers]
        except Exception:
            pass
        ip_info = {}
        for ip in ips[:3]:
            d = _get(f"https://ipinfo.io/{ip}/json")
            if d:
                ip_info[ip] = {
                    "country": d.get("country"),
                    "org":     d.get("org"),
                    "city":    d.get("city"),
                }
        return {"ips": ips, "ip_details": ip_info}

    def _render(self, domain: str, r: dict, url_mode: bool, path: str):
        whois_  = r.get("whois",   {})
        dns_    = r.get("dns",     {})
        ct      = r.get("ct",      {})
        vt      = r.get("vt",      {})
        urlscan = r.get("urlscan", {})
        ips     = r.get("ips",     {})

        age  = whois_.get("age_days")
        vt_m = vt.get("malicious", 0)
        phishing_score = 0
        if age and age < 30:           phishing_score += 30
        if whois_.get("privacy"):      phishing_score += 10
        if vt_m >= 1:                  phishing_score += min(vt_m * 8, 40)
        if not dns_.get("has_spf"):    phishing_score += 8
        if not dns_.get("has_dmarc"): phishing_score += 8
        for cat in vt.get("categories", []):
            if any(k in cat.lower() for k in ("phish","malware","spam","fraud")):
                phishing_score += 15

        risk = "CRITICAL" if phishing_score >= 60 else \
               "HIGH"     if phishing_score >= 40 else \
               "MEDIUM"   if phishing_score >= 20 else "CLEAN"

        console.print()
        console.print(Panel(
            f"[bold white]{domain}[/]  {severity_badge(risk)}\n"
            f"[{C['dim']}]{whois_.get('registrar','')} · age {age}d · "
            f"{'⚠ Privacy Shield' if whois_.get('privacy') else 'Public WHOIS'}[/]",
            title=f"[{C['header']}] {'URL' if url_mode else 'DOMAIN'} INVESTIGATION [/]",
            border_style="blue", padding=(0,2),
        ))

        _section("WHOIS Registration")
        _kv("Registrar",     whois_.get("registrar"))
        _kv("Created",       whois_.get("created"))
        _kv("Updated",       whois_.get("updated"))
        _kv("Expires",       whois_.get("expires"))
        _kv("Age",           f"{age} days" if age else "Unknown")
        _kv("Registrant",    whois_.get("registrant"))
        _kv("Country",       whois_.get("country"))
        _kv("Privacy Shield","YES ⚠" if whois_.get("privacy") else "No", C["high"] if whois_.get("privacy") else C["ok"])
        _kv("Name Servers",  ", ".join(whois_.get("name_servers",[])[:4]))

        _section("DNS Records")
        recs = dns_.get("records", {})
        for rtype, vals in recs.items():
            for v in vals[:4]:
                _kv(rtype, v[:100])
        _kv("SPF",   "Present ✓" if dns_.get("has_spf") else "MISSING ✗",
            C["ok"] if dns_.get("has_spf") else C["medium"])
        _kv("DMARC", "Present ✓" if dns_.get("has_dmarc") else "MISSING ✗",
            C["ok"] if dns_.get("has_dmarc") else C["medium"])

        _section("Resolved IPs")
        for ip, info in ips.get("ip_details", {}).items():
            _kv(ip, f"{info.get('country','')} · {info.get('org','')} · {info.get('city','')}")

        _section("Certificate Transparency")
        _kv("Total certs issued", ct.get("cert_count"))
        _kv("Unique subdomains",  len(ct.get("subdomains", [])))
        if ct.get("issuers"):
            _kv("Certificate issuers", ", ".join(ct["issuers"][:3]))
        if ct.get("subdomains"):
            console.print(f"\n  [{C['dim']}]Subdomains discovered via CT logs:[/]")
            for sd in ct["subdomains"][:20]:
                console.print(f"    [{C['val']}]{sd}[/]")

        _section("VirusTotal")
        if vt:
            col = C["critical"] if vt_m >= 10 else C["high"] if vt_m >= 3 else \
                  C["medium"] if vt_m >= 1 else C["ok"]
            _kv("Malicious",    str(vt_m), col)
            _kv("Suspicious",   str(vt.get("suspicious",0)))
            _kv("Categories",   ", ".join(vt.get("categories",[]))[:80])
            _kv("Tags",         ", ".join(vt.get("tags",[])[:6]))
            _kv("Reputation",   vt.get("reputation"))

        _section("URLScan.io")
        if urlscan:
            verdict = urlscan.get("verdict", {})
            _kv("Last scan",   urlscan.get("last_scan","")[:19])
            _kv("Page title",  urlscan.get("title"))
            _kv("Server",      urlscan.get("server"))
            _kv("Hosting IP",  urlscan.get("ips"))
            _kv("ASN",         f"{urlscan.get('asn','')} {urlscan.get('asnname','')}")
            _kv("Country",     urlscan.get("country"))
            mal = verdict.get("malicious", False)
            _kv("Verdict",     "MALICIOUS ✗" if mal else "Clean ✓",
                C["critical"] if mal else C["ok"])
            if urlscan.get("screenshot"):
                _kv("Screenshot", urlscan["screenshot"])

        _section("Phishing Risk Assessment")
        col = C["critical"] if phishing_score >= 60 else C["high"] if phishing_score >= 40 else \
              C["medium"] if phishing_score >= 20 else C["ok"]
        console.print(f"  [{C['label']}]{'Phishing Score':<28}[/][{col}]{phishing_score}/100  {risk}[/]")

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

    DISPOSABLE = {"tempmail.com","guerrillamail.com","10minutemail.com","mailinator.com",
                  "throwaway.email","temp-mail.org","fakeinbox.com","trashmail.com",
                  "maildrop.cc","getnada.com","mohmal.com","yopmail.com","sharklasers.com"}
    FREE       = {"gmail.com","yahoo.com","outlook.com","hotmail.com","aol.com","icloud.com",
                  "protonmail.com","gmx.com","yandex.com","zoho.com","live.com","me.com",
                  "proton.me","tutanota.com","mail.com","fastmail.com"}
    ROLES      = {"admin","info","support","sales","contact","help","noreply","no-reply",
                  "postmaster","webmaster","security","abuse","root","hello","team"}

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, email: str) -> dict:
        result = {"email": email, "timestamp": datetime.utcnow().isoformat()}

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as p:
            p.add_task("Validating + MX check...", total=None)
            p.add_task("HIBP breach check...",      total=None)
            p.add_task("Paste site scan...",        total=None)
            p.add_task("EmailRep reputation...",    total=None)
            p.add_task("Platform username probe...",total=None)

        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {
                ex.submit(self._validate, email):   "validation",
                ex.submit(self._hibp,    email):    "breaches",
                ex.submit(self._pastes,  email):    "pastes",
                ex.submit(self._emailrep,email):    "reputation",
                ex.submit(self._username_probe, email.split("@")[0]): "platforms",
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:   result[key] = fut.result()
                except: result[key] = {}

        self._render(email, result)
        self._correlate(email, result)
        return result

    def _validate(self, email: str) -> dict:
        parts  = email.split("@")
        domain = parts[1]
        user   = parts[0]
        mx_ok  = False
        try:
            dns.resolver.resolve(domain, "MX", lifetime=5)
            mx_ok = True
        except Exception:
            pass
        pattern = re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', email)
        return {
            "format_valid": bool(pattern),
            "mx_valid":     mx_ok,
            "domain":       domain,
            "username":     user,
            "disposable":   domain.lower() in self.DISPOSABLE,
            "free_provider":domain.lower() in self.FREE,
            "role_account": user.lower() in self.ROLES,
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
            return [{
                "name":        b.get("Name"),
                "date":        b.get("BreachDate"),
                "pwn_count":   b.get("PwnCount"),
                "data_classes":b.get("DataClasses",[]),
                "sensitive":   b.get("IsSensitive",False),
                "verified":    b.get("IsVerified",False),
            } for b in d]
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
            details = d.get("details", {})
            return {
                "reputation":       d.get("reputation"),
                "suspicious":       d.get("suspicious", False),
                "references":       d.get("references", 0),
                "blacklisted":      details.get("blacklisted", False),
                "malicious_activity":details.get("malicious_activity", False),
                "spam":             details.get("spam", False),
                "spoofing":         details.get("spoofing", False),
                "profiles":         details.get("profiles", []),
                "first_seen":       details.get("first_seen"),
                "last_seen":        details.get("last_seen"),
                "days_since_seen":  details.get("days_since_domain_creation"),
            }
        return {}

    def _username_probe(self, username: str) -> dict:
        urls = {
            "GitHub":       f"https://github.com/{username}",
            "Twitter/X":    f"https://twitter.com/{username}",
            "Instagram":    f"https://instagram.com/{username}",
            "Reddit":       f"https://reddit.com/user/{username}",
            "LinkedIn":     f"https://linkedin.com/in/{username}",
            "Medium":       f"https://medium.com/@{username}",
            "Pinterest":    f"https://pinterest.com/{username}",
            "YouTube":      f"https://youtube.com/@{username}",
            "TikTok":       f"https://tiktok.com/@{username}",
            "Twitch":       f"https://twitch.tv/{username}",
            "Steam":        f"https://steamcommunity.com/id/{username}",
            "Keybase":      f"https://keybase.io/{username}",
            "HackerNews":   f"https://news.ycombinator.com/user?id={username}",
            "Patreon":      f"https://patreon.com/{username}",
            "Linktree":     f"https://linktr.ee/{username}",
        }
        found = {}
        with ThreadPoolExecutor(max_workers=15) as ex:
            futures = {ex.submit(self._check_url, url): name for name, url in urls.items()}
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

    def _render(self, email: str, r: dict):
        v    = r.get("validation",  {})
        b    = r.get("breaches",    [])
        p    = r.get("pastes",      [])
        rep  = r.get("reputation",  {})
        plat = r.get("platforms",   {})

        score = 100
        score -= len(b) * 12
        score -= len(p) * 10
        if rep.get("suspicious"):    score -= 20
        if rep.get("blacklisted"):   score -= 25
        if not v.get("mx_valid"):    score -= 20
        if v.get("disposable"):      score -= 30
        rep_score = max(0, score)
        risk = "CRITICAL" if rep_score < 30 else "HIGH" if rep_score < 50 else \
               "MEDIUM" if rep_score < 70 else "CLEAN"

        console.print()
        console.print(Panel(
            f"[bold white]{email}[/]  {severity_badge(risk)}\n"
            f"[{C['dim']}]Reputation score: {rep_score}/100 · "
            f"{len(b)} breach(es) · {len(p)} paste(s)[/]",
            title=f"[{C['header']}] EMAIL INVESTIGATION [/]",
            border_style="blue", padding=(0,2),
        ))

        _section("Validation")
        _kv("Format",       "Valid ✓" if v.get("format_valid") else "Invalid ✗",
            C["ok"] if v.get("format_valid") else C["critical"])
        _kv("MX Record",    "Valid ✓" if v.get("mx_valid") else "No MX (undeliverable) ✗",
            C["ok"] if v.get("mx_valid") else C["high"])
        _kv("Disposable",   "YES ⚠" if v.get("disposable") else "No",
            C["high"] if v.get("disposable") else C["ok"])
        _kv("Free Provider","Yes" if v.get("free_provider") else "No")
        _kv("Role Account", "Yes" if v.get("role_account") else "No")
        _kv("Domain",       v.get("domain"))
        _kv("Username",     v.get("username"))

        _section("EmailRep Reputation")
        if rep:
            col = {"high": C["ok"], "medium": C["medium"],
                   "low": C["high"], "none": C["critical"]}.get(
                rep.get("reputation",""), C["dim"])
            _kv("Reputation",   rep.get("reputation","").upper(), col)
            _kv("Suspicious",   "YES ⚠" if rep.get("suspicious") else "No",
                C["high"] if rep.get("suspicious") else C["ok"])
            _kv("Blacklisted",  "YES ✗" if rep.get("blacklisted") else "No",
                C["critical"] if rep.get("blacklisted") else C["ok"])
            _kv("Spam",         "Flagged" if rep.get("spam") else "No",
                C["medium"] if rep.get("spam") else C["ok"])
            _kv("Spoofing",     "Flagged" if rep.get("spoofing") else "No",
                C["medium"] if rep.get("spoofing") else C["ok"])
            _kv("References",   rep.get("references"))
            _kv("First seen",   rep.get("first_seen"))
            _kv("Last seen",    rep.get("last_seen"))
            if rep.get("profiles"):
                _kv("Known profiles", ", ".join(rep["profiles"]))
        else:
            console.print(f"  [{C['dim']}]EmailRep returned no data.[/]")

        _section(f"Data Breaches ({len(b)} found)")
        if b:
            t = Table(box=box.SIMPLE, show_header=True,
                      header_style=C["label"], padding=(0,1))
            t.add_column("Breach",      style=C["high"],   no_wrap=True)
            t.add_column("Date",        style=C["dim"],    no_wrap=True, width=12)
            t.add_column("Records",     style=C["val"],    no_wrap=True, width=12)
            t.add_column("Data Exposed",style=C["val"],    overflow="fold")
            t.add_column("Verified",    style=C["ok"],     no_wrap=True, width=8)
            for breach in b:
                t.add_row(
                    breach.get("name",""),
                    breach.get("date",""),
                    f"{breach.get('pwn_count',0):,}",
                    ", ".join(breach.get("data_classes",[])[:5]),
                    "✓" if breach.get("verified") else "?",
                )
            console.print(Padding(t, (0,2)))
        elif not self.config.get("hibp_api_key"):
            console.print(f"  [{C['dim']}]Add HIBP_API_KEY to enable breach checking.[/]")
        else:
            console.print(f"  [{C['ok']}]No breaches found.[/]")

        _section(f"Paste Sites ({len(p)} found)")
        if p:
            for paste in p[:5]:
                _kv(paste.get("Source",""), f"{paste.get('Title','Untitled')} [{paste.get('Date','')}]")
        elif self.config.get("hibp_api_key"):
            console.print(f"  [{C['ok']}]No paste exposures found.[/]")

        _section(f"Platform Presence (derived from username: {email.split('@')[0]})")
        if plat:
            for platform, url in plat.items():
                console.print(f"  [{C['ok']}]✓[/] [{C['label']}]{platform:<20}[/] [{C['accent']}]{url}[/]")
        else:
            console.print(f"  [{C['dim']}]No platforms found for this username.[/]")

    def _correlate(self, email: str, r: dict):
        v    = r.get("validation", {})
        plat = r.get("platforms",  {})
        rep  = r.get("reputation", {})

        self.graph.add(Entity("email", email, "email_investigation",
                              attributes={"domain": v.get("domain"),
                                          "suspicious": rep.get("suspicious")}))
        domain = v.get("domain","")
        if domain:
            self.graph.add(Entity("domain", domain, "email_domain"))
            self.graph.relate(email, "hosted_on", domain, "email validation")

        username = v.get("username","")
        if username:
            self.graph.add(Entity("username", username, "email_username"))
            self.graph.relate(email, "username_is", username, "email split")

        for platform, url in plat.items():
            self.graph.add(Entity("url", url, "platform_probe",
                                  attributes={"platform": platform}))
            self.graph.relate(username, "found_on", platform, "platform_probe")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 — Phone Intelligence
# ══════════════════════════════════════════════════════════════════════════════

class PhoneIntelligence:

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, phone: str) -> dict:
        result = {"phone": phone, "timestamp": datetime.utcnow().isoformat()}
        parsed = self._parse(phone)
        result["parsed"] = parsed

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as p:
            p.add_task("Carrier + geolocation...",  total=None)
            p.add_task("NumVerify validation...",    total=None)
            p.add_task("Platform presence...",       total=None)
            p.add_task("SpamCalls reputation...",    total=None)

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(self._numverify, phone):       "numverify",
                ex.submit(self._platform_check, phone):  "platforms",
                ex.submit(self._spam_reputation, phone): "spam",
            }
            for fut in as_completed(futures):
                key = futures[fut]
                try:   result[key] = fut.result()
                except: result[key] = {}

        self._render(phone, parsed, result)
        self._correlate(phone, parsed, result)
        return result

    def _parse(self, phone: str) -> dict:
        try:
            p = phonenumbers.parse(phone, None)
            valid = phonenumbers.is_valid_number(p)
            possible = phonenumbers.is_possible_number(p)
            geo_str  = geocoder.description_for_number(p, "en")
            carr     = carrier.name_for_number(p, "en")
            tzs      = list(pn_timezone.time_zones_for_number(p))
            ltype    = phonenumbers.number_type(p)
            type_map = {
                0: "Fixed Line", 1: "Mobile", 2: "Fixed or Mobile",
                3: "Toll Free", 4: "Premium Rate", 6: "VOIP",
                7: "Personal Number", 27: "Unknown",
            }
            return {
                "valid":           valid,
                "possible":        possible,
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
            return {
                "carrier":      d.get("carrier"),
                "line_type":    d.get("line_type"),
                "location":     d.get("location"),
                "country_name": d.get("country_name"),
                "country_code": d.get("country_code"),
            }
        return {}

    def _platform_check(self, phone: str) -> dict:
        """Check which social platforms might be linked to this phone."""
        # Best that's possible without private APIs — check WhatsApp via wa.me
        found = {}
        clean = re.sub(r'[^\d+]','',phone)
        # wa.me lookup (checks if page exists)
        try:
            r = requests.head(f"https://wa.me/{clean.lstrip('+')}",
                              timeout=4, allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                found["WhatsApp"] = f"https://wa.me/{clean.lstrip('+')}"
        except Exception:
            pass
        return found

    def _spam_reputation(self, phone: str) -> dict:
        """Check spam/scam reputation via free lookup APIs."""
        # Sync API attempt — CallApp, ShouldIAnswer style public endpoints
        try:
            d = _get(f"https://www.shouldianswer.com/phone-number/{phone.replace('+','')}")
            if d:
                return {"source": "ShouldIAnswer", "data": d}
        except Exception:
            pass
        return {}

    def _render(self, phone: str, parsed: dict, r: dict):
        nv   = r.get("numverify", {})
        plat = r.get("platforms", {})

        ltype = parsed.get("line_type", "Unknown")
        risk  = "HIGH"   if ltype in ("VOIP","Toll Free") else \
                "MEDIUM" if not parsed.get("valid")       else "CLEAN"

        console.print()
        console.print(Panel(
            f"[bold white]{parsed.get('international', phone)}[/]  {severity_badge(risk)}\n"
            f"[{C['dim']}]{parsed.get('geo_description','')} · "
            f"{parsed.get('carrier','')} · {ltype}[/]",
            title=f"[{C['header']}] PHONE INVESTIGATION [/]",
            border_style="blue", padding=(0,2),
        ))

        _section("Number Analysis")
        _kv("Valid",          "✓ Yes" if parsed.get("valid") else "✗ No",
            C["ok"] if parsed.get("valid") else C["critical"])
        _kv("E.164 Format",   parsed.get("e164"))
        _kv("International",  parsed.get("international"))
        _kv("National",       parsed.get("national"))
        _kv("Country Code",   f"+{parsed.get('country_code')}")
        _kv("Region",         parsed.get("region"))
        _kv("Location",       parsed.get("geo_description") or nv.get("location"))
        _kv("Carrier",        parsed.get("carrier") or nv.get("carrier") or "Unknown")
        _kv("Line Type",      ltype, C["high"] if ltype in ("VOIP","Toll Free") else C["val"])
        _kv("Timezones",      ", ".join(parsed.get("timezones",[])[:3]))

        _section("Platform Presence")
        if plat:
            for platform, url in plat.items():
                console.print(f"  [{C['ok']}]✓[/] [{C['label']}]{platform:<20}[/] [{C['accent']}]{url}[/]")
        else:
            console.print(f"  [{C['dim']}]No public platform links detected.[/]")
            console.print(f"  [{C['dim']}]Tip: Social media reverse lookup requires paid APIs[/]")
            console.print(f"  [{C['dim']}]     (Pipl, Spokeo, TrueCaller — not free).[/]")

    def _correlate(self, phone: str, parsed: dict, r: dict):
        self.graph.add(Entity("phone", phone, "phone_investigation",
                              attributes={"carrier": parsed.get("carrier"),
                                          "line_type": parsed.get("line_type"),
                                          "country": parsed.get("region")}))
        if parsed.get("region"):
            self.graph.relate(phone, "registered_in", parsed["region"], "phonenumbers")
        if parsed.get("carrier"):
            self.graph.relate(phone, "carrier", parsed["carrier"], "phonenumbers")
        for plat, url in r.get("platforms", {}).items():
            self.graph.add(Entity("url", url, "platform_probe"))
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
        "Xbox":         "https://xboxgamertag.com/search/{}",
        "PSN":          "https://psnprofiles.com/{}",
        "Flickr":       "https://flickr.com/people/{}",
        "Tumblr":       "https://{}.tumblr.com",
    }

    def __init__(self, config: dict, graph: CorrelationGraph):
        self.config = config
        self.graph  = graph

    def investigate(self, username: str) -> dict:
        result = {"username": username, "timestamp": datetime.utcnow().isoformat()}

        console.print(f"\n  [{C['dim']}]Checking {len(self.PLATFORMS)} platforms...[/]")
        found = {}
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      console=console, transient=True) as p:
            p.add_task(f"Scanning {len(self.PLATFORMS)} platforms...", total=None)
            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = {}
                for name, tmpl in self.PLATFORMS.items():
                    url = tmpl.format(username)
                    futures[ex.submit(self._check, url)] = (name, url)
                for fut in as_completed(futures):
                    name, url = futures[fut]
                    try:
                        if fut.result():
                            found[name] = url
                    except Exception:
                        pass

        result["found"] = found
        result["profile_data"] = self._fetch_github_profile(username) if "GitHub" in found else {}
        self._render(username, result)
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

    def _fetch_github_profile(self, username: str) -> dict:
        d = _get(f"https://api.github.com/users/{username}")
        if d:
            return {
                "name":       d.get("name"),
                "bio":        d.get("bio"),
                "location":   d.get("location"),
                "company":    d.get("company"),
                "blog":       d.get("blog"),
                "email":      d.get("email"),
                "followers":  d.get("followers"),
                "repos":      d.get("public_repos"),
                "created_at": d.get("created_at"),
                "twitter":    d.get("twitter_username"),
            }
        return {}

    def _render(self, username: str, r: dict):
        found = r.get("found",        {})
        gh    = r.get("profile_data", {})

        console.print()
        console.print(Panel(
            f"[bold white]{username}[/]\n"
            f"[{C['dim']}]Found on {len(found)} / {len(self.PLATFORMS)} platforms checked[/]",
            title=f"[{C['header']}] USERNAME INVESTIGATION [/]",
            border_style="blue", padding=(0,2),
        ))

        if gh:
            _section("GitHub Profile (Public Data)")
            _kv("Name",      gh.get("name"))
            _kv("Bio",       gh.get("bio"))
            _kv("Location",  gh.get("location"))
            _kv("Company",   gh.get("company"))
            _kv("Blog/URL",  gh.get("blog"))
            _kv("Email",     gh.get("email"), C["high"] if gh.get("email") else C["val"])
            _kv("Twitter",   gh.get("twitter"))
            _kv("Followers", gh.get("followers"))
            _kv("Repos",     gh.get("repos"))
            _kv("Joined",    (gh.get("created_at","") or "")[:10])

        _section(f"Platform Presence — {len(found)} confirmed")
        if found:
            # Group by category
            cats = {
                "Social":       ["Twitter/X","Instagram","Facebook","TikTok","Snapchat","Pinterest","Tumblr"],
                "Professional": ["LinkedIn","GitHub","GitLab","Bitbucket","StackOverflow","AngelList","ProductHunt","Behance","Dribbble"],
                "Content":      ["YouTube","Twitch","Vimeo","SoundCloud","Spotify","Medium","Substack","Patreon","Flickr","DeviantArt"],
                "Identity":     ["Keybase","About.me","Linktree","HackerNews"],
                "Finance":      ["Venmo","CashApp"],
                "Gaming":       ["Steam","Xbox","PSN"],
            }
            for cat, members in cats.items():
                cat_found = {k: v for k, v in found.items() if k in members}
                if cat_found:
                    console.print(f"\n  [{C['dim']}]{cat}:[/]")
                    for platform, url in cat_found.items():
                        console.print(f"    [{C['ok']}]✓[/] [{C['label']}]{platform:<20}[/] [{C['accent']}]{url}[/]")
            # Anything not in categories
            uncategorised = {k: v for k, v in found.items()
                             if not any(k in m for m in cats.values())}
            if uncategorised:
                console.print(f"\n  [{C['dim']}]Other:[/]")
                for platform, url in uncategorised.items():
                    console.print(f"    [{C['ok']}]✓[/] [{C['label']}]{platform:<20}[/] [{C['accent']}]{url}[/]")
        else:
            console.print(f"  [{C['dim']}]Not found on any checked platforms.[/]")

    def _correlate(self, username: str, r: dict):
        self.graph.add(Entity("username", username, "username_investigation"))
        gh = r.get("profile_data", {})
        if gh.get("email"):
            self.graph.add(Entity("email", gh["email"], "github_profile"))
            self.graph.relate(username, "email_exposed_on", gh["email"], "GitHub public profile")
        if gh.get("location"):
            self.graph.relate(username, "location", gh["location"], "GitHub public profile")
        if gh.get("twitter"):
            self.graph.relate(username, "also_twitter", gh["twitter"], "GitHub public profile")
        if gh.get("blog"):
            self.graph.add(Entity("url", gh["blog"], "github_profile"))
            self.graph.relate(username, "personal_site", gh["blog"], "GitHub public profile")
        for platform in r.get("found", {}):
            self.graph.relate(username, "found_on", platform, "platform_scan")
