#!/usr/bin/env python3
"""
OSINT Correlation Engine — Streamlit Web UI
Full-width · No sidebar · Interactive Cytoscape.js graph
"""

import streamlit as st
import json
import os
import time
import re
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Page config — must be first Streamlit call ─────────────────────────────────
st.set_page_config(
    page_title="OSINT Engine",
    page_icon="",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Import engine ──────────────────────────────────────────────────────────────
import sys
sys.path.insert(0, str(Path(__file__).parent))

from osint_engine import (
    CorrelationGraph, Entity,
    IPIntelligence, DomainIntelligence,
    EmailIntelligence, PhoneIntelligence,
    UsernameIntelligence,
)

# ── Global CSS ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Syne:wght@400;600;700;800&display=swap');

/* ── Reset & base ── */
*, *::before, *::after { box-sizing: border-box; }

html, body, [data-testid="stAppViewContainer"],
[data-testid="stMain"], .main, .block-container {
    background: #080c10 !important;
    color: #c9d1d9 !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* ── Full width ── */
.block-container {
    max-width: 100% !important;
    padding: 0 2rem !important;
}

/* ── Hide Streamlit chrome ── */
#MainMenu, footer, header,
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="collapsedControl"],
section[data-testid="stSidebar"] { display: none !important; }

/* ── Typography ── */
h1, h2, h3, h4 {
    font-family: 'Syne', sans-serif !important;
    letter-spacing: -0.02em;
}

/* ── Input ── */
[data-testid="stTextInput"] input {
    background: #0d1117 !important;
    border: 1px solid #21262d !important;
    border-radius: 4px !important;
    color: #e6edf3 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.95rem !important;
    padding: 0.6rem 1rem !important;
    transition: border-color 0.15s ease;
}
[data-testid="stTextInput"] input:focus {
    border-color: #00d4aa !important;
    box-shadow: 0 0 0 2px rgba(0, 212, 170, 0.12) !important;
    outline: none !important;
}

/* ── Buttons ── */
[data-testid="stButton"] button {
    background: #00d4aa !important;
    border: none !important;
    border-radius: 4px !important;
    color: #080c10 !important;
    font-family: 'Syne', sans-serif !important;
    font-size: 0.85rem !important;
    font-weight: 700 !important;
    letter-spacing: 0.08em !important;
    padding: 0.55rem 1.4rem !important;
    text-transform: uppercase !important;
    transition: all 0.15s ease !important;
    cursor: pointer !important;
}
[data-testid="stButton"] button:hover {
    background: #00f0c2 !important;
    transform: translateY(-1px) !important;
}
[data-testid="stButton"] button[kind="secondary"] {
    background: transparent !important;
    border: 1px solid #30363d !important;
    color: #8b949e !important;
}
[data-testid="stButton"] button[kind="secondary"]:hover {
    border-color: #00d4aa !important;
    color: #00d4aa !important;
    transform: none !important;
}

/* ── Metrics ── */
[data-testid="stMetric"] {
    background: #0d1117 !important;
    border: 1px solid #21262d !important;
    border-radius: 6px !important;
    padding: 1rem 1.2rem !important;
}
[data-testid="stMetricLabel"] {
    color: #8b949e !important;
    font-size: 0.72rem !important;
    text-transform: uppercase !important;
    letter-spacing: 0.1em !important;
}
[data-testid="stMetricValue"] {
    color: #e6edf3 !important;
    font-family: 'Syne', sans-serif !important;
    font-size: 1.5rem !important;
    font-weight: 700 !important;
}

/* ── Expanders ── */
[data-testid="stExpander"] {
    background: #0d1117 !important;
    border: 1px solid #21262d !important;
    border-radius: 6px !important;
    margin-bottom: 0.5rem !important;
}
[data-testid="stExpander"] summary {
    color: #8b949e !important;
    font-size: 0.82rem !important;
    letter-spacing: 0.05em !important;
    text-transform: uppercase !important;
    padding: 0.75rem 1rem !important;
}
[data-testid="stExpander"] summary:hover { color: #00d4aa !important; }

/* ── Tabs ── */
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid #21262d !important;
    gap: 0 !important;
}
[data-testid="stTabs"] [role="tab"] {
    background: transparent !important;
    border: none !important;
    border-bottom: 2px solid transparent !important;
    color: #8b949e !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.8rem !important;
    letter-spacing: 0.05em !important;
    padding: 0.6rem 1.2rem !important;
    text-transform: uppercase !important;
    transition: all 0.15s ease !important;
}
[data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    border-bottom-color: #00d4aa !important;
    color: #00d4aa !important;
}

/* ── Dataframes / tables ── */
[data-testid="stDataFrame"] { border: 1px solid #21262d !important; border-radius: 6px !important; }

/* ── Divider ── */
hr { border-color: #21262d !important; }

/* ── Code blocks ── */
code, pre {
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    border-radius: 4px !important;
    color: #00d4aa !important;
    font-family: 'JetBrains Mono', monospace !important;
}

/* ── Alerts ── */
[data-testid="stAlert"] {
    border-radius: 4px !important;
    font-size: 0.85rem !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #080c10; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #00d4aa; }

/* ── Custom components ── */
.osint-header {
    border-bottom: 1px solid #21262d;
    margin-bottom: 1.5rem;
    padding: 1.5rem 0 1rem 0;
    display: flex;
    align-items: baseline;
    gap: 1.5rem;
}
.osint-wordmark {
    font-family: 'Syne', sans-serif;
    font-size: 1.4rem;
    font-weight: 800;
    color: #e6edf3;
    letter-spacing: -0.03em;
}
.osint-wordmark span { color: #00d4aa; }
.osint-tagline {
    color: #8b949e;
    font-size: 0.72rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
}

.badge {
    display: inline-block;
    border-radius: 3px;
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.08em;
    padding: 2px 7px;
    text-transform: uppercase;
}
.badge-critical { background: rgba(248,81,73,0.15); color: #f85149; border: 1px solid rgba(248,81,73,0.3); }
.badge-high     { background: rgba(210,153,34,0.15); color: #d2992a; border: 1px solid rgba(210,153,34,0.3); }
.badge-medium   { background: rgba(187,128,9,0.15);  color: #e3b341; border: 1px solid rgba(187,128,9,0.3); }
.badge-clean    { background: rgba(63,185,80,0.12);  color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
.badge-info     { background: rgba(0,212,170,0.1);   color: #00d4aa; border: 1px solid rgba(0,212,170,0.25); }
.badge-type     { background: #161b22; color: #8b949e; border: 1px solid #30363d; }

.kv-row {
    display: flex;
    border-bottom: 1px solid #0d1117;
    padding: 0.4rem 0;
    font-size: 0.82rem;
    align-items: flex-start;
    gap: 1rem;
}
.kv-label {
    color: #8b949e;
    min-width: 180px;
    flex-shrink: 0;
    font-size: 0.75rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    padding-top: 1px;
}
.kv-value { color: #e6edf3; word-break: break-all; }
.kv-value.accent { color: #00d4aa; }
.kv-value.warn  { color: #e3b341; }
.kv-value.danger { color: #f85149; }
.kv-value.ok    { color: #3fb950; }

.section-title {
    color: #8b949e;
    font-size: 0.68rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    border-bottom: 1px solid #21262d;
    padding-bottom: 0.4rem;
    margin: 1.2rem 0 0.8rem 0;
}

.entity-card {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 0.9rem 1rem;
    margin-bottom: 0.5rem;
    transition: border-color 0.15s;
    cursor: pointer;
}
.entity-card:hover { border-color: #00d4aa; }
.entity-card .ec-type {
    color: #8b949e;
    font-size: 0.68rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 0.2rem;
}
.entity-card .ec-value {
    color: #e6edf3;
    font-size: 0.9rem;
    font-weight: 500;
    word-break: break-all;
}
.entity-card .ec-source {
    color: #8b949e;
    font-size: 0.7rem;
    margin-top: 0.2rem;
}

.relation-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.35rem 0;
    font-size: 0.8rem;
    border-bottom: 1px solid #0d1117;
}
.relation-src  { color: #00d4aa; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
.relation-type { color: #8b949e; flex-shrink: 0; font-size: 0.72rem; }
.relation-dst  { color: #e6edf3; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
.relation-via  { color: #30363d; font-size: 0.68rem; flex-shrink: 0; }

.score-bar-bg {
    background: #161b22;
    border-radius: 2px;
    height: 4px;
    margin-top: 4px;
    overflow: hidden;
}
.score-bar-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.5s ease;
}

.session-item {
    background: #0d1117;
    border: 1px solid #21262d;
    border-left: 3px solid #00d4aa;
    border-radius: 4px;
    padding: 0.5rem 0.8rem;
    margin-bottom: 0.4rem;
    font-size: 0.8rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
}
.session-item .si-type { color: #8b949e; font-size: 0.68rem; min-width: 70px; }
.session-item .si-val  { color: #e6edf3; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.session-item .si-time { color: #30363d; font-size: 0.68rem; }
</style>
""", unsafe_allow_html=True)


# ── Config ─────────────────────────────────────────────────────────────────────
def load_config() -> dict:
    return {
        "virustotal_api_key":     os.getenv("VIRUSTOTAL_API_KEY", ""),
        "abuseipdb_api_key":      os.getenv("ABUSEIPDB_API_KEY", ""),
        "hibp_api_key":           os.getenv("HIBP_API_KEY", ""),
        "shodan_api_key":         os.getenv("SHODAN_API_KEY", ""),
        "securitytrails_api_key": os.getenv("SECURITYTRAILS_API_KEY", ""),
        "numverify_api_key":      os.getenv("NUMVERIFY_API_KEY", ""),
        "hunter_api_key":         os.getenv("HUNTER_API_KEY", ""),
        "urlscan_api_key":        os.getenv("URLSCAN_API_KEY", ""),
    }


# ── Target type detection ──────────────────────────────────────────────────────
def detect_type(target: str) -> str:
    t = target.strip()
    if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', t):
        return "email"
    if re.match(r'^\+?[1-9][\d\s\-().]{6,}$', t.replace(" ", "")):
        return "phone"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', t):
        return "ip"
    if t.startswith("http"):
        return "url"
    if re.match(r'^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}', t) and " " not in t:
        return "domain"
    return "username"


# ── Session state init ─────────────────────────────────────────────────────────
def init_state():
    if "graph" not in st.session_state:
        st.session_state.graph = CorrelationGraph()
    if "results" not in st.session_state:
        st.session_state.results = []        # list of {target, type, data, timestamp}
    if "active_result" not in st.session_state:
        st.session_state.active_result = None
    if "config" not in st.session_state:
        st.session_state.config = load_config()
    if "pivot_target" not in st.session_state:
        st.session_state.pivot_target = ""


# ── Run investigation ──────────────────────────────────────────────────────────
def run_investigation(target: str) -> dict:
    target    = target.strip()
    ttype     = detect_type(target)
    config    = st.session_state.config
    graph     = st.session_state.graph

    module_map = {
        "ip":       IPIntelligence,
        "domain":   DomainIntelligence,
        "url":      DomainIntelligence,
        "email":    EmailIntelligence,
        "phone":    PhoneIntelligence,
        "username": UsernameIntelligence,
    }

    module = module_map[ttype](config, graph)

    result = module.investigate(target)
    return {"target": target, "type": ttype, "data": result,
            "timestamp": datetime.utcnow().strftime("%H:%M:%S")}


# ── Cytoscape graph HTML ───────────────────────────────────────────────────────
TYPE_COLOURS = {
    "ip":       "#f85149",
    "domain":   "#00d4aa",
    "email":    "#79c0ff",
    "phone":    "#d2a679",
    "username": "#d2992a",
    "url":      "#a5d6ff",
    "asn":      "#8b949e",
    "org":      "#8b949e",
}

def build_cytoscape_html(graph: CorrelationGraph, active_target: str = "") -> str:
    nodes = []
    edges = []
    seen_nodes = set()

    for key, entity in graph.entities.items():
        colour = TYPE_COLOURS.get(entity.etype, "#8b949e")
        size   = 48 if entity.value == active_target else 32
        label  = entity.value if len(entity.value) <= 22 else entity.value[:19] + "..."
        nodes.append({
            "data": {
                "id":     entity.value,
                "label":  label,
                "full":   entity.value,
                "etype":  entity.etype,
                "source": entity.source,
                "colour": colour,
                "size":   size,
                "active": entity.value == active_target,
            }
        })
        seen_nodes.add(entity.value)

    for i, rel in enumerate(graph.relations):
        if rel.src in seen_nodes and rel.dst in seen_nodes:
            edges.append({
                "data": {
                    "id":     f"e{i}",
                    "source": rel.src,
                    "target": rel.dst,
                    "label":  rel.rel,
                    "via":    rel.source,
                }
            })

    elements = json.dumps(nodes + edges)

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  html, body {{ width: 100%; height: 100%; background: #080c10; overflow: hidden; }}
  #cy {{ width: 100%; height: 100%; }}
  #tooltip {{
    position: absolute;
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 8px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: #c9d1d9;
    pointer-events: none;
    display: none;
    max-width: 280px;
    word-break: break-all;
    z-index: 999;
    box-shadow: 0 4px 24px rgba(0,0,0,0.6);
  }}
  #tooltip .tt-type {{ color: #8b949e; font-size: 10px; text-transform: uppercase; letter-spacing: .1em; margin-bottom: 4px; }}
  #tooltip .tt-val  {{ color: #00d4aa; font-size: 12px; font-weight: 600; margin-bottom: 4px; word-break: break-all; }}
  #tooltip .tt-src  {{ color: #8b949e; font-size: 10px; }}
  #controls {{
    position: absolute;
    bottom: 16px;
    right: 16px;
    display: flex;
    flex-direction: column;
    gap: 6px;
    z-index: 100;
  }}
  .ctrl-btn {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 4px;
    color: #8b949e;
    cursor: pointer;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    padding: 5px 10px;
    transition: all .15s;
  }}
  .ctrl-btn:hover {{ border-color: #00d4aa; color: #00d4aa; }}
  #stats {{
    position: absolute;
    top: 12px;
    left: 12px;
    color: #8b949e;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: .08em;
    text-transform: uppercase;
  }}
  #pivot-hint {{
    position: absolute;
    bottom: 16px;
    left: 16px;
    color: #30363d;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: .06em;
  }}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
</head>
<body>
<div id="cy"></div>
<div id="tooltip">
  <div class="tt-type" id="tt-type"></div>
  <div class="tt-val"  id="tt-val"></div>
  <div class="tt-src"  id="tt-src"></div>
</div>
<div id="stats" id="stats-el"></div>
<div id="pivot-hint">Double-click a node to copy target for pivot</div>
<div id="controls">
  <button class="ctrl-btn" onclick="cy.fit()">Fit</button>
  <button class="ctrl-btn" onclick="cy.zoom(cy.zoom()*1.2)">+</button>
  <button class="ctrl-btn" onclick="cy.zoom(cy.zoom()*0.8)">-</button>
  <button class="ctrl-btn" onclick="resetLayout()">Reset</button>
</div>

<script>
const elements = {elements};

const cy = cytoscape({{
  container: document.getElementById('cy'),
  elements:  elements,
  style: [
    {{
      selector: 'node',
      style: {{
        'background-color':     'data(colour)',
        'border-width':         2,
        'border-color':         '#21262d',
        'color':                '#e6edf3',
        'font-family':          'JetBrains Mono, monospace',
        'font-size':            9,
        'label':                'data(label)',
        'text-halign':          'center',
        'text-valign':          'bottom',
        'text-margin-y':        5,
        'text-wrap':            'wrap',
        'text-max-width':       90,
        'width':                'data(size)',
        'height':               'data(size)',
        'min-zoomed-font-size': 6,
        'transition-property':  'border-color border-width background-color',
        'transition-duration':  '0.15s',
      }}
    }},
    {{
      selector: 'node[?active]',
      style: {{
        'border-color':  '#00d4aa',
        'border-width':  3,
        'font-weight':   700,
      }}
    }},
    {{
      selector: 'node:selected',
      style: {{
        'border-color': '#00d4aa',
        'border-width': 3,
      }}
    }},
    {{
      selector: 'node:hover',
      style: {{
        'border-color': '#ffffff',
        'border-width': 2,
      }}
    }},
    {{
      selector: 'edge',
      style: {{
        'curve-style':           'bezier',
        'line-color':            '#21262d',
        'target-arrow-color':    '#21262d',
        'target-arrow-shape':    'triangle',
        'arrow-scale':           0.7,
        'width':                 1.2,
        'label':                 'data(label)',
        'font-size':             8,
        'font-family':           'JetBrains Mono, monospace',
        'color':                 '#8b949e',
        'text-rotation':         'autorotate',
        'text-margin-y':         -6,
        'min-zoomed-font-size':  7,
      }}
    }},
    {{
      selector: 'edge:selected',
      style: {{
        'line-color':         '#00d4aa',
        'target-arrow-color': '#00d4aa',
      }}
    }},
  ],
  layout: {{
    name:             'cose',
    animate:          true,
    animationDuration: 600,
    nodeRepulsion:    12000,
    idealEdgeLength:  120,
    gravity:          0.6,
    numIter:          800,
    fit:              true,
    padding:          40,
  }},
  wheelSensitivity: 0.3,
}});

// Stats
const statsEl = document.getElementById('stats');
statsEl.textContent = `${{cy.nodes().length}} nodes  ·  ${{cy.edges().length}} edges`;

// Tooltip
const tooltip = document.getElementById('tooltip');
cy.on('mouseover', 'node', function(e) {{
  const d   = e.target.data();
  const pos = e.renderedPosition;
  document.getElementById('tt-type').textContent = d.etype;
  document.getElementById('tt-val').textContent  = d.full;
  document.getElementById('tt-src').textContent  = 'via ' + d.source;
  tooltip.style.display = 'block';
  tooltip.style.left    = (pos.x + 14) + 'px';
  tooltip.style.top     = (pos.y - 10) + 'px';
}});
cy.on('mouseout', 'node', () => {{ tooltip.style.display = 'none'; }});
cy.on('pan zoom', ()    => {{ tooltip.style.display = 'none'; }});

// Highlight neighbours on click
cy.on('tap', 'node', function(e) {{
  const node = e.target;
  cy.elements().removeClass('faded');
  const connected = node.closedNeighborhood();
  cy.elements().not(connected).addClass('faded');
}});
cy.on('tap', function(e) {{
  if (e.target === cy) cy.elements().removeClass('faded');
}});

// Double-click to copy for pivot
cy.on('dblclick', 'node', function(e) {{
  const val = e.target.data('full');
  navigator.clipboard.writeText(val).then(() => {{
    const hint = document.getElementById('pivot-hint');
    hint.textContent = 'Copied: ' + val;
    setTimeout(() => {{ hint.textContent = 'Double-click a node to copy target for pivot'; }}, 2500);
  }});
}});

// Add faded style
cy.style().selector('.faded').css({{
  'opacity': 0.12,
}}).update();

function resetLayout() {{
  cy.layout({{
    name: 'cose',
    animate: true,
    animationDuration: 500,
    nodeRepulsion: 12000,
    idealEdgeLength: 120,
    fit: true,
    padding: 40,
  }}).run();
}}
</script>
</body>
</html>"""


# ── Result renderers ───────────────────────────────────────────────────────────

def kv(label: str, value, cls: str = "") -> str:
    if not value or str(value).strip() in ("", "None", "[]", "{}", "Unknown"):
        return ""
    return f'<div class="kv-row"><span class="kv-label">{label}</span><span class="kv-value {cls}">{value}</span></div>'

def badge(text: str, cls: str = "info") -> str:
    return f'<span class="badge badge-{cls}">{text}</span>'

def section(title: str) -> str:
    return f'<div class="section-title">{title}</div>'

def score_bar(score: int, colour: str = "#00d4aa") -> str:
    return f"""<div class="score-bar-bg">
        <div class="score-bar-fill" style="width:{score}%;background:{colour};"></div>
    </div>"""

def risk_colour(score: int) -> tuple:
    if score >= 70: return "#f85149", "critical"
    if score >= 45: return "#d2992a", "high"
    if score >= 20: return "#e3b341", "medium"
    return "#3fb950", "clean"

def render_ip(data: dict):
    geo    = data.get("geo",    {})
    abuse  = data.get("abuse",  {})
    vt     = data.get("vt",     {})
    shodan = data.get("shodan", {})
    bgp    = data.get("bgp",    {})
    rdns   = data.get("rdns",   {})

    abuse_score = abuse.get("score", 0)
    vt_mal      = vt.get("malicious", 0)
    risk_s = min(100, abuse_score + vt_mal * 8)
    col, cls = risk_colour(risk_s)

    html = f"""
    <div style="display:flex;gap:.75rem;align-items:center;margin-bottom:1.2rem;flex-wrap:wrap;">
        {badge(cls.upper(), cls)}
        {badge(geo.get('country','?') + ' ' + geo.get('country_name',''), 'type')}
        {badge(abuse.get('usage_type','Unknown'), 'type') if abuse.get('usage_type') else ''}
        {badge('TOR EXIT', 'critical') if abuse.get('is_tor') else ''}
        {badge(shodan.get('os','') or 'OS Unknown', 'type') if shodan else ''}
    </div>
    """

    html += section("Network Identity")
    html += kv("Country", f"{geo.get('country_name','')} [{geo.get('country','')}]")
    html += kv("Region / City", f"{geo.get('region','')} / {geo.get('city','')}")
    html += kv("ISP / Org", geo.get("isp") or geo.get("org"))
    html += kv("ASN", geo.get("asn"))
    html += kv("Hostname", geo.get("hostname") or rdns.get("ptr"), "accent")
    html += kv("Timezone", geo.get("timezone"))
    html += kv("Coordinates", geo.get("loc"))

    if bgp:
        html += section("BGP Routing")
        html += kv("Prefix", bgp.get("prefix"), "accent")
        for a in bgp.get("asns", []):
            html += kv(f"AS{a.get('asn')}", a.get("holder"))

    html += section("Abuse Intelligence (AbuseIPDB)")
    if abuse:
        bar_col = "#f85149" if abuse_score >= 70 else "#d2992a" if abuse_score >= 40 else "#e3b341" if abuse_score >= 20 else "#3fb950"
        html += f"""<div class="kv-row">
            <span class="kv-label">Abuse Score</span>
            <span class="kv-value" style="color:{bar_col};font-weight:600;">{abuse_score}/100</span>
        </div>{score_bar(abuse_score, bar_col)}"""
        html += kv("Total Reports",    abuse.get("total_reports"))
        html += kv("Last Reported",    (abuse.get("last_reported","") or "")[:10])
        html += kv("Usage Type",       abuse.get("usage_type"))
        html += kv("Associated Domain",abuse.get("domain"), "accent")
        html += kv("Tor Exit Node",    "YES" if abuse.get("is_tor") else None, "danger")
        if abuse.get("attack_types"):
            html += kv("Attack Types", ", ".join(abuse["attack_types"]), "warn")
        if abuse.get("recent_reports"):
            html += f'<div style="margin-top:.6rem;font-size:.75rem;color:#8b949e;letter-spacing:.05em;text-transform:uppercase;margin-bottom:.3rem;">Recent Reports</div>'
            for rep in abuse["recent_reports"][:4]:
                from osint_engine import IPIntelligence as _IPI
                cats = [_IPI.THREAT_CATEGORIES.get(c, str(c)) for c in rep.get("categories", [])]
                html += f'<div style="font-size:.78rem;color:#c9d1d9;padding:.25rem 0;border-bottom:1px solid #0d1117;">'
                html += f'<span style="color:#8b949e;">{(rep.get("reportedAt","") or "")[:10]}</span>'
                html += f'&nbsp;&nbsp;<span style="color:#e3b341;">{", ".join(cats)}</span>'
                html += f'&nbsp;&nbsp;<span style="color:#30363d;">via {rep.get("reporterCountryCode","")}</span></div>'
    else:
        html += '<div style="color:#8b949e;font-size:.8rem;">No AbuseIPDB key configured.</div>'

    html += section("VirusTotal")
    if vt:
        vc = "#f85149" if vt_mal >= 10 else "#d2992a" if vt_mal >= 3 else "#e3b341" if vt_mal >= 1 else "#3fb950"
        html += f'<div class="kv-row"><span class="kv-label">Malicious</span><span class="kv-value" style="color:{vc};font-weight:600;">{vt_mal}</span></div>'
        html += kv("Suspicious", vt.get("suspicious", 0))
        html += kv("Harmless",   vt.get("harmless",   0), "ok")
        html += kv("AS Owner",   vt.get("as_owner"))
        html += kv("Network",    vt.get("network"),    "accent")
        html += kv("Reputation", vt.get("reputation"))
        if vt.get("tags"): html += kv("Tags", ", ".join(vt["tags"]))
    else:
        html += '<div style="color:#8b949e;font-size:.8rem;">No VirusTotal key configured.</div>'

    if shodan:
        html += section("Host Fingerprint (Shodan)")
        html += kv("OS",         shodan.get("os") or "Undetected")
        html += kv("Open Ports", ", ".join(str(p) for p in shodan.get("ports", [])), "accent")
        if shodan.get("vulns"):
            html += kv("CVEs", ", ".join(shodan["vulns"][:8]), "danger")
        if shodan.get("hostnames"):
            html += kv("Hostnames", ", ".join(shodan["hostnames"][:5]))
        if shodan.get("tags"):
            html += kv("Shodan Tags", ", ".join(shodan["tags"]))

        if shodan.get("services"):
            html += f'<div style="margin-top:.8rem;">'
            for svc in shodan["services"][:15]:
                banner = (svc.get("banner","") or "").replace("\n"," ")[:90]
                ssl    = " [SSL]" if svc.get("ssl") else ""
                html += f"""<div style="background:#080c10;border:1px solid #21262d;border-radius:4px;
                    padding:.4rem .7rem;margin-bottom:.3rem;font-size:.78rem;">
                    <span style="color:#00d4aa;font-weight:600;">{svc.get('port')}/{svc.get('protocol','')}</span>
                    &nbsp;&nbsp;<span style="color:#e6edf3;">{svc.get('service','') or ''}</span>
                    &nbsp;<span style="color:#8b949e;">{svc.get('product','') or ''} {svc.get('version','') or ''}{ssl}</span>
                    {"<br><span style='color:#30363d;font-size:.72rem;'>" + banner + "</span>" if banner else ""}
                </div>"""
            html += '</div>'

    st.markdown(html, unsafe_allow_html=True)


def render_domain(data: dict):
    whois_  = data.get("whois",   {})
    dns_    = data.get("dns",     {})
    ct      = data.get("ct",      {})
    vt      = data.get("vt",      {})
    urlscan = data.get("urlscan", {})
    ips     = data.get("ips",     {})

    age   = whois_.get("age_days")
    vt_m  = vt.get("malicious", 0)
    ps    = 0
    if age and age < 30:           ps += 30
    if whois_.get("privacy"):      ps += 10
    if vt_m >= 1:                  ps += min(vt_m * 8, 40)
    if not dns_.get("has_spf"):    ps += 8
    if not dns_.get("has_dmarc"): ps += 8
    col, cls = risk_colour(ps)

    html = f"""
    <div style="display:flex;gap:.75rem;align-items:center;margin-bottom:1.2rem;flex-wrap:wrap;">
        {badge('Phishing Score: ' + str(ps) + '/100', cls)}
        {badge('Privacy Shield', 'high') if whois_.get('privacy') else ''}
        {badge('New Domain <30d', 'critical') if age and age < 30 else ''}
        {badge('No SPF', 'medium') if not dns_.get('has_spf') else ''}
        {badge('No DMARC', 'medium') if not dns_.get('has_dmarc') else ''}
    </div>
    {score_bar(ps, col)}
    """

    html += section("WHOIS Registration")
    html += kv("Registrar",     whois_.get("registrar"))
    html += kv("Created",       whois_.get("created"))
    html += kv("Updated",       whois_.get("updated"))
    html += kv("Expires",       whois_.get("expires"))
    html += kv("Age",           f"{age} days" if age else "Unknown",
               "danger" if age and age < 30 else "")
    html += kv("Registrant",    whois_.get("registrant"))
    html += kv("Country",       whois_.get("country"))
    html += kv("Privacy Shield","YES" if whois_.get("privacy") else "No",
               "danger" if whois_.get("privacy") else "ok")
    html += kv("Name Servers",  ", ".join(whois_.get("name_servers",[])[:4]))

    html += section("DNS Records")
    recs = dns_.get("records", {})
    for rtype, vals in recs.items():
        for v in vals[:3]:
            html += kv(rtype, v[:120])
    html += kv("SPF",   "Present" if dns_.get("has_spf") else "MISSING",
               "ok" if dns_.get("has_spf") else "danger")
    html += kv("DMARC", "Present" if dns_.get("has_dmarc") else "MISSING",
               "ok" if dns_.get("has_dmarc") else "warn")

    html += section("Resolved IPs")
    for ip, info in ips.get("ip_details", {}).items():
        html += kv(ip, f"{info.get('country','')} · {info.get('org','')} · {info.get('city','')}", "accent")

    html += section("Certificate Transparency")
    html += kv("Total certs",      ct.get("cert_count"))
    html += kv("Unique subdomains",len(ct.get("subdomains",[])))
    if ct.get("issuers"):
        html += kv("Issuers", " / ".join(ct["issuers"][:3]))
    if ct.get("subdomains"):
        subs = ct["subdomains"][:24]
        html += '<div style="display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.6rem;">'
        for sd in subs:
            html += f'<span style="background:#080c10;border:1px solid #21262d;border-radius:3px;padding:2px 8px;font-size:.75rem;color:#00d4aa;">{sd}</span>'
        html += '</div>'

    html += section("VirusTotal")
    if vt:
        vc = "#f85149" if vt_m >= 10 else "#d2992a" if vt_m >= 3 else "#e3b341" if vt_m >= 1 else "#3fb950"
        html += f'<div class="kv-row"><span class="kv-label">Malicious</span><span class="kv-value" style="color:{vc};font-weight:600;">{vt_m}</span></div>'
        html += kv("Suspicious",  vt.get("suspicious", 0))
        html += kv("Categories",  ", ".join(vt.get("categories",[]))[:100], "warn")
        html += kv("Tags",        ", ".join(vt.get("tags",[])[:6]))
        html += kv("Reputation",  vt.get("reputation"))
    else:
        html += '<div style="color:#8b949e;font-size:.8rem;">No VirusTotal key configured.</div>'

    if urlscan:
        html += section("URLScan.io")
        verdict = urlscan.get("verdict", {})
        html += kv("Last Scan",  (urlscan.get("last_scan","") or "")[:19])
        html += kv("Page Title", urlscan.get("title"))
        html += kv("Server",     urlscan.get("server"))
        html += kv("Hosting IP", urlscan.get("ips"))
        html += kv("ASN",        f"{urlscan.get('asn','')} {urlscan.get('asnname','')}")
        html += kv("Country",    urlscan.get("country"))
        mal = verdict.get("malicious", False)
        html += kv("Verdict",    "MALICIOUS" if mal else "Clean",
                   "danger" if mal else "ok")
        if urlscan.get("screenshot"):
            html += kv("Screenshot", urlscan["screenshot"], "accent")

    st.markdown(html, unsafe_allow_html=True)


def render_email(data: dict):
    v    = data.get("validation",  {})
    b    = data.get("breaches",    [])
    p    = data.get("pastes",      [])
    rep  = data.get("reputation",  {})
    plat = data.get("platforms",   {})

    score = 100 - len(b)*12 - len(p)*10
    if rep.get("suspicious"):   score -= 20
    if rep.get("blacklisted"):  score -= 25
    if not v.get("mx_valid"):   score -= 20
    if v.get("disposable"):     score -= 30
    rep_score = max(0, score)
    risk_s    = 100 - rep_score
    col, cls  = risk_colour(risk_s)

    html = f"""
    <div style="display:flex;gap:.75rem;align-items:center;margin-bottom:1.2rem;flex-wrap:wrap;">
        {badge(cls.upper(), cls)}
        {badge('Reputation: ' + str(rep_score) + '/100', 'type')}
        {badge(str(len(b)) + ' Breaches', 'critical' if b else 'clean')}
        {badge(str(len(p)) + ' Pastes', 'high' if p else 'clean')}
        {badge('Disposable', 'critical') if v.get('disposable') else ''}
        {badge('Blacklisted', 'critical') if rep.get('blacklisted') else ''}
        {badge('Suspicious', 'high') if rep.get('suspicious') else ''}
    </div>
    """

    html += section("Validation")
    html += kv("Format",       "Valid" if v.get("format_valid") else "Invalid",
               "ok" if v.get("format_valid") else "danger")
    html += kv("MX Record",    "Valid" if v.get("mx_valid") else "No MX — undeliverable",
               "ok" if v.get("mx_valid") else "danger")
    html += kv("Disposable",   "YES" if v.get("disposable") else "No",
               "danger" if v.get("disposable") else "ok")
    html += kv("Free Provider","Yes" if v.get("free_provider") else "No")
    html += kv("Role Account", "Yes" if v.get("role_account") else "No")
    html += kv("Domain",       v.get("domain"), "accent")
    html += kv("Username",     v.get("username"))

    html += section("EmailRep Reputation")
    if rep:
        rep_col = {"high": "ok", "medium": "warn", "low": "danger", "none": "danger"}.get(rep.get("reputation",""), "")
        html += kv("Reputation",        (rep.get("reputation","")).upper(), rep_col)
        html += kv("Suspicious",        "YES" if rep.get("suspicious") else "No",
                   "danger" if rep.get("suspicious") else "ok")
        html += kv("Blacklisted",       "YES" if rep.get("blacklisted") else "No",
                   "danger" if rep.get("blacklisted") else "ok")
        html += kv("Spam",              "Flagged" if rep.get("spam") else "No",
                   "warn" if rep.get("spam") else "ok")
        html += kv("Spoofing",          "Flagged" if rep.get("spoofing") else "No",
                   "warn" if rep.get("spoofing") else "ok")
        html += kv("References",        rep.get("references"))
        html += kv("First Seen",        rep.get("first_seen"))
        html += kv("Last Seen",         rep.get("last_seen"))
        if rep.get("profiles"):
            html += kv("Known Profiles", ", ".join(rep["profiles"]), "accent")

    html += section(f"Data Breaches ({len(b)})")
    if b:
        for breach in b:
            classes = ", ".join(breach.get("data_classes",[])[:5])
            sens    = " [SENSITIVE]" if breach.get("sensitive") else ""
            html += f"""<div style="background:#0d1117;border:1px solid #21262d;border-left:3px solid #f85149;
                border-radius:4px;padding:.6rem .9rem;margin-bottom:.4rem;font-size:.8rem;">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="color:#f85149;font-weight:600;">{breach.get('name','')}{sens}</span>
                    <span style="color:#8b949e;">{breach.get('date','')}</span>
                </div>
                <div style="color:#8b949e;margin-top:.3rem;font-size:.75rem;">{classes}</div>
                <div style="color:#30363d;font-size:.72rem;">{breach.get('pwn_count',0):,} records</div>
            </div>"""
    elif not data.get("_has_hibp"):
        html += '<div style="color:#8b949e;font-size:.8rem;">Add HIBP_API_KEY to enable breach checking.</div>'
    else:
        html += '<div style="color:#3fb950;font-size:.8rem;">No breaches found.</div>'

    html += section(f"Paste Exposure ({len(p)})")
    if p:
        for paste in p[:6]:
            html += f'<div class="kv-row"><span class="kv-label">{paste.get("Source","")}</span>'
            html += f'<span class="kv-value warn">{paste.get("Title","Untitled")} [{paste.get("Date","")}]</span></div>'
    elif b or rep:
        html += '<div style="color:#3fb950;font-size:.8rem;">No paste exposures found.</div>'

    html += section(f"Platform Presence ({len(plat)} found)")
    if plat:
        html += '<div style="display:flex;flex-direction:column;gap:.3rem;margin-top:.4rem;">'
        for platform, url in plat.items():
            html += f"""<div style="display:flex;align-items:center;gap:.75rem;font-size:.8rem;">
                <span style="color:#3fb950;min-width:12px;">+</span>
                <span style="color:#8b949e;min-width:120px;">{platform}</span>
                <a href="{url}" target="_blank" style="color:#00d4aa;text-decoration:none;">{url}</a>
            </div>"""
        html += '</div>'
    else:
        html += '<div style="color:#8b949e;font-size:.8rem;">No platforms found for this username.</div>'

    st.markdown(html, unsafe_allow_html=True)


def render_phone(data: dict):
    parsed = data.get("parsed", {})
    plat   = data.get("platforms", {})
    nv     = data.get("numverify", {})

    ltype = parsed.get("line_type","Unknown")
    risk_s = 60 if ltype in ("VOIP","Toll Free") else 0 if parsed.get("valid") else 40
    col, cls = risk_colour(risk_s)

    html = f"""
    <div style="display:flex;gap:.75rem;align-items:center;margin-bottom:1.2rem;flex-wrap:wrap;">
        {badge(cls.upper(), cls)}
        {badge(ltype, 'high' if ltype in ('VOIP','Toll Free') else 'type')}
        {badge(parsed.get('region',''), 'type') if parsed.get('region') else ''}
        {badge('Valid' if parsed.get('valid') else 'Invalid', 'clean' if parsed.get('valid') else 'critical')}
    </div>
    """

    html += section("Number Analysis")
    html += kv("Valid",         "Yes" if parsed.get("valid") else "No",
               "ok" if parsed.get("valid") else "danger")
    html += kv("E.164 Format",  parsed.get("e164"), "accent")
    html += kv("International", parsed.get("international"))
    html += kv("National",      parsed.get("national"))
    html += kv("Country Code",  f"+{parsed.get('country_code')}")
    html += kv("Region",        parsed.get("region"))
    html += kv("Location",      parsed.get("geo_description") or nv.get("location"))
    html += kv("Carrier",       parsed.get("carrier") or nv.get("carrier") or "Unknown", "accent")
    html += kv("Line Type",     ltype, "warn" if ltype in ("VOIP","Toll Free") else "")
    html += kv("Timezones",     ", ".join(parsed.get("timezones",[])[:3]))

    html += section("Platform Presence")
    if plat:
        for platform, url in plat.items():
            html += f'<div class="kv-row"><span class="kv-label">{platform}</span>'
            html += f'<a href="{url}" target="_blank" style="color:#00d4aa;text-decoration:none;">{url}</a></div>'
    else:
        html += '<div style="color:#8b949e;font-size:.8rem;">No public platform links detected.</div>'
        html += '<div style="color:#30363d;font-size:.75rem;margin-top:.3rem;">Full social media reverse lookup requires Pipl / TrueCaller / Spokeo (paid).</div>'

    st.markdown(html, unsafe_allow_html=True)


def render_username(data: dict):
    found = data.get("found", {})
    gh    = data.get("profile_data", {})

    html = f"""
    <div style="display:flex;gap:.75rem;align-items:center;margin-bottom:1.2rem;flex-wrap:wrap;">
        {badge(str(len(found)) + ' platforms found', 'high' if len(found) > 10 else 'medium' if len(found) > 4 else 'info')}
    </div>
    """

    if gh:
        html += section("GitHub Public Profile")
        html += kv("Name",     gh.get("name"))
        html += kv("Bio",      gh.get("bio"))
        html += kv("Location", gh.get("location"), "accent")
        html += kv("Company",  gh.get("company"))
        html += kv("Blog/URL", gh.get("blog"), "accent")
        html += kv("Email",    gh.get("email"), "danger")
        html += kv("Twitter",  gh.get("twitter"), "accent")
        html += kv("Followers",gh.get("followers"))
        html += kv("Repos",    gh.get("repos"))
        html += kv("Joined",   (gh.get("created_at","") or "")[:10])

    cats = {
        "Social":       ["Twitter/X","Instagram","Facebook","TikTok","Pinterest","Tumblr"],
        "Professional": ["LinkedIn","GitHub","GitLab","Bitbucket","StackOverflow","AngelList","ProductHunt","Behance","Dribbble"],
        "Content":      ["YouTube","Twitch","Vimeo","SoundCloud","Spotify","Medium","Substack","Patreon","Flickr","DeviantArt"],
        "Identity":     ["Keybase","About.me","Linktree","HackerNews"],
        "Finance":      ["Venmo","CashApp"],
        "Gaming":       ["Steam","Xbox","PSN"],
    }

    for cat, members in cats.items():
        cat_found = {k: v for k, v in found.items() if k in members}
        if cat_found:
            html += section(cat)
            for platform, url in cat_found.items():
                html += f"""<div style="display:flex;align-items:center;gap:.75rem;font-size:.8rem;padding:.3rem 0;border-bottom:1px solid #0d1117;">
                    <span style="color:#3fb950;min-width:12px;">+</span>
                    <span style="color:#8b949e;min-width:130px;">{platform}</span>
                    <a href="{url}" target="_blank" style="color:#00d4aa;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">{url}</a>
                </div>"""

    st.markdown(html, unsafe_allow_html=True)


RENDERERS = {
    "ip":       render_ip,
    "domain":   render_domain,
    "url":      render_domain,
    "email":    render_email,
    "phone":    render_phone,
    "username": render_username,
}


# ── Main layout ────────────────────────────────────────────────────────────────

def main():
    init_state()
    config = st.session_state.config

    # ── Header ──
    st.markdown("""
    <div class="osint-header">
        <div class="osint-wordmark">OSINT<span>.</span>ENGINE</div>
        <div class="osint-tagline">Open Source Intelligence · Correlation Analysis</div>
    </div>
    """, unsafe_allow_html=True)

    # ── Search bar ──
    col_input, col_btn, col_clear = st.columns([6, 1, 1])
    with col_input:
        target = st.text_input(
            label="target",
            label_visibility="collapsed",
            placeholder="Enter target: IP, domain, URL, email, phone, or username",
            value=st.session_state.pivot_target,
            key="search_input",
        )
    with col_btn:
        investigate = st.button("Investigate", use_container_width=True)
    with col_clear:
        if st.button("Clear Session", use_container_width=True, type="secondary"):
            st.session_state.graph    = CorrelationGraph()
            st.session_state.results  = []
            st.session_state.active_result = None
            st.session_state.pivot_target  = ""
            st.rerun()

    # API status strip
    active_keys = [k for k, v in {
        "VT": config.get("virustotal_api_key"),
        "AbuseIPDB": config.get("abuseipdb_api_key"),
        "HIBP": config.get("hibp_api_key"),
        "Shodan": config.get("shodan_api_key"),
        "SecurityTrails": config.get("securitytrails_api_key"),
        "NumVerify": config.get("numverify_api_key"),
    }.items() if v]

    inactive_keys = [k for k, v in {
        "VT": config.get("virustotal_api_key"),
        "AbuseIPDB": config.get("abuseipdb_api_key"),
        "HIBP": config.get("hibp_api_key"),
        "Shodan": config.get("shodan_api_key"),
        "SecurityTrails": config.get("securitytrails_api_key"),
        "NumVerify": config.get("numverify_api_key"),
    }.items() if not v]

    strips = ""
    for k in active_keys:
        strips += f'<span style="color:#3fb950;font-size:.7rem;background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.2);border-radius:3px;padding:2px 8px;">{k}</span> '
    for k in inactive_keys:
        strips += f'<span style="color:#30363d;font-size:.7rem;background:#0d1117;border:1px solid #21262d;border-radius:3px;padding:2px 8px;">{k}</span> '
    st.markdown(f'<div style="margin:.5rem 0 1rem 0;display:flex;gap:.4rem;flex-wrap:wrap;">{strips}</div>',
                unsafe_allow_html=True)

    # ── Run investigation ──
    if investigate and target and target.strip():
        st.session_state.pivot_target = ""
        with st.spinner("Investigating..."):
            try:
                result = run_investigation(target.strip())
                st.session_state.results.insert(0, result)
                st.session_state.active_result = result
            except Exception as e:
                st.error(f"Investigation failed: {e}")
        st.rerun()

    # ── Main panes ──
    if not st.session_state.results:
        st.markdown("""
        <div style="text-align:center;padding:5rem 0;color:#30363d;">
            <div style="font-family:'Syne',sans-serif;font-size:2.5rem;font-weight:800;letter-spacing:-.04em;margin-bottom:.75rem;">
                Ready to investigate.
            </div>
            <div style="font-size:.85rem;letter-spacing:.08em;text-transform:uppercase;">
                Enter any IP · Domain · URL · Email · Phone · Username
            </div>
        </div>
        """, unsafe_allow_html=True)
        return

    # Three-column layout: history | results | graph
    col_hist, col_res, col_graph = st.columns([1.6, 3.5, 5], gap="medium")

    # ── History column ──
    with col_hist:
        st.markdown('<div class="section-title" style="margin-top:.3rem;">Session History</div>',
                    unsafe_allow_html=True)
        for i, r in enumerate(st.session_state.results):
            is_active = st.session_state.active_result and \
                        r["target"] == st.session_state.active_result["target"] and \
                        r["timestamp"] == st.session_state.active_result["timestamp"]
            border = "#00d4aa" if is_active else "#21262d"
            if st.button(
                f"{r['type'].upper()}  {r['target'][:28]}",
                key=f"hist_{i}",
                use_container_width=True,
                type="secondary",
            ):
                st.session_state.active_result = r
                st.rerun()

        st.markdown('<div class="section-title" style="margin-top:1.5rem;">Session Graph</div>',
                    unsafe_allow_html=True)
        graph = st.session_state.graph
        n_ent = len(graph.entities)
        n_rel = len(graph.relations)
        c1, c2 = st.columns(2)
        c1.metric("Nodes", n_ent)
        c2.metric("Edges", n_rel)

        # Pivot helper
        if n_ent > 0:
            st.markdown('<div class="section-title" style="margin-top:1rem;">Quick Pivot</div>',
                        unsafe_allow_html=True)
            entity_list = [e.value for e in graph.entities.values()]
            selected = st.selectbox("Select entity", entity_list,
                                    label_visibility="collapsed")
            if st.button("Pivot", use_container_width=True):
                st.session_state.pivot_target = selected
                st.rerun()

        # Export
        if st.button("Export JSON", use_container_width=True, type="secondary"):
            export = {
                "timestamp": datetime.utcnow().isoformat(),
                "entities": [{"type": e.etype, "value": e.value,
                               "source": e.source, "attributes": e.attributes}
                              for e in graph.entities.values()],
                "relations": [{"src": r.src, "rel": r.rel,
                                "dst": r.dst, "source": r.source}
                               for r in graph.relations],
            }
            st.download_button(
                "Download",
                data=json.dumps(export, indent=2, default=str),
                file_name=f"osint_session_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True,
            )

    # ── Results column ──
    with col_res:
        ar = st.session_state.active_result
        if ar:
            ttype  = ar["type"]
            target = ar["target"]

            st.markdown(f"""
            <div style="display:flex;align-items:baseline;gap:.75rem;margin-bottom:.8rem;">
                <span style="font-family:'Syne',sans-serif;font-size:1.1rem;font-weight:700;color:#e6edf3;word-break:break-all;">{target}</span>
                <span class="badge badge-type">{ttype.upper()}</span>
                <span style="color:#30363d;font-size:.72rem;">{ar['timestamp']}</span>
            </div>
            """, unsafe_allow_html=True)

            renderer = RENDERERS.get(ttype)
            if renderer:
                renderer(ar["data"])

            # Immediate connections
            graph = st.session_state.graph
            neighbours = graph.neighbours(target)
            if neighbours:
                st.markdown('<div class="section-title" style="margin-top:1.2rem;">Immediate Connections</div>',
                            unsafe_allow_html=True)
                for rel, other, direction in neighbours[:20]:
                    ent   = graph.entities.get(f"{CorrelationGraph._guess_type(other)}:{other}")
                    etype = ent.etype if ent else ""
                    pivot_key = f"pivot_{rel}_{other}"
                    col_r, col_p = st.columns([5, 1])
                    with col_r:
                        st.markdown(
                            f'<div class="relation-row">'
                            f'<span class="relation-src">{target}</span>'
                            f'<span class="relation-type">{direction} {rel} {direction[::-1]}</span>'
                            f'<span class="relation-dst">{other}</span>'
                            f'<span class="relation-via">({etype})</span>'
                            f'</div>',
                            unsafe_allow_html=True
                        )
                    with col_p:
                        if st.button("Pivot", key=pivot_key, type="secondary"):
                            st.session_state.pivot_target = other
                            st.rerun()

    # ── Graph column ──
    with col_graph:
        graph = st.session_state.graph
        active_target = st.session_state.active_result["target"] if st.session_state.active_result else ""

        st.markdown('<div class="section-title" style="margin-top:.3rem;">Correlation Graph</div>',
                    unsafe_allow_html=True)

        if graph.entities:
            cyto_html = build_cytoscape_html(graph, active_target)
            st.components.v1.html(cyto_html, height=620, scrolling=False)

            # Legend
            legend_html = '<div style="display:flex;gap:1rem;flex-wrap:wrap;margin-top:.6rem;">'
            for etype, colour in TYPE_COLOURS.items():
                legend_html += f'<span style="font-size:.7rem;color:{colour};display:flex;align-items:center;gap:.3rem;">'
                legend_html += f'<span style="width:8px;height:8px;background:{colour};border-radius:50%;display:inline-block;"></span>'
                legend_html += f'{etype}</span>'
            legend_html += '</div>'
            st.markdown(legend_html, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="height:500px;display:flex;align-items:center;justify-content:center;
                border:1px dashed #21262d;border-radius:6px;color:#30363d;
                font-size:.8rem;letter-spacing:.1em;text-transform:uppercase;">
                Graph will appear after investigation
            </div>
            """, unsafe_allow_html=True)

        # Relations table
        if graph.relations:
            with st.expander(f"All Relations ({len(graph.relations)})"):
                import pandas as pd
                df = pd.DataFrame([
                    {"Source": r.src, "Relation": r.rel,
                     "Target": r.dst, "Via": r.source}
                    for r in graph.relations
                ])
                st.dataframe(df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
