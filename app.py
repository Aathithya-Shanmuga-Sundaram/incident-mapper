#!/usr/bin/env python3
"""
interactive_incident_mapper_matplotlib.py

Interactive Incident Mapper with storytelling mode and Matplotlib + NetworkX visualization.
"""

import re
from collections import defaultdict
from dateutil import parser as dtparser
import networkx as nx
import pandas as pd
import sys

# ---------------- regex helpers ----------------
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HASH_RE = re.compile(r'\b[a-fA-F0-9]{32,128}\b')
URL_RE = re.compile(r'https?://[^\s,;]+|www\.[^\s,;]+')
HOST_RE = re.compile(r'\b(?:[A-Za-z0-9][A-Za-z0-9\-\_]*\.)+[A-Za-z]{2,}\b|\b[A-Za-z0-9\-\_]+(?:\.(?:local|internal|example|svc))\b')
USER_RE = re.compile(r'\buser\s*[:=]?\s*([A-Za-z0-9_\-\.]+)\b', re.I)
TS_RE = re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}\b')
FILE_RE = re.compile(r'(/[A-Za-z0-9_\-./]+|\b[A-Za-z0-9_\-]+\.[A-Za-z0-9]{2,4}\b)')

# ---------------- helpers ----------------
def safe_parse_ts(s):
    try:
        return dtparser.parse(s)
    except Exception:
        return None

def split_csv_input(s):
    if not s:
        return []
    return [p.strip() for p in re.split(r'[,\n;]+', s) if p.strip()]

def extract_entities(line):
    ents = defaultdict(list)
    for ip in set(IP_RE.findall(line)):
        ents['ip'].append(ip)
    for h in set(HASH_RE.findall(line)):
        ents['hash'].append(h)
    for u in set(URL_RE.findall(line)):
        ents['url'].append(u)
        try:
            host = re.sub(r'https?://','',u).split('/')[0]
            ents['host'].append(host)
        except Exception:
            pass
    for h in set(HOST_RE.findall(line)):
        if h not in ents['host']:
            ents['host'].append(h)
    for u in set(USER_RE.findall(line)):
        ents['user'].append(u)
    for f in set(FILE_RE.findall(line)):
        if not IP_RE.match(f) and '.' in f and len(f) < 200:
            ents['file'].append(f)
    for t in set(TS_RE.findall(line)):
        dt = safe_parse_ts(t)
        if dt:
            ents['timestamp'].append(dt.isoformat())
    dt = safe_parse_ts(line)
    if dt:
        iso = dt.isoformat()
        if iso not in ents['timestamp']:
            ents['timestamp'].append(iso)
    return ents

def node_id(etype, value):
    return f"{etype}::{value}"

def prettify_node_label(etype, value):
    if etype=='timestamp':
        return f"TIME: {value}"
    return f"{etype.upper()}: {value}"

def add_entity_node(G, etype, value, meta=None):
    nid = node_id(etype, value)
    if not G.has_node(nid):
        G.add_node(nid, label=prettify_node_label(etype, value), type=etype, value=value)
    if meta:
        for k,v in meta.items():
            G.nodes[nid][k] = v
    return nid

def add_edge(G, a, b, **kwargs):
    if G.has_edge(a,b):
        G[a][b]['weight'] = G[a][b].get('weight',1) + 1
        ev = G[a][b].get('evidence_list', [])
        if 'evidence' in kwargs:
            ev.append(kwargs['evidence'])
            G[a][b]['evidence_list'] = ev
    else:
        G.add_edge(a, b, weight=kwargs.get('weight',1), evidence_list=[kwargs.get('evidence')] if kwargs.get('evidence') else [])

# ---------------- intake ----------------
def ask(prompt, multiline=False):
    print(prompt)
    if multiline:
        print("(End input with blank line)")
        lines = []
        while True:
            l = input()
            if l.strip() == '':
                break
            lines.append(l)
        return "\n".join(lines).strip()
    else:
        return input("> ").strip()

def intake_structured():
    print("=== Structured incident intake ===")
    time_input = ask("1) Time of attack (ISO preferred, e.g. 2025-10-01T12:03:05):")
    time_parsed = safe_parse_ts(time_input) if time_input else None
    compromised_hosts = ask("2) Compromised hosts (comma-separated):")
    exploited_vulns = ask("3) Exploited vulnerabilities (comma-separated):")
    ips_seen = ask("4) IPs seen in network (comma-separated):")
    users_compromised = ask("5) Users compromised/suspected (comma-separated):")
    malware_hashes = ask("6) Malware hashes observed (comma-separated):")
    urls_seen = ask("7) Suspicious URLs/domains (comma-separated):")
    files_seen = ask("8) Suspicious file paths/names (comma-separated):")
    additional = ask("9) Additional notes/statements:", multiline=True)

    return {
        'time_raw': time_input.strip() if time_input else '',
        'time_parsed': time_parsed.isoformat() if time_parsed else '',
        'compromised_hosts': split_csv_input(compromised_hosts),
        'exploited_vulns': split_csv_input(exploited_vulns),
        'ips_seen': split_csv_input(ips_seen),
        'users_compromised': split_csv_input(users_compromised),
        'malware_hashes': split_csv_input(malware_hashes),
        'urls_seen': split_csv_input(urls_seen),
        'files_seen': split_csv_input(files_seen),
        'additional_notes': additional
    }

# ---------------- graph building ----------------
def build_graph_from_intake(structured, freeform_lines):
    G = nx.Graph()
    parse_trace = []
    stmt_id = "stmt::structured_intake"
    G.add_node(stmt_id, label="Structured Intake", type='statement', confidence=1.0)

    # Structured info
    if structured['time_parsed']:
        ts_node = add_entity_node(G, 'timestamp', structured['time_parsed'])
        add_edge(G, stmt_id, ts_node, evidence="time_of_attack")

    for h in structured['compromised_hosts']:
        if not h: continue
        ntype = 'ip' if IP_RE.match(h) else 'host'
        n = add_entity_node(G, ntype, h)
        add_edge(G, stmt_id, n, evidence="compromised_host")

    for v in structured['exploited_vulns']:
        if not v: continue
        vnid = add_entity_node(G, 'vuln', v)
        add_edge(G, stmt_id, vnid, evidence="exploited_vuln")

    for ip in structured['ips_seen']:
        if not ip: continue
        inid = add_entity_node(G, 'ip', ip)
        add_edge(G, stmt_id, inid, evidence="ip_seen")

    for u in structured['users_compromised']:
        if not u: continue
        unid = add_entity_node(G, 'user', u)
        add_edge(G, stmt_id, unid, evidence="user_compromised")

    for h in structured['malware_hashes']:
        if not h: continue
        hid = add_entity_node(G, 'hash', h)
        add_edge(G, stmt_id, hid, evidence="malware_hash")

    for u in structured['urls_seen']:
        if not u: continue
        uid = add_entity_node(G, 'url', u)
        add_edge(G, stmt_id, uid, evidence="url_seen")

    for f in structured['files_seen']:
        if not f: continue
        fid = add_entity_node(G, 'file', f)
        add_edge(G, stmt_id, fid, evidence="file_seen")

    # Additional notes
    if structured['additional_notes']:
        for ln_idx, ln in enumerate(structured['additional_notes'].splitlines(), start=1):
            ents = extract_entities(ln)
            conf = 0.5 if ents else 0.2
            sid = node_id('stmt', f"struct_note_{ln_idx}")
            G.add_node(sid, label=ln.strip(), type='statement', confidence=conf)
            for etype, vals in ents.items():
                for v in vals:
                    ntype = 'host' if etype=='host' else etype
                    n = add_entity_node(G, ntype, v)
                    add_edge(G, sid, n, evidence="parsed_from_additional_note")
            parse_trace.append({'line_no': f"struct_{ln_idx}", 'raw': ln, 'entities': dict(ents), 'confidence': conf})

    # Freeform lines
    for idx, line in enumerate(freeform_lines, start=1):
        ents = extract_entities(line)
        conf = 0.5 if ents else 0.2
        sid = node_id('stmt', f"free_{idx}")
        G.add_node(sid, label=line.strip(), type='statement', confidence=conf)
        for etype, vals in ents.items():
            for v in vals:
                ntype = 'host' if etype=='host' else etype
                n = add_entity_node(G, ntype, v)
                add_edge(G, sid, n, evidence="parsed_from_freeform")
        parse_trace.append({'line_no': f"free_{idx}", 'raw': line, 'entities': dict(ents), 'confidence': conf})

    # ---------------- STORYTELLING ----------------
    stmt_nodes = [n for n,d in G.nodes(data=True) if d.get('type')=='statement']
    for i in range(len(stmt_nodes)-1):
        add_edge(G, stmt_nodes[i], stmt_nodes[i+1], evidence="story_sequence")

    return G, parse_trace

# ---------------- export ----------------
def export_graph_tables(G):
    nodes = [{'node_id': n, 'label': d.get('label',''), 'type': d.get('type',''), 'value': d.get('value',''), 'confidence': d.get('confidence','')} for n,d in G.nodes(data=True)]
    edges = [{'src': a, 'dst': b, 'weight': d.get('weight',1), 'evidence': d.get('evidence_list',[])} for a,b,d in G.edges(data=True)]
    pd.DataFrame(nodes).to_csv('nodes.csv', index=False)
    pd.DataFrame(edges).to_csv('edges.csv', index=False)

def export_iocs(G):
    iocs = []
    for n,d in G.nodes(data=True):
        if d.get('type') in ('ip','hash','url','host'):
            deg = G.degree(n)
            ts_neighbors = sum(1 for nbr in G.neighbors(n) if G.nodes[nbr].get('type')=='timestamp')
            score = deg + ts_neighbors
            iocs.append({'node_id': n, 'type': d.get('type'), 'value': d.get('value'), 'score': score, 'label': d.get('label')})
    if iocs:
        df = pd.DataFrame(sorted(iocs, key=lambda x: x['score'], reverse=True))
    else:
        df = pd.DataFrame([], columns=['node_id','type','value','score','label'])
    df.to_csv('iocs.csv', index=False)

def export_parse_trace(parse_trace):
    with open('parse_output.txt', 'w', encoding='utf-8') as f:
        for t in parse_trace:
            f.write(f"Line {t['line_no']} (conf={t['confidence']}): {t['raw']}\n")
            for etype, vals in t['entities'].items():
                if vals:
                    f.write(f"  {etype.upper():10s}: {', '.join(map(str, vals))}\n")
            f.write("\n")

# ---------------- matplotlib visualization ----------------
import matplotlib
import matplotlib.pyplot as plt

def visualize_matplotlib(G, filename='incident_graph.png'):
    if 'idlelib' in sys.modules:
        matplotlib.use("TkAgg")
    else:
        matplotlib.use("Agg")
    fig, ax = plt.subplots(figsize=(15,12))

    # Spring layout, centered, scaled
    pos = nx.spring_layout(G, k=1.0, seed=42, scale=2.0, center=(0,0))

    color_map = {
        'statement':'#ffd1a9',
        'ip':'#ff9999',
        'hash':'#c2f0c2',
        'url':'#99ccff',
        'host':'#ffcc99',
        'user':'#d9b3ff',
        'file':'#f2f2b3',
        'timestamp':'#d6f5f5',
        'vuln':'#ffb3e6'
    }

    node_colors = []
    node_sizes = []
    for n,d in G.nodes(data=True):
        ntype = d.get('type','statement')
        node_colors.append(color_map.get(ntype,'#cccccc'))
        node_sizes.append(1200 + 200*G.degree(n))

    labels = {n:(d.get('label')[:20]+'...' if len(d.get('label',''))>20 else d.get('label','')) for n,d in G.nodes(data=True)}

    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=node_sizes, alpha=0.9)
    nx.draw_networkx_edges(G, pos, ax=ax, width=1, alpha=0.7)
    nx.draw_networkx_labels(G, pos, labels, ax=ax, font_size=9)

    x_values, y_values = zip(*pos.values())
    x_margin = (max(x_values)-min(x_values))*0.15
    y_margin = (max(y_values)-min(y_values))*0.15
    ax.set_xlim(min(x_values)-x_margin, max(x_values)+x_margin)
    ax.set_ylim(min(y_values)-y_margin, max(y_values)+y_margin)

    ax.set_title("Incident Mapping Graph", fontsize=16)
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(filename, dpi=300)

    if 'idlelib' in sys.modules:
        plt.show()
    print(f"Graph visualization saved to {filename}")

# ---------------- banner ----------------
print(r"""
$$$$$$\                     $$\       $$\                      $$\           $$\      $$\                                                   
\_$$  _|                    \__|      $$ |                     $$ |          $$$\    $$$ |                                                  
  $$ |  $$$$$$$\   $$$$$$$\ $$\  $$$$$$$ | $$$$$$\  $$$$$$$\ $$$$$$\         $$$$\  $$$$ | $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  
  $$ |  $$  __$$\ $$  _____|$$ |$$  __$$ |$$  __$$\ $$  __$$\\_$$  _|        $$\$$\$$ $$ | \____$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
  $$ |  $$ |  $$ |$$ /      $$ |$$ /  $$ |$$$$$$$$ |$$ |  $$ | $$ |          $$ \$$$  $$ | $$$$$$$ |$$ /  $$ |$$ /  $$ |$$$$$$$$ |$$ |  \__|
  $$ |  $$ |  $$ |$$ |      $$ |$$ |  $$ |$$   ____|$$ |  $$ | $$ |$$\       $$ |\$  /$$ |$$  __$$ |$$ |  $$ |$$ |  $$ |$$   ____|$$ |      
$$$$$$\ $$ |  $$ |\$$$$$$$\ $$ |\$$$$$$$ |\$$$$$$$\ $$ |  $$ | \$$$$  |      $$ | \_/ $$ |\$$$$$$$ |$$$$$$$  |$$$$$$$  |\$$$$$$$\ $$ |      
\______|\__|  \__| \_______|\__| \_______| \_______|\__|  \__|  \____/       \__|     \__| \_______|$$  ____/ $$  ____/  \_______|\__|      
                                                                                                    $$ |      $$ |                          
                                                                                                    $$ |      $$ |                          
                                                                                                    \__|      \__|                          
                      Incident Mapper
       Developed by Aathithya Shanmuga Sundaram
""")

# ---------------- main ----------------
def main():
    structured = intake_structured()
    print("\n=== Now paste free-form incident statements (one per line). Blank line to finish. ===")
    free_lines = []
    count = 1
    while True:
        ln = input(f"free-{count:02d}> ").strip()
        if ln == "":
            break
        free_lines.append(ln)
        count += 1

    G, parse_trace = build_graph_from_intake(structured, free_lines)

    print("Exporting CSVs and parse trace...")
    export_graph_tables(G)
    export_iocs(G)
    export_parse_trace(parse_trace)
    print("nodes.csv, edges.csv, iocs.csv, parse_output.txt written.")

    print("Visualizing graph...")
    visualize_matplotlib(G)

if __name__ == '__main__':
    main()
