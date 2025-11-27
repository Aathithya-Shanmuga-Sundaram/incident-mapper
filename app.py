import streamlit as st
import re
from collections import defaultdict
from dateutil import parser as dtparser
import networkx as nx
import pandas as pd
from io import BytesIO
import streamlit.components.v1 as components
from pyvis.network import Network
import os
import matplotlib.pyplot as plt
import plotly.graph_objects as go

# --- Configuration & Styling ---
st.set_page_config(
    page_title="BlackSpine: Incident Knowledge Mapper",  
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- REGEX HELPERS ----------------
# Regular expressions for automatic entity extraction
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HASH_RE = re.compile(r'\b[a-fA-F0-9]{32,128}\b')
URL_RE = re.compile(r'https?://[^\s,;]+|www\.[^\s,;]+')
HOST_RE = re.compile(r'\b(?:[A-Za-z0-9][A-Za-z0-9\-\_]*\.)+[A-Za-z]{2,}\b|\b[A-Za-z0-9\-\_]+(?:\.(?:local|internal|example|svc))\b')
USER_RE = re.compile(r'\buser\s*[:=]?\s*([A-Za-z0-9_\-\.]+)\b', re.I)
TS_RE = re.compile(r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}\b')
FILE_RE = re.compile(r'(/[A-Za-z0-9_\-./]+|\b[A-Za-z0-9_\-]+\.[A-Za-z0-9]{2,4}\b)')

# ---------------- UTILITY HELPERS ----------------
def safe_parse_ts(s):
    """Safely parses a string into a datetime object."""
    try:
        return dtparser.parse(s)
    except Exception:
        return None

def split_csv_input(s):
    """Splits input string by common delimiters (comma, newline, semicolon)."""
    if not s:
        return []
    return [p.strip() for p in re.split(r'[,\n;]+', s) if p.strip()]

def extract_entities(line):
    """Extracts common threat intelligence entities from a single line of text."""
    ents = defaultdict(list)
    for ip in set(IP_RE.findall(line)): ents['ip'].append(ip)
    for h in set(HASH_RE.findall(line)): ents['hash'].append(h)
    for u in set(URL_RE.findall(line)): 
        ents['url'].append(u)
        try:
            host = re.sub(r'https?://','',u).split('/')[0]
            ents['host'].append(host)
        except Exception:
            pass
    for h in set(HOST_RE.findall(line)): 
        if h not in ents['host']: ents['host'].append(h)
    for u in set(USER_RE.findall(line)): ents['user'].append(u)
    for f in set(FILE_RE.findall(line)):
        if not IP_RE.match(f) and '.' in f and len(f) < 200: ents['file'].append(f)
    for t in set(TS_RE.findall(line)):
        dt = safe_parse_ts(t)
        if dt: ents['timestamp'].append(dt.isoformat())
    dt = safe_parse_ts(line)
    if dt:
        iso = dt.isoformat()
        if iso not in ents['timestamp']: ents['timestamp'].append(iso)
    return ents

def node_id(etype, value):
    """Creates a unique node ID."""
    return f"{etype}::{value}"

def prettify_node_label(etype, value):
    """Creates a display label for the node."""
    if etype=='timestamp':
        return f"TIME: {value.split('T')[-1].split('+')[0]}"
    
    # Simplify label for on-graph display to prevent clutter
    if len(value) > 20 and etype not in ('timestamp', 'statement'):
        return f"{etype.upper()}: {value[:17]}..."
        
    return f"{etype.upper()}: {value}"

# Function to get the simplified label for display on the graph
def get_display_label(etype, value):
    """Creates a concise display label for the node, used for on-graph text."""
    if etype in ('ip', 'hash', 'url', 'host'):
        return value
    if etype == 'user':
        return f"User: {value}"
    if etype == 'timestamp':
        return value.split('T')[-1].split('+')[0]
    if etype == 'statement':
        return value[:30] + '...' if len(value) > 30 else value
    return value

def add_entity_node(G, etype, value, meta=None):
    """Adds a node to the graph if it doesn't exist."""
    nid = node_id(etype, value)
    if not G.has_node(nid):
        G.add_node(nid, label=prettify_node_label(etype, value), display_label=get_display_label(etype, value), type=etype, value=value)
    if meta:
        for k,v in meta.items():
            G.nodes[nid][k] = v
    return nid

def add_edge(G, a, b, **kwargs):
    """Adds an edge, or increases its weight and adds evidence if it exists."""
    if G.has_edge(a,b):
        G[a][b]['weight'] = G[a][b].get('weight',1) + 1
        ev = G[a][b].get('evidence_list', [])
        evidence = kwargs.get('evidence')
        if evidence and evidence not in ev:
            ev.append(evidence)
            G[a][b]['evidence_list'] = ev
    else:
        evidence_list = [kwargs.get('evidence')] if kwargs.get('evidence') else []
        G.add_edge(a, b, weight=kwargs.get('weight',1), evidence_list=evidence_list)

# ---------------- GRAPH BUILDING ----------------
def build_graph_from_intake(structured_data, freeform_lines):
    """Constructs the NetworkX graph from structured and free-form input."""
    G = nx.Graph()
    parse_trace = []
    stmt_id = "stmt::structured_intake"
    G.add_node(stmt_id, label="Structured Intake Summary", display_label="Structured Intake", type='statement', confidence=1.0)

    # 1. Structured Info
    if structured_data.get('time_parsed'):
        ts_node = add_entity_node(G, 'timestamp', structured_data['time_parsed'])
        add_edge(G, stmt_id, ts_node, evidence="time_of_attack")

    entity_map = {
        'compromised_hosts': ('ip', 'host'), 'exploited_vulns': 'vuln', 
        'ips_seen': 'ip', 'users_compromised': 'user', 
        'malware_hashes': 'hash', 'urls_seen': 'url', 
        'files_seen': 'file'
    }

    for key, etype in entity_map.items():
        if isinstance(etype, tuple):
            for h in structured_data.get(key, []):
                if not h: continue
                ntype = etype[0] if IP_RE.match(h) else etype[1]
                n = add_entity_node(G, ntype, h)
                add_edge(G, stmt_id, n, evidence=key)
        else:
            for v in structured_data.get(key, []):
                if not v: continue
                n = add_entity_node(G, etype, v)
                add_edge(G, stmt_id, n, evidence=key)

    # 2. Additional notes
    if structured_data.get('additional_notes'):
        for ln_idx, ln in enumerate(structured_data['additional_notes'].splitlines(), start=1):
            if not ln.strip(): continue
            ents = extract_entities(ln)
            conf = 0.6 if ents else 0.3
            sid = node_id('stmt', f"struct_note_{ln_idx}")
            G.add_node(sid, label=ln.strip(), display_label=get_display_label('statement', ln.strip()), type='statement', confidence=conf)
            add_edge(G, stmt_id, sid, evidence="additional_note")
            
            for etype, vals in ents.items():
                for v in vals:
                    ntype = 'host' if etype=='host' else etype
                    n = add_entity_node(G, ntype, v)
                    add_edge(G, sid, n, evidence="parsed_from_additional_note")
            parse_trace.append({'line_no': f"struct_{ln_idx}", 'raw': ln, 'entities': dict(ents), 'confidence': conf})

    # 3. Freeform lines
    for idx, line in enumerate(freeform_lines, start=1):
        if not line.strip(): continue
        ents = extract_entities(line)
        conf = 0.7 if ents else 0.4
        sid = node_id('stmt', f"free_{idx}")
        G.add_node(sid, label=line.strip(), display_label=get_display_label('statement', line.strip()), type='statement', confidence=conf)
        for etype, vals in ents.items():
            for v in vals:
                ntype = 'host' if etype=='host' else etype
                n = add_entity_node(G, ntype, v)
                add_edge(G, sid, n, evidence="parsed_from_freeform")
        parse_trace.append({'line_no': f"free_{idx}", 'raw': line, 'entities': dict(ents), 'confidence': conf})

    # 4. Storytelling: Sequential link between all statement nodes
    stmt_nodes = sorted([n for n,d in G.nodes(data=True) if d.get('type')=='statement'], key=lambda x: x.split('::')[-1])
    for i in range(len(stmt_nodes)-1):
        # Edge to show the flow/sequence of events (narrative)
        add_edge(G, stmt_nodes[i], stmt_nodes[i+1], evidence="story_sequence") 

    return G, parse_trace

# ---------------- EXPORT/DISPLAY FUNCTIONS ----------------

def export_iocs(G):
    """Generates a DataFrame of key IoCs scored by connectivity (commonality)."""
    iocs = []
    for n,d in G.nodes(data=True):
        if d.get('type') in ('ip','hash','url','host'):
            deg = G.degree(n)
            ts_neighbors = sum(1 for nbr in G.neighbors(n) if G.nodes[nbr].get('type')=='timestamp')
            # Score = Connectivity + Proximity to time-based events
            score = deg + ts_neighbors
            iocs.append({'node_id': n, 'type': d.get('type'), 'value': d.get('value'), 'score': score, 'label': d.get('label')})
            
    if iocs:
        df = pd.DataFrame(sorted(iocs, key=lambda x: x['score'], reverse=True))
    else:
        df = pd.DataFrame([], columns=['node_id','type','value','score','label'])
        
    return df

# ---------------- PLOTLY VISUALIZATION (FIXED + LABELS ADDED) ----------------
def visualize_plotly(G):
    """
    Generates a static and stable Plotly network visualization with labels.
    """
    if not G.number_of_nodes():
        st.info("The graph is empty. Please enter data to visualize.")
        return

    # --- 1. Map Node Attributes and Calculate Layout ---
    color_map = {
        'statement': '#F0F8FF', 'ip': '#FF4B4B', 'hash': '#4ECDC4',         
        'url': '#FFC300', 'host': '#4682B4', 'user': '#8A2BE2',         
        'file': '#3CB371', 'timestamp': '#FF69B4', 'vuln': '#FF8C00'
    }
    
    # Calculate initial positions using NetworkX's Spring Layout (stable, force-directed)
    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)
    
    # --- 2. Build Edge Trace ---
    edge_x = []
    edge_y = []
    
    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        
        # Add line segments for the edge
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none', 
        mode='lines'
    )
    
    # --- 3. Build Node Trace ---
    node_x = []
    node_y = []
    hover_texts = []
    node_labels = [] 
    node_colors = []
    node_sizes = []

    for node_id, data in G.nodes(data=True):
        x, y = pos[node_id]
        node_x.append(x)
        node_y.append(y)
        
        ntype = data.get('type', 'statement')
        
        # Hover text is the full, detailed label
        hover_title = f"<b>{ntype.upper()}</b>: {data.get('value', 'N/A')}<br>Connections: {G.degree(node_id)}"
        
        # Display text is the simplified label
        display_label = data.get('display_label', data.get('value', 'N/A'))
        
        hover_texts.append(hover_title)
        node_labels.append(display_label) # <-- Populate display labels
        node_colors.append(color_map.get(ntype, '#cccccc'))
        node_sizes.append(10 + G.degree(node_id) * 3) 

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text', 
        hoverinfo='text',
        text=node_labels, 
        hovertext=hover_texts, 
        textposition="bottom center", 
        marker=dict(
            color=node_colors,
            size=node_sizes,
            line_width=2,
            line_color='#fff' 
        )
    )

    # --- 4. Create Figure and Display ---
    fig = go.Figure(data=[edge_trace, node_trace],
                layout=go.Layout(
                    # Correct structure for title font size
                    title=dict(
                        text='<br>BlackSpine Incident Entity Graph (Plotly)',  
                        font=dict(size=16)
                    ),
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20,l=5,r=5,t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    plot_bgcolor='#222222', 
                    paper_bgcolor='#222222',
                    font=dict(color='white')
                )
            )

    # Display the Plotly figure in Streamlit
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': True})
    
    st.markdown("*(Graph now displays labels directly on the nodes. Hovering still provides detailed information. Use **Display Mode Bar** to zoom/pan.)*")


# ---------------- STREAMLIT UI LAYOUT ----------------

def main_app():
    st.title("🛡BlackSpine: Incident Knowledge Mapper")  
    st.markdown("Map your incident response data into a visual graph of entities and events. **The map updates automatically after every input change.**")

    # --- Sidebar Input ---
    with st.sidebar:
        st.header("1. Structured Input")
        st.markdown("Enter high-certainty information.")
        
        time_input = st.text_input("Time of Attack (ISO preferred)", help="e.g., 2025-10-01T12:03:05")
        
        st.subheader("Indicators")
        compromised_hosts = st.text_area("Compromised Hosts", help="Comma/newline separated list of hostnames or IPs.")
        ips_seen = st.text_area("External/Suspicious IPs Seen", help="Comma/newline separated IPs (e.g., C2).")
        urls_seen = st.text_area("Suspicious URLs/Domains", help="Comma/newline separated list.")
        malware_hashes = st.text_area("Malware Hashes", help="Comma/newline separated hashes (MD5, SHA256 etc.).")

        st.subheader("Context")
        users_compromised = st.text_area("Compromised Users", help="Comma/newline separated usernames.")
        exploited_vulns = st.text_area("Exploited Vulnerabilities", help="Comma/newline separated list (e.g., CVE-2023-XXXX).")
        files_seen = st.text_area("Suspicious File Paths/Names", help="Comma/newline separated list.")
        
        st.subheader("Additional Notes (Free-form)")
        additional_notes = st.text_area("General Incident Notes", help="Any other contextual text or narrative.")

    # --- Main Area Processing ---
    
    # Consolidate Structured Data
    time_parsed_result = safe_parse_ts(time_input)
    structured_data = {
        'time_raw': time_input,
        'time_parsed': time_parsed_result.isoformat() if time_parsed_result else '',
        'compromised_hosts': split_csv_input(compromised_hosts),
        'exploited_vulns': split_csv_input(exploited_vulns),
        'ips_seen': split_csv_input(ips_seen),
        'users_compromised': split_csv_input(users_compromised),
        'malware_hashes': split_csv_input(malware_hashes),
        'urls_seen': split_csv_input(urls_seen),
        'files_seen': split_csv_input(files_seen),
        'additional_notes': additional_notes
    }

    st.header("2. Free-form Evidence Timeline")
    free_form_input = st.text_area(
        "Paste Log Lines or Narrative Statements Here (one entry per line)",
        height=200,
        placeholder="e.g., Host WIN-SRV01 executed C:\\temp\\loader.exe (sha256:a1b2c3d4e5...) at 2025-10-01T12:03:05. It then made a connection to 192.168.1.10."
    )
    free_form_lines = free_form_input.splitlines()

    # --- DYNAMIC GRAPH GENERATION ---
    
    if not (time_input or compromised_hosts or free_form_input or additional_notes):
        st.info("Start entering data in the sidebar or free-form area to generate the map dynamically.")

        st.markdown("---")
        st.markdown("<p style='text-align: center; color: gray;'>Developed by Aathithya Shanmuga Sundaram #MakeEveryoneCyberSafe</p>", unsafe_allow_html=True)  
        return

    with st.spinner("Updating Knowledge Graph and Visualization..."):
        G, parse_trace = build_graph_from_intake(structured_data, free_form_lines)
        st.session_state['G'] = G
        st.session_state['parse_trace'] = parse_trace

    st.success(f"Graph updated! **{G.number_of_nodes()}** nodes and **{G.number_of_edges()}** edges generated.")

    # --- Display Results ---

    if 'G' in st.session_state:
        G = st.session_state['G']
        parse_trace = st.session_state['parse_trace']

        st.markdown("---")
        st.header("3. Visualization and IoCs")
        
        tab1, tab2, tab3 = st.tabs(["📊 Interactive Graph", "📋 Extracted IoCs", "🔍 Parse Trace"])

        with tab1:
            st.subheader("Interactive Incident Entity Graph")
            
            # CALLS THE FIXED PLOTLY FUNCTION WITH LABELS
            visualize_plotly(G)

        with tab2:
            st.subheader("Key Indicators of Compromise (IoCs)")
            ioc_df = export_iocs(G)
            
            if not ioc_df.empty:
                st.dataframe(ioc_df, hide_index=True, use_container_width=True)
                
                csv_data = ioc_df.to_csv(index=False).encode('utf-8')
                st.download_button(
                    label="Download IoC List (.csv)",
                    data=csv_data,
                    file_name="iocs.csv",
                    mime="text/csv"
                )
            else:
                st.info("No common Indicators of Compromise (IPs, Hashes, URLs, Hosts) were extracted.")

        with tab3:
            st.subheader("Entity Extraction Log")
            
            trace_data = []
            for t in parse_trace:
                entities_str = "\n".join([f"  - **{k.upper()}**: {', '.join(map(str, v))}" for k, v in t['entities'].items() if v])
                trace_data.append({
                    'Line ID': t['line_no'],
                    'Confidence': f"{t['confidence']:.1f}",
                    'Raw Statement': t['raw'],
                    'Extracted Entities': entities_str
                })
            
            if trace_data:
                st.dataframe(pd.DataFrame(trace_data), use_container_width=True, hide_index=True)
            else:
                st.info("No entities were extracted from the free-form input.")
    st.markdown("---")
    st.markdown("<p style='text-align: center; color: gray;'>Developed by Aathithya Shanmuga Sundaram #MakeEveryoneCyberSafe</p>", unsafe_allow_html=True)  

if __name__ == '__main__':
    main_app()
