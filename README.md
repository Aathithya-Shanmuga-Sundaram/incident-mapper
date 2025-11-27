# BlackSpine

## Overview

**BlackSpine** is a precision‑engineered Streamlit platform built for **Security Analysts**, **Threat Hunters**, and **Incident Responders** who refuse to operate blindly. It cuts through fragmented evidence, scattered logs, and free‑form notes by converting them into a structured, visual **Incident Intelligence Graph**.

BlackSpine exposes the hidden backbone of an incident — the relationships, timelines, pivots, and dependencies that are usually buried inside disconnected text. It reveals what actually holds the incident together, giving responders an immediate strategic view that ordinary tools never surface.

---

## ✨ Key Features

* **Adaptive Entity Extraction:** Identifies and normalizes IPs, domains, hashes, URLs, files, usernames, timestamps, and more using robust pattern logic.
* **Context‑Driven Graph Construction:** Builds a dynamic, interconnected graph with **NetworkX**, linking entities based on real co‑occurrence and narrative relevance.
* **High‑Stability Visualization:** Uses **Plotly** to render a smooth, interactive, zoom‑ready force graph with clearly visible node labels.
* **IOC Influence Ranking:** Generates a downloadable list of Indicators of Compromise, automatically ranked by structural importance (graph degree + relational weight).
* **Streamlined IR Interface:** A clean, rapid, browser‑native workflow designed specifically for real‑world analyst pressure.

---

## 🚀 Installation and Setup

Python **3.8+** is required.

### 1. Clone the Repository

```bash
git clone https://github.com/Aathithya-Shanmuga-Sundaram/BlackSpine.git
cd BlackSpine
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Launch BlackSpine

```bash
streamlit run app.py
```

The interface opens automatically (generally at [http://localhost:8501](http://localhost:8501)).

---

## 💻 Usage Guide

### Structured Inputs (Sidebar)

Feed in reliable, high‑confidence indicators such as:

* Primary attack timestamps
* Compromised assets
* Verified malware hashes

### Free‑Form Inputs (Main Panel)

Paste:

* Log fragments
* Narrative notes
* Analyst observations
* Timelines

BlackSpine extracts entities line‑by‑line and injects them into the graph.

### Visualization

The graph updates instantly, exposing:

* Hidden relationships
* Lateral pivots
* Contextual clusters
* Temporal patterns

### Analysis Tabs

**Interactive Graph:**
Explore the full relational map. Zoom, hover, and pan to inspect nodes and edges.

**Extracted IoCs:**
Download a ranked CSV of IPs, hashes, and URLs sorted by their structural importance.

**Parse Trace:**
Review a granular log of how each line was interpreted and which entities were successfully extracted.

---

## 🤝 Contributing

Suggestions, enhancements, and pull requests are always welcome. BlackSpine grows stronger with every contributor who sharpens its spine.
