# Incident Mapper – Cybersecurity Lab Tool

An **interactive incident mapping tool** for cybersecurity labs and exercises.
It helps students or analysts **collect, parse, and visualize security incidents** using Python. The tool maps relationships between compromised hosts, IPs, malware, URLs, files, users, and timestamps into a graph for **easy analysis**.

---

## Features

* Interactive intake of **structured incident data**:

  * Time of attack
  * Compromised hosts and users
  * Exploited vulnerabilities
  * IPs, malware hashes, URLs, and files seen
  * Freeform notes/statements
* Automatic **entity extraction** using regex:

  * IP addresses, hosts, users, file paths, URLs, hashes, timestamps
* Builds a **NetworkX graph** of entities and relationships
* Exports:

  * `nodes.csv` — list of all nodes/entities
  * `edges.csv` — list of relationships
  * `iocs.csv` — high-priority indicators of compromise (IOCs)
  * `parse_output.txt` — detailed parsed notes
* **Matplotlib-based graph visualization**:

  * Colored nodes by entity type
  * Larger/high-priority nodes for key IOCs
  * Saves as `incident_graph.png`
* Safe, self-contained Python script without heavy dependencies

---

## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/Aathithya-Shanmuga-Sundaram/incident-mapper.git
cd incident-mapper
```

2. **Install dependencies:**

```bash
pip install networkx pandas python-dateutil matplotlib
```

> Optional: For Jupyter notebooks, Matplotlib inline will work automatically.

---

## Usage

Run the script:

```bash
python app.py
```

**Steps:**

1. Answer structured questions about the incident.
2. Enter any freeform incident statements (one per line). End with a blank line.
3. The script will:

   * Parse the data
   * Build a network graph of entities
   * Export CSVs and a textual parse report
   * Generate a **graph visualization** (`incident_graph.png`)

---

## Example

**Structured input:**

```
Time of attack: 2025-10-08T10:15:00
Compromised hosts: 192.0.2.1, db01.internal
Exploited vulnerabilities: SQLi
IPs seen: 172.2.0.1
Users compromised: Carl Johnson
Malware hashes: 9fc58423aa0341dd75c031e1b2fabe0a
Suspicious URLs: example.com
Suspicious files: /admin
Notes: i suspect it's 172.2.0.1
```

**Outputs:**

* `nodes.csv` — All entities (IPs, users, hashes, hosts, URLs, timestamps)
* `edges.csv` — Relationships between entities
* `iocs.csv` — High-priority IOCs for investigation
* `parse_output.txt` — Extracted entities from notes
* `incident_graph.png` — Visualization of incident mapping

---

## Entity Types & Colors in Graph

| Entity Type   | Color  |
| ------------- | ------ |
| IP            | Red    |
| Host          | Orange |
| User          | Purple |
| File          | Yellow |
| Hash          | Green  |
| URL           | Blue   |
| Vulnerability | Pink   |
| Timestamp     | Cyan   |
| Statement     | Peach  |

High-priority nodes (connected to multiple entities or timestamp) are **larger**.

---

## Contributing

Contributions are welcome! Suggestions:

* Add new entity types (emails, ports, protocols)
* Enhance automatic entity extraction
* Add advanced graph analytics (centrality, clusters)
* Improve visualization aesthetics

Please fork the repository and submit a pull request.

---
