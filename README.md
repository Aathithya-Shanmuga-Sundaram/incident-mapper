## Overview

**ConnectIR** is a specialized Streamlit application built for **Security Analysts** and **Incident Responders**. It solves the challenge of analyzing fragmented incident data by transforming unstructured, free-form notes, log lines, and structured Indicators of Compromise (IoCs) into a dynamic, visual **Knowledge Graph** of entities.

This tool helps responders instantly map the relationships between disparate pieces of evidence (IPs, Hashes, Users, Files, Timestamps), providing a **cohesive timeline and context** that is often impossible to derive from raw data or traditional spreadsheets alone.

---

## ✨ Key Features

* **Dynamic Entity Extraction:** Automatically parses and normalizes common security entities (IPs, Hashes, URLs, Timestamps, Users, Files) from any text input using sophisticated Regular Expressions.
* **Intelligent Graph Generation:** Uses **NetworkX** to build a comprehensive graph where nodes represent entities and edges establish connections based on co-occurrence in the evidence or narrative flow.
* **Stable Visualization (Plotly):** Renders a stable, zoomable, and interactive force-directed graph with visible node labels using **Plotly**, enhancing exploratory data analysis.
* **IOC Prioritization:** Generates a separate, downloadable list of key Indicators of Compromise, dynamically **scored by their connectivity** within the incident to highlight the most pivotal pieces of evidence.
* **Streamlit Interface:** Provides an intuitive, easy-to-use, browser-based graphical interface for rapid deployment and analysis.

---

## 🚀 Installation and Setup

This application requires Python 3.8 or higher.

### 1. Clone the Repository

```bash
git clone https://github.com/Aathithya-Shanmuga-Sundaram/incident-mapper.git
cd incident-mapper
```

### 2. Install Dependencies

All necessary libraries are listed in requirements.txt.

```bash
pip install -r requirements.txt
```

### 3. Run the Application

Start the Streamlit server from the project directory.

```bash
streamlit run app.py
```

The ConnectIR application will automatically open in your default web browser (typically at [http://localhost:8501](http://localhost:8501)).

---

## 💻 Usage Guide

**Structured Input (Sidebar):** Use the left sidebar to input high-certainty indicators like the main attack time, compromised hosts, and known malware hashes.

**Free-form Input (Main Area):** Paste raw log lines, timeline narrative statements, or contextual notes into the large text box. The application processes and extracts entities from each line independently.

**Visualization:** The graph in the main area updates instantly as you input data, visually mapping the relationships and flow between the entities you enter.

### Analyze Tabs:

**Interactive Graph:** Visualize the network of connections. Use the Plotly controls to zoom, pan, and hover over nodes for detailed information and context.

**Extracted IoCs:** View and download a prioritized CSV list of Indicators (IPs, Hashes, URLs) ranked by their degree of connection within the incident.

**Parse Trace:** Review a detailed log of every line processed and the specific entities successfully extracted, along with the calculated confidence score.

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!
