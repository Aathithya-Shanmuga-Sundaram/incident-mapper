# 🛡️ Interactive Incident Mapper

## Overview

The Interactive Incident Mapper is a Streamlit application designed for Security Analysts and Incident Responders. It transforms unstructured, free-form incident notes, log lines, and structured IoCs (Indicators of Compromise) into a dynamic, visual **Network Graph** of entities (IPs, Hashes, Users, Files).

This tool allows responders to quickly map the relationships between different pieces of evidence, providing a cohesive timeline and context that is difficult to derive from raw log files alone.

## ✨ Key Features

  * **Dynamic Entity Extraction:** Automatically parses common security entities (IPs, Hashes, URLs, Timestamps, Users, Files) from any text input.
  * **Knowledge Graph Generation:** Uses **NetworkX** to build a graph where nodes are entities and edges represent a connection in the evidence or narrative.
  * **Stable Visualization:** Employs **Plotly** to render a stable, zoomable, and interactive force-directed graph with visible node labels.
  * **IOC Prioritization:** Generates a separate list of key Indicators of Compromise, scored by their connectivity within the incident, helping analysts focus on the most relevant items.
  * **Streamlit Interface:** Provides an easy-to-use, browser-based graphical interface.

## 🚀 Installation and Setup

This application requires Python 3.8 or higher.

### 1\. Clone the Repository

```bash
git clone https://github.com/Aathithya-Shanmuga-Sundaram/incident-mapper.git
cd incident-mapper
```

### 2\. Install Dependencies

All necessary libraries are listed in `requirements.txt`.

```bash
pip install -r requirements.txt
```

### 3\. Run the Application

Start the Streamlit server from the project directory.

```bash
streamlit run app.py
```

The application will automatically open in your default web browser (typically at `http://localhost:8501`).

-----

## 💻 Usage

1.  **Structured Input (Sidebar):** Use the left sidebar to input high-certainty information like the main attack time, compromised hosts, and known malware hashes.
2.  **Free-form Input (Main Area):** Paste raw log lines, timeline narrative statements, or email snippets into the large text box. The application processes each line independently.
3.  **Visualization:** The graph in the main area updates instantly as you type, mapping the relationships between the entities you enter.
4.  **Analyze Tabs:**
      * **Interactive Graph:** Visualize the network of connections. Click, drag, and zoom to explore, and hover over nodes for detailed information.
      * **Extracted IoCs:** View and download a prioritized CSV list of Indicators (IPs, Hashes, URLs) ranked by their connections within the incident.
      * **Parse Trace:** Review a log of every line processed and which entities were successfully extracted.

-----

## 🤝 Contributing

Contributions, issues, and feature requests are welcome\!
