# 🛡️ AI-Powered SIEM System

Welcome to the **Next-Gen AI SIEM** (Security Information and Event Management) project. This system is designed to secure your infrastructure by collecting, analyzing, and detecting anomalies in system logs using advanced Machine Learning and AI.

## 🚀 Key Features

- **⚡ High Performance**: Built on a fully asynchronous architecture for maximum speed and throughput.
- **🧠 AI Analysis**: Uses Log-LLM (Large Language Model) integration to explain *why* a log is suspicious.
- **🔮 Anomaly Detection**: Automatically flags unusual behavior using Isolation Forest algorithms.
- **📊 Real-Time Dashboard**: Visualize threats and logs in an interactive Streamlit Command Center.
- **🔍 Elastic Storage**: Stores millions of logs for instant retrieval and forensic search.

---

## 📥 How to Download & Install

### Prerequisites
- **Docker Desktop**: [Download Here](https://www.docker.com/products/docker-desktop/)
- **Git**: [Download Here](https://git-scm.com/downloads)

### Installation Steps

1.  **Clone the Repository**
    Open your terminal (PowerShell or Command Prompt) and run:
    ```bash
    git clone https://github.com/Shafiyullah/siem-cyber.git
    ```
    ```bash
    cd siem-cyber
    ```    

2.  **Configure Environment**
    Create a `.env` file to secure your installation (optional but recommended):
    ```bash
    # Create a new file named .env and add:
    API_KEY=my-secret-admin-key
    ES_PASSWORD=secure-password
    ```

3.  **Run with Docker (Recommended)**
    Start the entire system with one command:
    ```bash
    docker-compose up --build -d
    ```
    *This will start Elasticsearch, the SIEM Engine, and the API.*

---

## 🎮 How to Use

### 1. accessing the Dashboard
Once running, open your browser and access the API or Dashboard (if configured separately):
- **API Docs**: `http://localhost:8000/docs`
- **Health Check**: `http://localhost:8000/health`

### 2. Monitoring Logs
The system automatically monitors logs defined in `config.py` (default: `test_logs.txt` on Windows, `/var/log/syslog` on Linux).
To simulate a threat, add a suspicious log line to `test_logs.txt`:
```text
2025-01-01T12:00:00 Failed password for user root from 192.168.1.50 port 22 ssh2
```
*The system will detect this within seconds!*

### 3. Checking Alerts
Use the API to fetch security alerts:
```bash
curl -H "X-API-Key: my-secret-admin-key" http://localhost:8000/alerts?severity=high
```

---

## 🛠️ Troubleshooting

- **"Connection Refused"**: Ensure Docker is running (`docker ps`). Wait 30 seconds for Elasticsearch to fully start.
- **"No Logs Found"**: Check if `test_logs.txt` exists and has data. The system waits for this file to be created.
- **"Memory Error"**: Elasticsearch uses significant RAM. Ensure Docker has at least 4GB allocated.

---

## 🤝 Contributing
We welcome contributions! Please fork the repo and submit a Pull Request.

---
*Built with ❤️ for Cyber Security.*
