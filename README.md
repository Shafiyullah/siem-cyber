# AI-Powered SIEM System

Welcome to the AI-Powered SIEM (Security Information and Event Management) project. This system is designed to collect, analyze, and detect anomalies in system logs using machine learning and AI.

## 🚀 Overview

This project provides a lightweight but powerful SIEM solution that:
- **Collects Logs**: Ingests logs from various sources (syslog, auth logs, or custom files).
- **Detects Anomalies**: Uses machine learning (Isolation Forest) to identify unusual patterns in log data.
- **AI Analysis**: Leverages LLM techniques to provide context and severity assessment for logs.
- **Search & Storage**: Stores all data in Elasticsearch for fast retrieval and analysis.
- **API Access**: Provides a RESTful API built with FastAPI for querying logs and alerts.

## 🛠️ Technology Stack

- **Backend**: Python 3.14, FastAPI
- **Database**: Elasticsearch 9.2.1
- **ML/AI**: Scikit-learn, VaderSentiment
- **Infrastructure**: Docker & Docker Compose

## 📋 Prerequisites

- Docker Desktop installed on your machine.
- Git (for version control).

## ⚡ Quick Start

You can get the system up and running in just a few minutes using Docker.

1.  **Clone the repository** (if you haven't already):
    ```bash
    git clone https://github.com/YOUR_USERNAME/siem-cyber.git
    cd siem-cyber
    ```

2.  **Configure Environment**:
    Ensure you have a `.env` file. You can create one based on your needs, but the defaults in `config.py` handle most dev scenarios.
    ```bash
    # Example .env
    API_KEY=my-secret-key
    ```

3.  **Run with Docker**:
    Build and start the services:
    ```bash
    docker-compose up --build -d
    ```

4.  **Verify Installation**:
    Check if the API is running:
    ```bash
    curl http://localhost:8000/health
    ```
    You should see a JSON response indicating the status is "healthy".

## 🔌 API Endpoints

The system exposes several endpoints for interaction:

-   `GET /health`: Check system health.
-   `GET /logs`: Search through indexed logs.
-   `GET /alerts`: Retrieve generated security alerts.
-   `POST /configure`: Update log sources dynamically.

*Note: Most endpoints require the `X-API-Key` header for authentication.*

## 📝 Configuration

You can customize the system behavior by modifying `config.py` or setting environment variables in `docker-compose.yml`:

-   `LOG_SOURCES`: Comma-separated list of files to monitor.
-   `ANOMALY_THRESHOLD`: Sensitivity of the anomaly detection model.
-   `TRAINING_DAYS`: How many days of historical data to use for training.

## 🤝 Contributing

Feel free to fork this project and submit pull requests. We welcome improvements to the detection algorithms or new features!

---
*Built with ❤️ for Cyber Security.*
