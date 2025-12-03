# Contributing to AI-Powered SIEM

Thank you for your interest in contributing to the AI-Powered SIEM project! We welcome contributions from the cybersecurity community to make this tool more robust and intelligent.

## 🚀 Getting Started

### Prerequisites
-   **Docker Desktop**: Required for running the stack.
-   **Python 3.12+**: For local development.
-   **Git**: For version control.

### Setup Environment
1.  **Fork and Clone**:
    ```bash
    git clone https://github.com/Shafiyullah/siem-cyber.git
    ```

    ```bash
    cd siem-cyber
    ```

2.  **Create Virtual Environment**:
    ```bash
    python -m venv venv
    ```

    ```bash
    pip install -r requirements.txt
    ```

    # On Windows: venv\Scripts\activate
    ```bash
    source venv/bin/activate  
    ```

3.  **Environment Variables**:
    Copy `.env.example` to `.env` (create one if missing):
    ```ini
    ES_HOST=localhost
    ES_PORT=9200
    ES_USER=elastic
    ES_PASSWORD=changeme
    LLM_PROVIDER=ollama # or gemini
    ```

## 🧪 Running Tests
We use `pytest` for testing. Please ensure all tests pass before submitting a PR.
```bash
pytest tests/
```

## 🛠️ Development Workflow

### Adding a New Rule
1.  Open `rule_engine.py`.
2.  Add your rule logic in the `__init__` method or create a new method.
3.  Add a test case in `tests/test_rule_engine.py`.

### Improving AI Analysis
1.  Modify `llm_analysis.py`.
2.  If adding a new provider, ensure it implements the `analyze_log_context` interface.

## 📝 Style Guide
-   Follow **PEP 8** for Python code.
-   Use **Type Hints** where possible.
-   Write clear commit messages (e.g., `feat: add brute force detection rule`).

## 🤝 Community
-   Join our [GitHub Discussions](https://github.com/Shafiyullah/siem-cyber/discussions).
-   Open an [Issue](https://github.com/Shafiyullah/siem-cyber/issues) for bugs or feature requests.

We look forward to your PRs! 🛡️
