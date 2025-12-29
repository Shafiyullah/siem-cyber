# In config.py
import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class Config:
    # Elasticsearch
    ES_HOST = os.getenv('ES_HOST', 'localhost')
    ES_PORT = int(os.getenv('ES_PORT', 9200))
    ES_USER = os.getenv('ES_USER', 'elastic')
    ES_PASSWORD = os.getenv('ES_PASSWORD', 'changeme')
    ES_INDEX_NAME = os.getenv('ES_INDEX_NAME', 'siem_logs')

    # Log Sources
    _default_sources = '/var/log/syslog,/var/log/auth.log'
    if os.name == 'nt':
        _default_sources = 'test_logs.txt' # Default for Windows dev
        
    LOG_SOURCES = [src.strip() for src in os.getenv(
        'LOG_SOURCES', _default_sources
    ).split(',') if src.strip()]

    # Anomaly Detection
    ANOMALY_THRESHOLD = float(os.getenv('ANOMALY_THRESHOLD', '-0.5'))
    TRAINING_DAYS = int(os.getenv('TRAINING_DAYS', '7'))

    # Alerting
    ALERT_WEBHOOK = os.getenv('ALERT_WEBHOOK')
    ALERT_EMAIL = os.getenv('ALERT_EMAIL')
    
    # --- SECURITY ---
    # Add a secure, random string here in your .env file
    # e.g., openssl rand -hex 32
    API_KEY = os.getenv('API_KEY')
    if not API_KEY:
        # Fallback for development only - DO NOT USE IN PRODUCTION
        API_KEY = "dev-secret-key"