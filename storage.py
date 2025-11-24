# In storage.py
from elasticsearch import Elasticsearch, helpers
from typing import Dict, Any, List
import logging
from config import Config 

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class ElasticsearchStorage:
    def __init__(self):
        # Use passed-in values, which will come from Config via SIEMEngine
        host = Config.ES_HOST
        port = Config.ES_PORT
        self.es = Elasticsearch([{'host': host, 'port': port, 'scheme': 'http'}]) # SECURITY NOTE: In production, use 'https' and add auth credentials
        self.index_name = "siem_logs"
        self._create_index()

    def _create_index(self):
        """Create Elasticsearch index with proper mappings"""
        mapping = {
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "source": {"type": "keyword"},
                    "message": {"type": "text"},
                    "ip": {"type": "ip"},
                    "severity": {"type": "keyword"}, # Use .keyword for aggregation
                    "anomaly_score": {"type": "float"},
                    "ai_analysis": { # Store AI analysis as an object
                        "type": "object", 
                        "enabled": False # Don't index sub-fields by default
                    },
                    "raw_log": {"type": "text", "index": False} # No need to search raw log
                }
            }
        }
        if not self.es.indices.exists(index=self.index_name):
            try:
                self.es.indices.create(index=self.index_name, body=mapping)
                logging.info(f"Created index: {self.index_name}")
            except Exception as e:
                logging.error(f"Failed to create index: {e}")

    def is_connected(self) -> bool:
        """Check if Elasticsearch is connected"""
        return self.es.ping()

    def store_log(self, log_data: Dict[str, Any]):
        """Store single log in Elasticsearch (less efficient)"""
        try:
            self.es.index(index=self.index_name, document=log_data)
        except Exception as e:
            logging.error(f"Error storing log: {e}")

    def store_bulk_logs(self, logs: List[Dict[str, Any]]):
        """Store multiple logs efficiently (MORE efficient)"""
        actions = [
            {"_index": self.index_name, "_source": log} for log in logs
        ]
        if not actions:
            return
            
        try:
            helpers.bulk(self.es, actions)
        except Exception as e:
            logging.error(f"Error storing bulk logs: {e}")

    def search_logs(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        """Search logs with given query"""
        try:
            result = self.es.search(index=self.index_name, body=query, size=size)
            return [hit['_source'] for hit in result['hits']['hits']]
        except Exception as e:
            logging.error(f"Error searching logs: {e}")
            return []