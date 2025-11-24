# In siem_engine.py
import asyncio
import json
from typing import Dict, Any, List
from log_collector import LogCollector
from storage import ElasticsearchStorage
from anomaly_detection import AnomalyDetector
from llm_analysis import LLMAnalyzer
from config import Config
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class SIEMEngine:
    def __init__(self):
        # Read from Config for proper initialization
        self.storage = ElasticsearchStorage()
        self.anomaly_detector = AnomalyDetector()
        self.llm_analyzer = LLMAnalyzer()
        self.collector = None
        self.alert_threshold = Config.ANOMALY_THRESHOLD  # Use Config
        self.training_days = Config.TRAINING_DAYS      # Use Config

    async def initialize(self, log_sources: List[str]):
        """Initialize SIEM engine with log sources"""
        self.collector = LogCollector(log_sources, self.storage)

        # Load historical logs for anomaly detection training
        historical_logs = self.load_historical_logs(days_back=self.training_days)
        if historical_logs:
            try:
                self.anomaly_detector.fit(historical_logs)
                logging.info(f"Trained anomaly detector on {len(historical_logs)} historical logs")
            except Exception as e:
                logging.error(f"Failed to train anomaly detector: {e}. Check log format.")
        else:
            logging.warning("No historical logs found for training. Anomaly detector is not fitted.")

    def load_historical_logs(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """Load historical logs for training"""
        query = {
            "query": {
                "range": {
                    "timestamp": {
                        "gte": f"now-{days_back}d/d",
                        "lt": "now/d"
                    }
                }
            }
        }
        return self.storage.search_logs(query, size=10000)

    async def process_log_batch(self, logs: List[Dict[str, Any]]):
        """Process a batch of logs through analysis pipeline"""
        if not logs:
            return

        # Step 1: LLM Analysis (Now lightweight)
        # We process logs one by one, but it's fast now
        analyzed_logs = []
        for log in logs:
            ai_analysis = self.llm_analyzer.analyze_log_context(
                log.get('message', log.get('raw_log', ''))
            )
            log['ai_analysis'] = ai_analysis
            log['severity'] = ai_analysis.get('severity', 'unknown')
            analyzed_logs.append(log)

        # Step 2: Anomaly Detection
        if self.anomaly_detector.is_fitted:
            try:
                anomaly_scores = self.anomaly_detector.detect_anomalies(analyzed_logs)
                for log, score in zip(analyzed_logs, anomaly_scores):
                    log['anomaly_score'] = float(score)
            except Exception as e:
                logging.error(f"Error during anomaly detection: {e}")
                for log in analyzed_logs:
                    log['anomaly_score'] = 0.0 # Default score on error
        else:
            for log in analyzed_logs:
                log['anomaly_score'] = 0.0 # Default score if not fitted

        # Step 3: Store and Alert
        # OPTIMIZATION: Store all logs in one bulk request
        self.storage.store_bulk_logs(analyzed_logs)

        # Now, generate alerts for anomalous logs
        for log in analyzed_logs:
            if log.get('anomaly_score', 0) < self.alert_threshold:
                await self.generate_alert(log)

    def _infer_severity(self, message: str) -> str:
        """Heuristic severity inference - This is now handled by LLMAnalyzer"""
        # We can keep this as a fallback if needed, but llm_analysis.py
        # is the primary source now.
        return self.llm_analyzer.analyze_log_context(message)['severity']

    async def generate_alert(self, log: Dict[str, Any]):
        """Generate security alert for anomalous log"""
        alert = {
            'timestamp': log['timestamp'],
            'severity': log.get('severity', 'high'),
            'anomaly_score': log.get('anomaly_score'),
            'source': log.get('source'),
            'message': log.get('message', log.get('raw_log', '')),
            'ai_summary': log.get('ai_analysis', {}).get('summary', ''),
            'recommendation': self.generate_recommendation(log)
        }
        logging.warning(f"SECURITY ALERT: {json.dumps(alert)}")
        # In production, you would push this to Config.ALERT_WEBHOOK or
        # send via email using Config.ALERT_EMAIL

    def generate_recommendation(self, log: Dict[str, Any]) -> str:
        """Generate actionable recommendation based on log analysis"""
        severity = log.get('severity', 'unknown')
        message = log.get('message', '').lower()

        if 'denied' in message or 'blocked' in message or 'unauthorized' in message:
            return "Investigate potential unauthorized access attempt. Check source IP and user."
        elif 'error' in message or 'fail' in message or 'exception' in message:
            return "Check system health and application logs for root cause of this error."
        elif severity == 'critical':
            return "Immediate investigation required - potential system crash or security incident."
        else:
            return "Monitor for similar patterns and investigate if recurring."

    async def start_monitoring(self):
        """Start continuous log monitoring FOR REAL"""
        logging.info("Starting SIEM monitoring...")
        if not self.collector:
            logging.error("Collector not initialized. Call initialize() first.")
            return

        # Create a list of monitoring tasks, one for each log source
        tasks = [
            asyncio.create_task(self.run_collector(source))
            for source in self.collector.log_sources
        ]
        
        if tasks:
            logging.info(f"Monitoring {len(tasks)} log sources...")
            await asyncio.gather(*tasks) # Run all monitoring tasks concurrently
        else:
            logging.warning("No log sources configured to monitor.")

    async def run_collector(self, source: str):
        """Helper function to run a single collector and batch its logs"""
        batch_size = 100
        log_batch = []
        try:
            # We now use the ASYNC generator from log_collector
            async for log in self.collector.collect_from_file(source):
                if log:
                    log_batch.append(log)
                    if len(log_batch) >= batch_size:
                        await self.process_log_batch(log_batch)
                        log_batch = []
        except Exception as e:
            logging.error(f"Collector for {source} failed: {e}", exc_info=True)
        finally:
            # Process any remaining logs before exiting
            if log_batch:
                await self.process_log_batch(log_batch)