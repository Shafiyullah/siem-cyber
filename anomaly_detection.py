import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from datetime import datetime
from typing import Dict, Any, List
import hashlib

class AnomalyDetector:
    def __init__(self):
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        
    def extract_features(self, logs: List[Dict[str, Any]]) -> pd.DataFrame:
        """Extract numerical features from logs"""
        features = []
        
        for log in logs:
            feature_row = {}
            
            # Temporal features
            if 'timestamp' in log:
                try:
                    dt = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                    feature_row['hour'] = dt.hour
                    feature_row['day_of_week'] = dt.weekday()
                    feature_row['is_weekend'] = int(dt.weekday() >= 5)
                except Exception:
                    feature_row['hour'] = 0
                    feature_row['day_of_week'] = 0
                    feature_row['is_weekend'] = 0
            
            # Source features
            feature_row['source_hash'] = int(hashlib.md5(log.get('source', '').encode()).hexdigest()[:8], 16)
            
            # IP-based features
            ip = log.get('ip')
            feature_row['ip_hash'] = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16) if ip else 0
                
            # Message features
            message = log.get('message', '')
            feature_row['message_length'] = len(message)
            feature_row['word_count'] = len(message.split())
            feature_row['has_error'] = int(any(keyword in message.lower() 
                                              for keyword in ['error', 'fail', 'exception', 'denied']))
            
            features.append(feature_row)
        
        # Convert to DataFrame
        return pd.DataFrame(features).fillna(0)
    
    def fit(self, logs: List[Dict[str, Any]]):
        """Fit the anomaly detector on historical logs"""
        df_features = self.extract_features(logs)
        self.isolation_forest.fit(self.scaler.fit_transform(df_features.values))
        self.is_fitted = True
        
    def detect_anomalies(self, logs: List[Dict[str, Any]]) -> List[float]:
        """Detect anomalies and return anomaly scores"""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before detecting anomalies")
            
        df_features = self.extract_features(logs)
        anomaly_scores = self.isolation_forest.decision_function(self.scaler.transform(df_features.values))
        return anomaly_scores.tolist()
