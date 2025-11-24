# In llm_analysis.py
from typing import Dict, Any, List
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

class LLMAnalyzer:
    def __init__(self):
        # We replace the multi-GB Transformer models with
        # this single, lightweight, rule-based analyzer.
        self.sentiment_analyzer = SentimentIntensityAnalyzer()
        
        # We can expand this heuristic to be more effective
        self.severity_keywords = {
            'critical': ['critical', 'fatal', 'panic', 'crash', 'segmentation fault'],
            'high': ['error', 'fail', 'denied', 'blocked', 'attack', 'exception', 'unauthorized'],
            'medium': ['warning', 'unusual', 'suspicious', 'timeout', 'refused', 'non-fatal'],
            'low': ['info', 'debug', 'normal', 'success', 'accepted', 'connected']
        }

    def analyze_log_context(self, log_message: str) -> Dict[str, Any]:
        """Analyze log message for context and severity (Lightweight Version)"""
        try:
            # 1. Get Sentiment (fast, no GPU/ML model needed)
            sentiment_scores = self.sentiment_analyzer.polarity_scores(log_message)
            
            # Classify sentiment based on the 'compound' score
            if sentiment_scores['compound'] >= 0.05:
                sentiment = {'label': 'POSITIVE', 'score': sentiment_scores['pos']}
            elif sentiment_scores['compound'] <= -0.05:
                sentiment = {'label': 'NEGATIVE', 'score': sentiment_scores['neg']}
            else:
                sentiment = {'label': 'NEUTRAL', 'score': sentiment_scores['neu']}

            # 2. Get Severity (fast heuristic)
            severity = 'low'
            msg_lower = log_message.lower()
            for level, keywords in self.severity_keywords.items():
                if any(keyword in msg_lower for keyword in keywords):
                    severity = level
                    break  # Stop at the highest severity found

            return {
                # 'embedding' is removed, saving huge computation
                'sentiment': sentiment,
                'severity': severity,
                'key_entities': self.extract_entities(log_message),
                'summary': self.generate_summary(log_message)
            }

        except Exception as e:
            return {
                'error': str(e),
                'severity': 'unknown',
                'summary': 'Unable to analyze log'
            }
    
    # The rest of your functions (extract_entities, is_ip_like, generate_summary)
    # are already lightweight and efficient. No changes needed there.

    def extract_entities(self, text: str) -> List[str]:
        """Extract potential security-relevant entities"""
        entities = []
        words = text.split()
        for word in words:
            # IP addresses
            if self.is_ip_like(word):
                entities.append(f"IP:{word}")
            # File paths
            elif '/' in word or '\\' in word:
                entities.append(f"FILE:{word}")
            # Usernames heuristic
            elif word.startswith('user:') or 'username' in word.lower():
                entities.append(f"USER:{word}")
        return entities

    @staticmethod
    def is_ip_like(s: str) -> bool:
        parts = s.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return False

    @staticmethod
    def generate_summary(log_message: str) -> str:
        """Concise log summary (placeholder)"""
        return (log_message[:97] + "...") if len(log_message) > 100 else log_message