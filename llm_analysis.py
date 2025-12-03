# In llm_analysis.py
from typing import Dict, Any, List, Optional
import os
import json
import logging
import aiohttp
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LLMAnalyzer:
    def __init__(self):
        self.sentiment_analyzer = SentimentIntensityAnalyzer()
        self.provider = os.getenv("LLM_PROVIDER", "local").lower() # local (vader), ollama, gemini
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
        self.ollama_model = os.getenv("OLLAMA_MODEL", "mistral")
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        
        self.severity_keywords = {
            'critical': ['critical', 'fatal', 'panic', 'crash', 'segmentation fault'],
            'high': ['error', 'fail', 'denied', 'blocked', 'attack', 'exception', 'unauthorized'],
            'medium': ['warning', 'unusual', 'suspicious', 'timeout', 'refused', 'non-fatal'],
            'low': ['info', 'debug', 'normal', 'success', 'accepted', 'connected']
        }

    async def analyze_log_context(self, log_message: str) -> Dict[str, Any]:
        """Analyze log message using the configured provider"""
        
        # 1. Fast Heuristics (Always run this for basic severity/sentiment)
        base_analysis = self._heuristic_analysis(log_message)
        
        # 2. Advanced LLM Analysis (Optional, if configured)
        llm_analysis = {}
        if self.provider == "ollama":
            llm_analysis = await self._query_ollama(log_message)
        elif self.provider == "gemini" and self.gemini_api_key:
            llm_analysis = await self._query_gemini(log_message)
            
        # Merge results (LLM overrides heuristics if available)
        if llm_analysis:
            base_analysis.update(llm_analysis)
            
        return base_analysis

    def _heuristic_analysis(self, log_message: str) -> Dict[str, Any]:
        """Fast, rule-based analysis"""
        try:
            # Sentiment
            sentiment_scores = self.sentiment_analyzer.polarity_scores(log_message)
            if sentiment_scores['compound'] >= 0.05:
                sentiment = {'label': 'POSITIVE', 'score': sentiment_scores['pos']}
            elif sentiment_scores['compound'] <= -0.05:
                sentiment = {'label': 'NEGATIVE', 'score': sentiment_scores['neg']}
            else:
                sentiment = {'label': 'NEUTRAL', 'score': sentiment_scores['neu']}

            # Severity
            severity = 'low'
            msg_lower = log_message.lower()
            for level, keywords in self.severity_keywords.items():
                if any(keyword in msg_lower for keyword in keywords):
                    severity = level
                    break

            return {
                'sentiment': sentiment,
                'severity': severity,
                'key_entities': self.extract_entities(log_message),
                'summary': (log_message[:97] + "...") if len(log_message) > 100 else log_message,
                'recommendation': "Monitor for recurrence." # Default
            }
        except Exception as e:
            logger.error(f"Heuristic analysis failed: {e}")
            return {'severity': 'unknown', 'error': str(e)}

    async def _query_ollama(self, log_message: str) -> Dict[str, Any]:
        """Query local Ollama instance"""
        prompt = f"""
        Analyze this system log: "{log_message}"
        Return a JSON object with:
        - severity: (low, medium, high, critical)
        - summary: (concise explanation)
        - recommendation: (actionable fix)
        Do not include any other text.
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                }
                async with session.post(self.ollama_url, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        return json.loads(result['response'])
        except Exception as e:
            logger.warning(f"Ollama query failed: {e}")
        return {}

    async def _query_gemini(self, log_message: str) -> Dict[str, Any]:
        """Query Google Gemini API"""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={self.gemini_api_key}"
        prompt = f"""
        Analyze this system log: "{log_message}"
        Return ONLY a JSON object with:
        - severity: (low, medium, high, critical)
        - summary: (concise explanation)
        - recommendation: (actionable fix)
        """
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}]
                }
                async with session.post(url, json=payload) as response:
                    if response.status == 200:
                        result = await response.json()
                        text = result['candidates'][0]['content']['parts'][0]['text']
                        # Clean markdown code blocks if present
                        text = text.replace("```json", "").replace("```", "").strip()
                        return json.loads(text)
                    else:
                        logger.error(f"Gemini API error: {await response.text()}")
        except Exception as e:
            logger.warning(f"Gemini query failed: {e}")
        return {}

    def extract_entities(self, text: str) -> List[str]:
        """Extract potential security-relevant entities"""
        entities = []
        words = text.split()
        for word in words:
            if self.is_ip_like(word):
                entities.append(f"IP:{word}")
            elif '/' in word or '\\' in word:
                entities.append(f"FILE:{word}")
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