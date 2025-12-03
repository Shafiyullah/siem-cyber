import time
from collections import defaultdict, deque
from typing import Dict, Any, List, Optional
import logging

class RuleEngine:
    def __init__(self):
        # Rules format: {rule_name: {condition_func, threshold, window_seconds}}
        self.rules = {}
        # State: {rule_name: {key: deque([timestamps])}}
        self.state = defaultdict(lambda: defaultdict(deque))
        
        # Initialize default rules
        self.add_rule(
            name="Brute Force Detection",
            condition=lambda log: "failed" in log.get("message", "").lower() or "auth failure" in log.get("message", "").lower(),
            threshold=3,
            window_seconds=60,
            group_by="ip" # Group events by IP address
        )

    def add_rule(self, name: str, condition: callable, threshold: int, window_seconds: int, group_by: str = "ip"):
        """Add a new frequency-based rule"""
        self.rules[name] = {
            "condition": condition,
            "threshold": threshold,
            "window": window_seconds,
            "group_by": group_by
        }

    def evaluate(self, log: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate log against all rules and return triggered alerts"""
        triggered_alerts = []
        current_time = time.time()

        for rule_name, rule in self.rules.items():
            if rule["condition"](log):
                # Get the grouping key (e.g., IP address)
                key = log.get(rule["group_by"])
                if not key:
                    continue

                # Add current event timestamp
                timestamps = self.state[rule_name][key]
                timestamps.append(current_time)

                # Remove old events outside the window
                window_start = current_time - rule["window"]
                while timestamps and timestamps[0] < window_start:
                    timestamps.popleft()

                # Check threshold
                if len(timestamps) >= rule["threshold"]:
                    alert = {
                        "rule_name": rule_name,
                        "severity": "high",
                        "message": f"Rule '{rule_name}' triggered: {len(timestamps)} events in {rule['window']}s for {rule['group_by']} {key}",
                        "source_log": log,
                        "timestamp": log.get("timestamp")
                    }
                    triggered_alerts.append(alert)
                    # Optional: Clear state to avoid duplicate alerts for the same burst? 
                    # For now, we keep it to alert continuously or maybe debounce.
                    # Let's clear it to prevent spamming for the same set of events.
                    timestamps.clear() 

        return triggered_alerts
