import pytest
import time
from rule_engine import RuleEngine

def test_rule_engine_brute_force():
    engine = RuleEngine()
    
    # Simulate 3 failed logins in 10 seconds (should trigger)
    logs = [
        {"message": "password failed for user admin", "ip": "192.168.1.5", "timestamp": "2023-01-01T10:00:00"},
        {"message": "password failed for user admin", "ip": "192.168.1.5", "timestamp": "2023-01-01T10:00:05"},
        {"message": "password failed for user admin", "ip": "192.168.1.5", "timestamp": "2023-01-01T10:00:10"}
    ]
    
    alerts = []
    for log in logs:
        alerts.extend(engine.evaluate(log))
        
    assert len(alerts) == 1
    assert alerts[0]['rule_name'] == "Brute Force Detection"
    assert "3 events" in alerts[0]['message']

def test_rule_engine_window_expiry():
    engine = RuleEngine()
    
    # Simulate 2 failed logins, then wait > 60s, then 1 more (should NOT trigger)
    logs = [
        {"message": "failed login", "ip": "10.0.0.1"},
        {"message": "failed login", "ip": "10.0.0.1"},
    ]
    
    for log in logs:
        engine.evaluate(log)
        
    # Manually fast-forward time in the engine state (mocking time.time would be cleaner but this works for simple logic)
    # Actually, since RuleEngine uses time.time(), we should mock it or sleep.
    # Let's mock time.time
    
    # ... Or just define a rule with a very short window for testing
    engine.add_rule("Fast Rule", lambda l: "fail" in l.get("message"), threshold=2, window_seconds=1)
    
    engine.evaluate({"message": "fail", "ip": "1.2.3.4"})
    time.sleep(1.1)
    alerts = engine.evaluate({"message": "fail", "ip": "1.2.3.4"})
    
    assert len(alerts) == 0 # Should not trigger because window expired
