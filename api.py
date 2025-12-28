# In api.py
import logging
import asyncio
from fastapi import FastAPI, HTTPException, Query, Security, Depends
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional
from siem_engine import SIEMEngine
from config import Config

app = FastAPI(title="AI-Powered SIEM API")

# Initialize SIEM engine
siem_engine = SIEMEngine()

# --- SECURITY ---
api_key_header = APIKeyHeader(name="X-API-Key")

async def get_api_key(api_key: str = Security(api_key_header)):
    """Check if API key is valid"""
    if Config.API_KEY and api_key == Config.API_KEY:
        return api_key
    raise HTTPException(status_code=403, detail="Could not validate credentials")

# Request Models
class LogSource(BaseModel):
    sources: List[str]


@app.on_event("startup")
async def startup_event():
    """
    CRITICAL: Initialize SIEM and start monitoring in the background.
    This is what actually starts your engine.
    """
    logging.info(f"Initializing SIEM with sources: {Config.LOG_SOURCES}")
    try:
        await siem_engine.initialize(Config.LOG_SOURCES)
        
        # Start the monitoring task in the background
        asyncio.create_task(siem_engine.start_monitoring())
        logging.info("SIEM monitoring task started in background.")
    except Exception as e:
        logging.error(f"Failed to initialize SIEM engine: {e}")
        logging.error("The API will continue to run, but SIEM features may be unavailable.")


@app.post("/configure", dependencies=[Depends(get_api_key)])
async def configure_sources(sources: LogSource):
    """Re-configure and initialize log sources (protected)"""
    await siem_engine.stop_monitoring()
    await siem_engine.initialize(sources.sources)
    asyncio.create_task(siem_engine.start_monitoring())
    return {"status": "configured", "sources": sources.sources}


@app.get("/alerts", dependencies=[Depends(get_api_key)])
async def get_alerts(
    severity: Optional[str] = Query(None, description="Severity filter (e.g., high, critical)"),
    time_range: Optional[str] = Query("1h", description="Time range (e.g., 1h, 6h, 24h, 7d)")
):
    """Get security alerts (protected)"""
    query_body = {
        "query": {"bool": {"must": []}},
        "sort": [{"timestamp": {"order": "desc"}}]
    }

    if severity:
        # Validate severity
        allowed_severities = ['low', 'medium', 'high', 'critical']
        if severity.lower() not in allowed_severities:
            raise HTTPException(status_code=400, detail="Invalid severity")
        query_body["query"]["bool"]["must"].append({"term": {"severity.keyword": severity.lower()}})

    # Validate and apply time filter
    time_ranges = {
        "1h": "now-1h/h",
        "6h": "now-6h/h",
        "24h": "now-24h/d",
        "7d": "now-7d/d"
    }
    time_filter = time_ranges.get(time_range)
    if not time_filter:
        raise HTTPException(status_code=400, detail="Invalid time_range")
        
    query_body["query"]["bool"]["must"].append({"range": {"timestamp": {"gte": time_filter}}})

    alerts = await siem_engine.storage.search_logs(query_body, size=100)
    return {"alerts": alerts}


@app.get("/logs", dependencies=[Depends(get_api_key)])
async def search_logs(query: str, size: int = 50):
    """Search logs by query (protected)"""
    es_query = {
        "query": {
            "multi_match": {
                "query": query,
                "fields": ["message", "raw_log", "source", "ip"]
            }
        },
        "sort": [{"timestamp": {"order": "desc"}}]
    }
    logs = await siem_engine.storage.search_logs(es_query, size=size)
    return {"logs": logs}


@app.get("/health")
async def health_check():
    """Health check endpoint (unprotected)"""
    es_healthy = await siem_engine.storage.is_connected()
    return {"status": "healthy", "engine_running": True, "elasticsearch_connected": es_healthy}