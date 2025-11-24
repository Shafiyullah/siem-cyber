# In main.py
import uvicorn
import logging
from config import Config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if __name__ == "__main__":
    """
    Main application entry point.
    This starts the FastAPI server.
    The API server (api.py) will then start the SIEM engine
    on its 'startup' event.
    """
    if not Config.API_KEY:
        logging.warning("="*50)
        logging.warning("WARNING: API_KEY is not set!")
        logging.warning("The API is running without authentication.")
        logging.warning("Set the API_KEY environment variable.")
        logging.warning("="*50)

    logging.info("Starting API server...")
    uvicorn.run("api:app", host="0.0.0.0", port=8000)