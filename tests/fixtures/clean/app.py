import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def fetch_data():
    db_host = os.getenv("DB_HOST", "localhost")
    logger.info(f"Connecting to {db_host}")
    return {"status": "ok"}

if __name__ == "__main__":
    fetch_data()
