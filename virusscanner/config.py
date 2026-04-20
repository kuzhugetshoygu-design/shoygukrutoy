import os
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("virustotal.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
MAX_FILE_SIZE = 32 * 1024 * 1024
RATE_LIMIT = 15
