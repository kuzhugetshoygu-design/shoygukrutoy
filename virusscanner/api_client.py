import time
import base64
import requests
from config import API_KEY, BASE_URL, RATE_LIMIT, logger

class VTClient:
    def __init__(self):
        if not API_KEY:
            raise ValueError("API key not found. Set VIRUSTOTAL_API_KEY")
        self.headers = {"x-apikey": API_KEY}
        self.last_request = 0
    
    def _rate_limit(self):
        elapsed = time.time() - self.last_request
        if elapsed < RATE_LIMIT:
            time.sleep(RATE_LIMIT - elapsed)
        self.last_request = time.time()
    
    def _request(self, method, endpoint, **kwargs):
        self._rate_limit()
        url = f"{BASE_URL}/{endpoint}"
        try:
            resp = requests.request(method, url, headers=self.headers, **kwargs)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return None
            elif resp.status_code == 429:
                logger.error("Quota exceeded")
                raise Exception("Quota exceeded")
            resp.raise_for_status()
        except Exception as e:
            logger.error(f"API error: {e}")
            raise
    
    def get_file(self, file_hash):
        return self._request("GET", f"files/{file_hash}")
    
    def upload_file(self, file_path):
        with open(file_path, "rb") as f:
            files = {"file": f}
            return self._request("POST", "files", files=files)
    
    def get_analysis(self, analysis_id):
        time.sleep(20)
        return self._request("GET", f"analyses/{analysis_id}")
    
    def scan_url(self, url):
        encoded = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return self._request("GET", f"urls/{encoded}")
    
    def submit_url(self, url):
        return self._request("POST", "urls", json={"url": url})
