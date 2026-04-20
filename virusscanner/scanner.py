import os
import hashlib
from config import logger, MAX_FILE_SIZE
from api_client import VTClient

class VirusScanner:
    def __init__(self):
        self.client = VTClient()
    
    def get_sha256(self, file_path):
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.error(f"Hash error: {e}")
            return None
    
    def parse_stats(self, data):
        stats = data.get("data", {}).get("attributes", {}).get("stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }
    
    def get_detections(self, data):
        results = data.get("data", {}).get("attributes", {}).get("results", {})
        return [av for av, res in results.items() if res.get("category") in ["malicious", "suspicious"]]
    
    def display_stats(self, stats):
        print(f"\nStatistics:")
        print(f"  Malicious: {stats['malicious']}")
        print(f"  Suspicious: {stats['suspicious']}")
        print(f"  Harmless: {stats['harmless']}")
        print(f"  Undetected: {stats['undetected']}")
        
        if stats['malicious'] > 0:
            print("\nWARNING: MALICIOUS SOFTWARE DETECTED!")
        elif stats['suspicious'] > 0:
            print("\nWarning: Suspicious elements detected")
        else:
            print("\nNo malware detected")
    
    def scan_file(self, file_path):
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return False
        
        print(f"\nScanning file: {file_path}")
        
        file_hash = self.get_sha256(file_path)
        if not file_hash:
            return False
        print(f"  SHA-256: {file_hash[:32]}...")
        
        report = self.client.get_file(file_hash)
        
        if not report:
            size = os.path.getsize(file_path)
            if size > MAX_FILE_SIZE:
                print(f"File {size/1024/1024:.1f}MB exceeds 32MB limit")
                return False
            
            print("  File not found, uploading...")
            upload_result = self.client.upload_file(file_path)
            if not upload_result:
                return False
            
            analysis_id = upload_result.get("data", {}).get("id")
            print("  Analyzing (20 sec)...")
            report = self.client.get_analysis(analysis_id)
        
        if report:
            stats = self.parse_stats(report)
            self.display_stats(stats)
            
            detections = self.get_detections(report)
            if detections:
                print(f"\nDetected by: {', '.join(detections[:5])}")
            return True
        
        return False
    
    def scan_url(self, url):
        print(f"\nScanning URL: {url}")
        
        report = self.client.scan_url(url)
        
        if not report:
            print("  URL not found, submitting for analysis...")
            submit_result = self.client.submit_url(url)
            if not submit_result:
                return False
            
            analysis_id = submit_result.get("data", {}).get("id")
            print("  Analyzing (20 sec)...")
            report = self.client.get_analysis(analysis_id)
        
        if report:
            stats = self.parse_stats(report)
            self.display_stats(stats)
            
            categories = report.get("data", {}).get("attributes", {}).get("categories", {})
            if categories:
                print(f"\nCategories: {', '.join(list(categories.values())[:3])}")
            return True
        
        return False
    
    def scan_hash(self, file_hash):
        print(f"\nScanning hash: {file_hash}")
        report = self.client.get_file(file_hash)
        
        if report:
            stats = self.parse_stats(report)
            self.display_stats(stats)
            return True
        else:
            print("Report not found")
            return False
