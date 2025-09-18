import requests
import hashlib
import time
from urllib.parse import urlparse

class ReputationChecker:
    def __init__(self):
        self.cache = {}
        self.cache_expiry = 3600  # 1 hour cache
        
    def check_google_safe_browsing(self, url):
        """Check Google Safe Browsing (requires API key)"""
        # For demo purposes, return random score
        # In production, integrate with Google Safe Browsing API
        import random
        return random.uniform(0, 0.3)  # Most URLs are safe
    
    def check_url_reputation(self, url):
        """Check URL reputation from multiple sources"""
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        # Check cache first
        if url_hash in self.cache:
            cached_time, score = self.cache[url_hash]
            if time.time() - cached_time < self.cache_expiry:
                return score
        
        # Calculate reputation score (0 = safe, 1 = dangerous)
        reputation_score = 0.0
        
        try:
            # Factor 1: Domain age (newer domains more suspicious)
            domain_age_score = self.check_domain_age(url)
            reputation_score += domain_age_score * 0.3
            
            # Factor 2: SSL certificate
            ssl_score = self.check_ssl_certificate(url)
            reputation_score += ssl_score * 0.2
            
            # Factor 3: External reputation (placeholder)
            external_score = self.check_google_safe_browsing(url)
            reputation_score += external_score * 0.5
            
            # Cache result
            self.cache[url_hash] = (time.time(), reputation_score)
            
            return min(reputation_score, 1.0)
            
        except Exception as e:
            print(f"Error checking reputation for {url}: {e}")
            return 0.5  # Unknown/moderate risk
    
    def check_domain_age(self, url):
        """Check domain registration age"""
        try:
            domain = urlparse(url).netloc
            # Placeholder - in production, use WHOIS API
            # For now, return low risk for known domains
            known_domains = ['google.com', 'facebook.com', 'amazon.com', 'github.com']
            if any(known in domain for known in known_domains):
                return 0.0
            return 0.4  # Unknown domain = moderate risk
        except:
            return 0.5
    
    def check_ssl_certificate(self, url):
        """Check SSL certificate validity"""
        try:
            if not url.startswith('https://'):
                return 0.8  # HTTP is suspicious for sensitive sites
            
            # Placeholder - in production, check actual certificate
            response = requests.head(url, timeout=5, verify=True)
            return 0.1 if response.status_code == 200 else 0.4
        except:
            return 0.6  # SSL issues = high risk
