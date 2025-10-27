import os
import requests
import socket
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

class ReputationChecker:
    def __init__(self):
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'google_safebrowsing': os.getenv('GOOGLE_SAFEBROWSING_KEY'),
            'urlscan': os.getenv('URLSCAN_API_KEY'),
            'openphish': os.getenv('OPENPHISH_API_KEY'),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
            'emailrep': os.getenv('EMAILREP_API_KEY'),
            'threatminer': os.getenv('THREATMINER_API_KEY')
        }
        self.cache = {}
        self.cache_expiry = 3600  # 1 hour cache

    def check_virustotal(self, url):
        """Check URL with VirusTotal API"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {'error': 'VirusTotal API key not found'}

        try:
            response = requests.get(
                'https://www.virustotal.com/api/v3/urls/{}'.format(url),
                headers={'x-apikey': api_key}
            )
            if response.status_code == 200:
                return response.json()
            return {'error': f'VirusTotal API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_google_safe_browsing(self, url):
        """Check URL with Google Safe Browsing API"""
        api_key = self.api_keys.get('google_safebrowsing')
        if not api_key:
            return {'error': 'Google Safe Browsing API key not found'}

        try:
            response = requests.post(
                'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}'.format(api_key),
                json={
                    'client': {'clientId': 'phishing-detector', 'clientVersion': '1.0'},
                    'threatInfo': {
                        'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                        'platformTypes': ['ANY_PLATFORM'],
                        'threatEntryTypes': ['URL'],
                        'threatEntries': [{'url': url}]
                    }
                }
            )
            if response.status_code == 200:
                return response.json()
            return {'error': f'Google Safe Browsing API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_urlscan(self, url):
        """Check URL with URLScan.io API"""
        api_key = self.api_keys.get('urlscan')
        if not api_key:
            return {'error': 'URLScan.io API key not found'}

        try:
            response = requests.post(
                'https://urlscan.io/api/v1/scan/',
                headers={'API-Key': api_key},
                json={'url': url, 'public': 'on'}
            )
            if response.status_code == 200:
                return response.json()
            return {'error': f'URLScan.io API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_openphish(self, url):
        """Check URL with OpenPhish API"""
        try:
            response = requests.get(f'https://openphish.com/feed.txt')
            if response.status_code == 200:
                return {'is_phishing': url in response.text}
            return {'error': f'OpenPhish API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_abuseipdb(self, ip_address):
        """Check IP address with AbuseIPDB API"""
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return {'error': 'AbuseIPDB API key not found'}

        try:
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': api_key, 'Accept': 'application/json'},
                params={'ipAddress': ip_address, 'maxAgeInDays': '90'}
            )
            if response.status_code == 200:
                return response.json()
            return {'error': f'AbuseIPDB API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_emailrep(self, email):
        """Check email with EmailRep.io API"""
        api_key = self.api_keys.get('emailrep')
        if not api_key:
            return {'error': 'EmailRep.io API key not found'}

        try:
            response = requests.get(
                f'https://emailrep.io/{email}',
                headers={'Key': api_key, 'User-Agent': 'phishing-detector'}
            )
            if response.status_code == 200:
                return response.json()
            return {'error': f'EmailRep.io API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_threatminer(self, domain):
        """Check domain with ThreatMiner API"""
        try:
            response = requests.get(f'https://api.threatminer.org/v2/domain.php?q={domain}&rt=1')
            if response.status_code == 200:
                return response.json()
            return {'error': f'ThreatMiner API error: {response.status_code}'}
        except Exception as e:
            return {'error': str(e)}

    def check_all_reputations(self, url):
        """Check URL reputation from all available sources"""
        reputation_results = {}

        # Get IP address for AbuseIPDB check
        try:
            parsed_url = urlparse(url)
            ip_address = socket.gethostbyname(parsed_url.hostname)
            reputation_results['abuseipdb'] = self.check_abuseipdb(ip_address)
        except Exception as e:
            reputation_results['abuseipdb'] = {'error': str(e)}

        reputation_results['virustotal'] = self.check_virustotal(url)
        reputation_results['google_safebrowsing'] = self.check_google_safe_browsing(url)
        reputation_results['urlscan'] = self.check_urlscan(url)
        reputation_results['openphish'] = self.check_openphish(url)
        reputation_results['threatminer'] = self.check_threatminer(urlparse(url).hostname)

        return reputation_results

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
