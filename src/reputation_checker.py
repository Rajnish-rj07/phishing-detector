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
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
            'emailrep': os.getenv('EMAILREP_API_KEY')
        }
        self.cache = {}
        self.cache_expiry = 3600  # 1 hour cache
        # Define reliability weights for each API service
        self.api_weights = {
            'virustotal': 0.35,
            'google_safebrowsing': 0.30,
            'urlscan': 0.20,
            'abuseipdb': 0.10,
            'emailrep': 0.05
        }

    def check_virustotal(self, url):
        """Check URL with VirusTotal API"""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {'error': 'VirusTotal API key not found'}

        try:
            # First, submit the URL for scanning
            scan_response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers={'x-apikey': api_key},
                data={'url': url}
            )
            
            if scan_response.status_code != 200:
                return {'error': f'VirusTotal API scan error: {scan_response.status_code}'}
                
            # Extract the analysis ID from the response
            scan_data = scan_response.json()
            analysis_id = scan_data.get('data', {}).get('id')
            
            if not analysis_id:
                return {'error': 'Failed to get analysis ID from VirusTotal'}
                
            # Get the analysis results
            response = requests.get(
                f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                headers={'x-apikey': api_key}
            )
            
            if response.status_code == 200:
                return response.json()
            return {'error': f'VirusTotal API error: {response.status_code}'}
        except Exception as e:
            print(f"VirusTotal API error: {str(e)}")
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

    def check_all_reputations(self, url):
        """Check URL reputation from all available sources using weighted ensemble approach"""
        reputation_results = {}
        weighted_scores = []
        total_weight = 0

        # Get IP address for AbuseIPDB check
        try:
            parsed_url = urlparse(url)
            ip_address = socket.gethostbyname(parsed_url.hostname)
            reputation_results['abuseipdb'] = self.check_abuseipdb(ip_address)
            # Process AbuseIPDB result to get a normalized score (0-1)
            if 'data' in reputation_results['abuseipdb'] and 'abuseConfidenceScore' in reputation_results['abuseipdb']['data']:
                score = min(reputation_results['abuseipdb']['data']['abuseConfidenceScore'] / 100, 1.0)
                weight = self.api_weights.get('abuseipdb', 0.1)
                weighted_scores.append((score, weight))
                total_weight += weight
        except Exception as e:
            reputation_results['abuseipdb'] = {'error': str(e)}

        # Check VirusTotal
        reputation_results['virustotal'] = self.check_virustotal(url)
        try:
            if 'data' in reputation_results['virustotal'] and 'attributes' in reputation_results['virustotal']['data']:
                stats = reputation_results['virustotal']['data']['attributes']['last_analysis_stats']
                if stats:
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    total = sum(stats.values())
                    if total > 0:
                        score = (malicious + suspicious * 0.5) / total
                        weight = self.api_weights.get('virustotal', 0.35)
                        weighted_scores.append((score, weight))
                        total_weight += weight
        except Exception:
            pass

        # Check Google Safe Browsing
        reputation_results['google_safebrowsing'] = self.check_google_safe_browsing(url)
        if isinstance(reputation_results['google_safebrowsing'], (int, float)):
            score = float(reputation_results['google_safebrowsing'])
            weight = self.api_weights.get('google_safebrowsing', 0.30)
            weighted_scores.append((score, weight))
            total_weight += weight
        elif isinstance(reputation_results['google_safebrowsing'], dict) and 'matches' in reputation_results['google_safebrowsing']:
            score = 1.0 if reputation_results['google_safebrowsing']['matches'] else 0.0
            weight = self.api_weights.get('google_safebrowsing', 0.30)
            weighted_scores.append((score, weight))
            total_weight += weight

        # Check URLScan
        reputation_results['urlscan'] = self.check_urlscan(url)
        try:
            if 'verdicts' in reputation_results['urlscan'] and 'overall' in reputation_results['urlscan']['verdicts']:
                score = 1.0 if reputation_results['urlscan']['verdicts']['overall']['malicious'] else 0.0
                weight = self.api_weights.get('urlscan', 0.20)
                weighted_scores.append((score, weight))
                total_weight += weight
        except Exception:
            pass

        # Calculate ensemble score using weighted average
        if weighted_scores and total_weight > 0:
            ensemble_score = sum(score * weight for score, weight in weighted_scores) / total_weight
            reputation_results['ensemble_score'] = ensemble_score
            confidence_value = min(0.5 + (len(weighted_scores) / len(self.api_weights)) * 0.5, 1.0)
            reputation_results['confidence'] = confidence_value
            # Add formatted values for the extension
            reputation_results['probabilityPhishing'] = int(ensemble_score * 100)
            reputation_results['confidence_percent'] = int(confidence_value * 100)
            
            # Set risk level based on ensemble score
            if ensemble_score >= 0.7:
                reputation_results['riskLevel'] = 'HIGH'
            elif ensemble_score >= 0.4:
                reputation_results['riskLevel'] = 'MEDIUM'
            elif ensemble_score >= 0.2:
                reputation_results['riskLevel'] = 'LOW'
            else:
                reputation_results['riskLevel'] = 'SAFE'
        else:
            reputation_results['ensemble_score'] = 0.5  # Neutral score if no data
            reputation_results['confidence'] = 0.3  # Low confidence
            reputation_results['probabilityPhishing'] = 50
            reputation_results['confidence_percent'] = 30
            reputation_results['riskLevel'] = 'UNKNOWN'

        return reputation_results

    def check_google_safe_browsing(self, url):
        """Check Google Safe Browsing (requires API key)"""
        # For demo purposes, return random score
        # In production, integrate with Google Safe Browsing API
        import random
        return random.uniform(0, 0.3)  # Most URLs are safe
    
    def check_url_reputation(self, url):
        """Check URL reputation using Bayesian approach and ensemble learning"""
        import hashlib
        import time
        import math
        
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        # Check cache first
        if url_hash in self.cache:
            cached_time, result = self.cache[url_hash]
            if time.time() - cached_time < self.cache_expiry:
                return result
        
        # Initialize with prior probability (base rate of phishing)
        # Typical phishing base rate is around 1% of all URLs
        prior_phishing_probability = 0.01
        
        # Feature collection and importance analysis
        features = {}
        feature_importance = {}
        
        try:
            # Feature 1: Domain age (newer domains more suspicious)
            domain_age_score = self.check_domain_age(url)
            features['domain_age'] = domain_age_score
            feature_importance['domain_age'] = 0.15
            
            # Feature 2: SSL certificate
            ssl_score = self.check_ssl_certificate(url)
            features['ssl_certificate'] = ssl_score
            feature_importance['ssl_certificate'] = 0.10
            
            # Feature 3: External reputation APIs
            reputation_results = self.check_all_reputations(url)
            if 'ensemble_score' in reputation_results:
                features['api_reputation'] = reputation_results['ensemble_score']
                feature_importance['api_reputation'] = 0.50
                
                # Confidence in the API results
                confidence = reputation_results.get('confidence', 0.5)
            else:
                features['api_reputation'] = 0.5  # Neutral if no API data
                feature_importance['api_reputation'] = 0.25
                confidence = 0.3  # Low confidence
            
            # Feature 4: URL characteristics (length, special chars, etc.)
            url_chars_score = self.analyze_url_characteristics(url)
            features['url_characteristics'] = url_chars_score
            feature_importance['url_characteristics'] = 0.25
            
            # Bayesian update of probability
            likelihood_ratio = 1.0
            for feature, value in features.items():
                # Convert feature score to likelihood ratio
                # Higher feature value = more likely to be phishing
                feature_weight = feature_importance.get(feature, 0.1)
                if value > 0.5:  # Feature suggests phishing
                    # Adjust likelihood based on feature value and importance
                    lr = 1.0 + (value - 0.5) * 2 * feature_weight * 10
                else:  # Feature suggests legitimate
                    # Inverse relationship for legitimate indicators
                    lr = 1.0 / (1.0 + (0.5 - value) * 2 * feature_weight * 10)
                
                likelihood_ratio *= lr
            
            # Apply Bayes' theorem
            posterior_probability = (prior_phishing_probability * likelihood_ratio) / \
                ((prior_phishing_probability * likelihood_ratio) + 
                 (1 - prior_phishing_probability))
            
            # Calculate confidence interval (simplified)
            margin_of_error = 0.5 * (1 - confidence)
            
            # Prepare result with feature importance and format for extension
            result = {
                'probability_phishing': posterior_probability,
                'probabilityPhishing': int(posterior_probability * 100),
                'confidence': confidence,
                'confidence_percent': int(confidence * 100),
                'margin_of_error': margin_of_error,
                'confidence_interval': [
                    max(0, posterior_probability - margin_of_error),
                    min(1, posterior_probability + margin_of_error)
                ],
                'features': features,
                'feature_importance': feature_importance,
                'isPhishing': posterior_probability > 0.5,
                'riskLevel': 'HIGH' if posterior_probability > 0.7 else 
                            'MEDIUM' if posterior_probability > 0.4 else
                            'LOW' if posterior_probability > 0.2 else 'SAFE'
            }
            
            # Cache result
            self.cache[url_hash] = (time.time(), result)
            
            return result
            
        except Exception as e:
            print(f"Error checking reputation for {url}: {e}")
            return {
                'probability_phishing': 0.5,  # Unknown/moderate risk
                'confidence': 0.2,  # Very low confidence
                'error': str(e)
            }
            
    def analyze_url_characteristics(self, url):
        """Analyze URL characteristics for suspicious patterns"""
        score = 0.0
        count = 0
        
        # Check URL length (longer URLs more suspicious)
        if len(url) > 100:
            score += 0.8
            count += 1
        elif len(url) > 75:
            score += 0.5
            count += 1
        elif len(url) > 50:
            score += 0.3
            count += 1
        else:
            score += 0.1
            count += 1
            
        # Check for suspicious characters
        suspicious_chars = ['@', ',', '%', '+', '\\', '&', '=', '$', '#']
        char_count = sum(1 for c in url if c in suspicious_chars)
        if char_count > 5:
            score += 0.9
            count += 1
        elif char_count > 3:
            score += 0.6
            count += 1
        elif char_count > 0:
            score += 0.3
            count += 1
        else:
            score += 0.1
            count += 1
            
        # Check for IP address instead of domain
        import re
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            score += 0.9
            count += 1
            
        # Check for multiple subdomains
        parsed_url = urlparse(url)
        domain_parts = parsed_url.netloc.split('.')
        if len(domain_parts) > 3:
            score += 0.7
            count += 1
            
        # Return average score
        return score / count if count > 0 else 0.5
    
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
