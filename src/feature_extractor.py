import re
import requests
from urllib.parse import urlparse, parse_qs
import tldextract
import hashlib
from bs4 import BeautifulSoup
import socket
from src.reputation_checker import ReputationChecker
from sklearn.feature_extraction.text import TfidfVectorizer

class EnhancedURLFeatureExtractor:
    def __init__(self):
        self.reputation_checker = ReputationChecker()
        self.tfidf_vectorizer = None # Placeholder for TF-IDF vectorizer
        self.tfidf_feature_names = []
    
    def extract_all_features(self, url):
        """Extract comprehensive features including real-time data"""
        features = {}
        
        # Original features (keep your existing ones)
        features.update(self.extract_basic_url_features(url))
        
        # NEW: Real-time features
        features.update(self.extract_reputation_features(url))
        features.update(self.extract_technical_features(url))
        features.update(self.extract_content_features(url))
        
        # NEW: NLP features (placeholder for now)
        text_content = self.extract_text_content(url)
        nlp_features = self._process_text_features(text_content)
        features.update(nlp_features)
        
        return features
    
    def _process_text_features(self, text_content):
        """Process text content using TF-IDF (placeholder for now)"""
        if self.tfidf_vectorizer and text_content:
            # Transform the text content into TF-IDF features
            text_vector = self.tfidf_vectorizer.transform([text_content])
            # Convert to a dictionary of feature names and values
            return dict(zip(self.tfidf_feature_names, text_vector.toarray()[0]))
        return {}

    def extract_basic_url_features(self, url):
        """Your existing URL feature extraction"""
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        features = {
            'url_length': len(url),
            'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_slashes': url.count('/'),
            'num_question_marks': url.count('?'),
            'num_equal_signs': url.count('='),
            'num_ampersands': url.count('&'),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'domain_length': len(extracted.domain),
            'subdomain_count': len(extracted.subdomain.split('.')) if extracted.subdomain else 0,
            'path_length': len(parsed.path),
            'query_length': len(parsed.query) if parsed.query else 0,
            'fragment_length': len(parsed.fragment) if parsed.fragment else 0
        }
        
        return features
    
    def extract_reputation_features(self, url):
        """NEW: Reputation-based features"""
        features = {}
        
        try:
            # Get reputation score
            reputation_score = self.reputation_checker.check_url_reputation(url)
            features['reputation_score'] = reputation_score
            features['is_high_reputation'] = 1 if reputation_score < 0.3 else 0
            features['is_low_reputation'] = 1 if reputation_score > 0.7 else 0
            
        except Exception as e:
            print(f"Error extracting reputation features: {e}")
            features['reputation_score'] = 0.5
            features['is_high_reputation'] = 0
            features['is_low_reputation'] = 0
        
        return features
    
    def extract_technical_features(self, url):
        """NEW: Technical analysis features"""
        features = {}
        
        try:
            parsed = urlparse(url)
            
            # DNS resolution time
            start_time = time.time()
            try:
                socket.gethostbyname(parsed.netloc)
                dns_resolution_time = time.time() - start_time
            except:
                dns_resolution_time = 999  # Failed resolution
            
            features['dns_resolution_time'] = dns_resolution_time
            features['dns_resolution_failed'] = 1 if dns_resolution_time > 10 else 0
            
            # Port analysis
            default_ports = {'http': 80, 'https': 443}
            expected_port = default_ports.get(parsed.scheme, 80)
            actual_port = parsed.port if parsed.port else expected_port
            features['uses_non_standard_port'] = 1 if actual_port != expected_port else 0
            
            # URL complexity
            features['url_entropy'] = self.calculate_entropy(url)
            features['has_suspicious_keywords'] = self.check_suspicious_keywords(url)
            
        except Exception as e:
            print(f"Error extracting technical features: {e}")
            features.update({
                'dns_resolution_time': 999,
                'dns_resolution_failed': 1,
                'uses_non_standard_port': 0,
                'url_entropy': 0,
                'has_suspicious_keywords': 0
            })
        
        return features
    
    def extract_content_features(self, url):
        """NEW: Safe content analysis features"""
        features = {
            'page_title_suspicious': 0,
            'has_login_form': 0,
            'external_resources_count': 0,
            'redirect_count': 0,
            'content_length': 0
        }
        
        try:
            # Only analyze if reputation is not extremely bad
            reputation = self.reputation_checker.check_url_reputation(url)
            if reputation > 0.9:
                return features  # Skip content analysis for very suspicious URLs
            
            # Safe HTTP request with strict timeout
            response = requests.get(
                url, 
                timeout=5, 
                allow_redirects=True,
                verify=False,  # Skip SSL verification for analysis
                headers={'User-Agent': 'Mozilla/5.0 (compatible; PhishingBot/1.0)'}
            )
            
            features['redirect_count'] = len(response.history)
            features['content_length'] = len(response.content)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Title analysis
                title = soup.find('title')
                if title:
                    title_text = title.get_text().lower()
                    suspicious_words = ['login', 'verify', 'account', 'suspend', 'urgent', 'click']
                    features['page_title_suspicious'] = 1 if any(word in title_text for word in suspicious_words) else 0
                
                # Form analysis
                forms = soup.find_all('form')
                features['has_login_form'] = 1 if any('password' in str(form).lower() for form in forms) else 0
                
                # External resources
                external_count = 0
                for tag in soup.find_all(['img', 'script', 'link']):
                    src = tag.get('src') or tag.get('href')
                    if src and ('http' in src and urlparse(url).netloc not in src):
                        external_count += 1
                features['external_resources_count'] = external_count
                
        except Exception as e:
            print(f"Error extracting content features from {url}: {e}")
        
        return features
    
    def extract_text_content(self, url):
        """NEW: Extract visible text content from the webpage"""
        try:
            response = requests.get(
                url, 
                timeout=5, 
                allow_redirects=True,
                verify=False,  # Skip SSL verification for analysis
                headers={'User-Agent': 'Mozilla/5.0 (compatible; PhishingBot/1.0)'}
            )
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                # Remove script and style elements
                for script_or_style in soup(['script', 'style']):
                    script_or_style.extract()
                text = soup.get_text()
                # Break into lines and remove leading/trailing space on each
                lines = (line.strip() for line in text.splitlines())
                # Break multi-hyphenated words into two
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                # Drop blank lines
                text = '\n'.join(chunk for chunk in chunks if chunk)
                return text
        except Exception as e:
            print(f"Error extracting text content from {url}: {e}")
        return ""

    def calculate_entropy(self, url):
        """Calculate Shannon entropy of URL"""
        import math
        from collections import Counter
        
        if not url:
            return 0
        
        counts = Counter(url)
        probs = [count / len(url) for count in counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs)
        
        return entropy
    
    def check_suspicious_keywords(self, url):
        """Check for suspicious keywords in URL"""
        suspicious_words = [
            'verify', 'account', 'suspend', 'login', 'bank', 'paypal',
            'amazon', 'microsoft', 'apple', 'google', 'secure', 'update'
        ]
        
        url_lower = url.lower()
        return 1 if any(word in url_lower for word in suspicious_words) else 0
