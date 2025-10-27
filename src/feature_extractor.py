import re
import requests
from urllib.parse import urlparse, parse_qs
import tldextract
import hashlib
from bs4 import BeautifulSoup
import socket
import ssl
from datetime import datetime
from .reputation_checker import ReputationChecker
from sklearn.feature_extraction.text import TfidfVectorizer

class EnhancedURLFeatureExtractor:
    def __init__(self):
        self.reputation_checker = ReputationChecker()
        self.tfidf_vectorizer = None
        self.tfidf_feature_names = []

    def extract_all_features(self, url):
        """Extract all features, including reputation and SSL"""
        features = self._extract_basic_features(url)

        # Add reputation features
        reputation_features = self.reputation_checker.check_all_reputations(url)
        features.update(reputation_features)

        # Add SSL features
        ssl_features = self.extract_ssl_certificate_features(url)
        features.update(ssl_features)

        return features
        
    def extract_ssl_certificate_features(self, url):
        """Extract features from SSL certificate"""
        ssl_features = {}
        
        try:
            # Parse the domain from the URL
            domain = urlparse(url).netloc
            if not domain:
                domain = url
                
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
                
            # Get SSL certificate info
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check if certificate is valid
                    ssl_features['has_ssl'] = True
                    
                    # Extract issuer information
                    issuer = dict(x[0] for x in cert['issuer'])
                    ssl_features['ssl_issuer'] = issuer.get('organizationName', 'Unknown')
                    
                    # Calculate days until expiry
                    not_after = cert['notAfter']
                    expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days_to_expiry = (expiry_date - datetime.now()).days
                    ssl_features['ssl_days_to_expiry'] = days_to_expiry
                    
                    # Is the certificate about to expire?
                    ssl_features['ssl_about_to_expire'] = days_to_expiry < 30
        except Exception as e:
            # No SSL or error in connection
            ssl_features['has_ssl'] = False
            ssl_features['ssl_issuer'] = 'None'
            ssl_features['ssl_days_to_expiry'] = -1
            ssl_features['ssl_about_to_expire'] = False
            
        return ssl_features
        
    def _extract_basic_features(self, url):
        """Extract basic URL features"""
        features = {}
        
        # URL length
        features['url_length'] = len(url)
        
        # Parse URL
        parsed_url = urlparse(url)
        
        # Domain features
        domain_info = tldextract.extract(url)
        features['domain_length'] = len(domain_info.domain)
        features['subdomain_length'] = len(domain_info.subdomain) if domain_info.subdomain else 0
        features['tld_length'] = len(domain_info.suffix) if domain_info.suffix else 0
        
        # Path features
        features['path_length'] = len(parsed_url.path)
        features['path_depth'] = parsed_url.path.count('/')
        
        # Query parameters
        query_params = parse_qs(parsed_url.query)
        features['num_query_params'] = len(query_params)
        
        # Special characters
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_equals'] = url.count('=')
        features['num_at_signs'] = url.count('@')
        features['num_ampersands'] = url.count('&')
        features['num_percent'] = url.count('%')
        
        return features
