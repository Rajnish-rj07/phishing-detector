# Phase 2: Feature Engineering

feature_engineering_code = '''
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse, parse_qs
import tldextract
from collections import Counter
import socket
import requests
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class URLFeatureExtractor:
    def __init__(self):
        self.suspicious_words = [
            'secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking',
            'confirm', 'account', 'admin', 'member', 'service', 'verification', 'verify',
            'update', 'suspended', 'security', 'billing', 'support', 'paypal'
        ]
        
        self.shortening_services = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 
            'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
        ]
    
    def extract_basic_features(self, url):
        """Extract basic URL structure features"""
        features = {}
        
        # URL length
        features['url_length'] = len(url)
        
        # Number of dots
        features['num_dots'] = url.count('.')
        
        # Number of hyphens  
        features['num_hyphens'] = url.count('-')
        
        # Number of underscores
        features['num_underscores'] = url.count('_')
        
        # Number of slashes
        features['num_slashes'] = url.count('/')
        
        # Number of question marks
        features['num_question_marks'] = url.count('?')
        
        # Number of equal signs
        features['num_equal_signs'] = url.count('=')
        
        # Number of at symbols
        features['num_at_symbols'] = url.count('@')
        
        # Number of ampersands
        features['num_ampersands'] = url.count('&')
        
        # Number of percentage signs
        features['num_percent_signs'] = url.count('%')
        
        return features
    
    def extract_domain_features(self, url):
        """Extract domain-related features"""
        features = {}
        
        try:
            parsed_url = urlparse(url)
            extracted = tldextract.extract(url)
            
            # Domain length
            features['domain_length'] = len(parsed_url.netloc)
            
            # Number of subdomains
            subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
            features['num_subdomains'] = len([s for s in subdomains if s])
            
            # Has IP address
            features['has_ip_address'] = self.is_ip_address(parsed_url.netloc)
            
            # HTTPS usage
            features['is_https'] = 1 if parsed_url.scheme == 'https' else 0
            
            # Port in URL
            features['has_port'] = 1 if parsed_url.port else 0
            
            # URL shortening service
            features['is_shortened'] = 1 if any(service in url.lower() for service in self.shortening_services) else 0
            
        except Exception as e:
            # Set default values if parsing fails
            features.update({
                'domain_length': 0, 'num_subdomains': 0, 'has_ip_address': 0,
                'is_https': 0, 'has_port': 0, 'is_shortened': 0
            })
        
        return features
    
    def extract_lexical_features(self, url):
        """Extract lexical and string-based features"""
        features = {}
        
        # Number of digits
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Number of letters
        features['num_letters'] = sum(c.isalpha() for c in url)
        
        # Ratio of digits to total characters
        features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
        
        # Ratio of letters to total characters
        features['letter_ratio'] = features['num_letters'] / len(url) if len(url) > 0 else 0
        
        # Suspicious words count
        url_lower = url.lower()
        features['suspicious_words_count'] = sum(1 for word in self.suspicious_words if word in url_lower)
        
        # Longest word length
        words = re.findall(r'[a-zA-Z]+', url)
        features['longest_word_length'] = max([len(word) for word in words]) if words else 0
        
        # Average word length
        features['avg_word_length'] = np.mean([len(word) for word in words]) if words else 0
        
        return features
    
    def extract_path_features(self, url):
        """Extract path and query parameter features"""
        features = {}
        
        try:
            parsed_url = urlparse(url)
            
            # Path length
            features['path_length'] = len(parsed_url.path)
            
            # Query length
            features['query_length'] = len(parsed_url.query) if parsed_url.query else 0
            
            # Fragment length
            features['fragment_length'] = len(parsed_url.fragment) if parsed_url.fragment else 0
            
            # Number of parameters
            query_params = parse_qs(parsed_url.query)
            features['num_params'] = len(query_params)
            
            # Number of path segments
            path_segments = [segment for segment in parsed_url.path.split('/') if segment]
            features['num_path_segments'] = len(path_segments)
            
        except Exception as e:
            features.update({
                'path_length': 0, 'query_length': 0, 'fragment_length': 0,
                'num_params': 0, 'num_path_segments': 0
            })
        
        return features
    
    def is_ip_address(self, domain):
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain.split(':')[0])  # Remove port if present
            return 1
        except socket.error:
            return 0
    
    def extract_all_features(self, url):
        """Extract all features for a single URL"""
        features = {}
        
        # Combine all feature extraction methods
        features.update(self.extract_basic_features(url))
        features.update(self.extract_domain_features(url))
        features.update(self.extract_lexical_features(url))
        features.update(self.extract_path_features(url))
        
        return features
    
    def process_dataset(self, input_file, output_file=None):
        """Process entire dataset and extract features"""
        print(f"Processing dataset: {input_file}")
        
        # Load dataset
        df = pd.read_csv(input_file)
        print(f"Loaded {len(df)} URLs")
        
        # Extract features for each URL
        feature_list = []
        for idx, row in df.iterrows():
            if idx % 100 == 0:
                print(f"Processing URL {idx+1}/{len(df)}")
            
            try:
                features = self.extract_all_features(row['url'])
                features['url'] = row['url']
                features['label'] = row['label']
                feature_list.append(features)
            except Exception as e:
                print(f"Error processing URL {row['url']}: {e}")
                continue
        
        # Create feature DataFrame
        feature_df = pd.DataFrame(feature_list)
        
        # Save processed dataset
        if output_file:
            feature_df.to_csv(output_file, index=False)
            print(f"Features saved to {output_file}")
        
        print(f"Feature extraction complete!")
        print(f"Features extracted: {list(feature_df.columns)}")
        print(f"Feature matrix shape: {feature_df.shape}")
        
        return feature_df

if __name__ == "__main__":
    extractor = URLFeatureExtractor()
    
    # Process the dataset
    features_df = extractor.process_dataset(
        'data/phishing_dataset.csv',
        'data/features_dataset.csv'
    )
    
    print("\\n📊 Sample features:")
    print(features_df.head())
'''

# Save the feature engineering script
with open('phishing-detector/src/feature_extractor.py', 'w') as f:
    f.write(feature_engineering_code)

print("✅ Phase 2: Feature engineering script created!")
print("📄 File: phishing-detector/src/feature_extractor.py")