import json
import os
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, jsonify, request
from flask_cors import CORS
import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.preprocessing import StandardScaler
from urllib.parse import urlparse

import tldextract
import requests
import time
import os
import json
import ssl
import socket
import pickle
import joblib
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["chrome-extension://ciingiplfdkjgggpekedijaiplefflik", "http://localhost:*", "https://phishing-detector-isnv.onrender.com"]}})

# Initialize ThreadPoolExecutor for async tasks
executor = ThreadPoolExecutor(max_workers=5)

# Simple in-memory cache for external API responses
cache = {}
CACHE_TTL = 3600  # Cache Time-To-Live in seconds (1 hour)

def cached_get(url, headers=None, params=None, timeout=5):
    cache_key = json.dumps({'url': url, 'headers': headers, 'params': params}, sort_keys=True)
    if cache_key in cache and (time.time() - cache[cache_key]['timestamp'] < CACHE_TTL):
        return cache[cache_key]['response']

    response = requests.get(url, headers=headers, params=params, timeout=timeout)
    cache[cache_key] = {'response': response, 'timestamp': time.time()}
    return response

def cached_post(url, data=None, json=None, headers=None, timeout=5):
    cache_key = json.dumps({'url': url, 'data': data, 'json': json, 'headers': headers}, sort_keys=True)
    if cache_key in cache and (time.time() - cache[cache_key]['timestamp'] < CACHE_TTL):
        return cache[cache_key]['response']

    response = requests.post(url, data=data, json=json, headers=headers, timeout=timeout)
    cache[cache_key] = {'response': response, 'timestamp': time.time()}
    return response

# Global variables for model updates
MODEL_UPDATE_INTERVAL = 24 * 60 * 60  # 24 hours in seconds
FEEDBACK_DATA_PATH = os.path.join(os.path.dirname(__file__), 'feedback_data.json')
LAST_UPDATE_PATH = os.path.join(os.path.dirname(__file__), 'last_update.txt')
MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'phishing_pipeline.pkl')

# API keys for external services (replace with your actual API keys)
# In production, these should be stored in environment variables
API_KEYS = {
    'virustotal': os.environ.get('VIRUSTOTAL_API_KEY', ''),
    'google_safebrowsing': os.environ.get('GOOGLE_SAFEBROWSING_KEY', ''),
    'urlscan': os.environ.get('URLSCAN_API_KEY', ''),
    'openphish': os.environ.get('OPENPHISH_API_KEY', ''),
    'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY', ''),
    'emailrep': os.environ.get('EMAILREP_API_KEY', ''),
    'threatminer': os.environ.get('THREATMINER_API_KEY', '')
}

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "message": "Real-Time Phishing Detection API",
        "version": "2.0",
        "status": "running"
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

def check_openphish(url):
    """Check if URL is in OpenPhish database"""
    try:
        # OpenPhish offers a free feed that can be downloaded
        # For this implementation, we'll use their public feed URL
        # In a production environment, you would download this regularly
        response = cached_get('https://openphish.com/feed.txt', timeout=5)
        if response.status_code == 200:
            phishing_urls = response.text.splitlines()
            # Check if the URL or domain is in the list
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            for phish_url in phishing_urls:
                if url in phish_url or domain in phish_url:
                    return {
                        'is_malicious': True,
                        'source': 'OpenPhish',
                        'threat_type': 'phishing'
                    }
            
            return {
                'is_malicious': False,
                'source': 'OpenPhish',
                'message': 'URL not found in database'
            }
        else:
            return {
                'error': f'OpenPhish API returned status code {response.status_code}',
                'is_malicious': False
            }
    except Exception as e:
        return {
            'error': f'Error checking OpenPhish: {str(e)}',
            'is_malicious': False
        }

def check_abuseipdb(ip):
    """Check IP reputation with AbuseIPDB"""
    if not API_KEYS['abuseipdb']:
        return {'error': 'AbuseIPDB API key not configured', 'is_malicious': False}
    
    try:
        headers = {
            'Key': API_KEYS['abuseipdb'],
            'Accept': 'application/json',
        }
        params = {
            'ipAddress': ip,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        response = cached_get(
            'https://api.abuseipdb.com/api/v2/check',
            headers=headers,
            params=params,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            result = data.get('data', {})
            abuse_score = result.get('abuseConfidenceScore', 0)
            
            return {
                'is_malicious': abuse_score > 50,
                'confidence_score': abuse_score,
                'country': result.get('countryCode', 'Unknown'),
                'isp': result.get('isp', 'Unknown'),
                'domain': result.get('domain', 'Unknown'),
                'total_reports': result.get('totalReports', 0),
                'last_reported': result.get('lastReportedAt', 'Never')
            }
        else:
            return {
                'error': f'AbuseIPDB API returned status code {response.status_code}',
                'is_malicious': False
            }
    except Exception as e:
        return {
            'error': f'Error checking AbuseIPDB: {str(e)}',
            'is_malicious': False
        }

def check_emailrep(email):
    """Check email reputation with EmailRep.io"""
    if not API_KEYS['emailrep']:
        return {'error': 'EmailRep API key not configured', 'is_malicious': False}
    
    try:
        headers = {
            'Key': API_KEYS['emailrep'],
            'Accept': 'application/json',
        }
        response = cached_get(
            f'https://emailrep.io/{email}',
            headers=headers,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'is_malicious': data.get('suspicious', False),
                'reputation': data.get('reputation', 'Unknown'),
                'details': {
                    'first_seen': data.get('first_seen', 'Unknown'),
                    'last_seen': data.get('last_seen', 'Unknown'),
                    'suspicious': data.get('suspicious', False),
                    'spam': data.get('details', {}).get('spam', False),
                    'free_provider': data.get('details', {}).get('free_provider', False),
                    'disposable': data.get('details', {}).get('disposable', False),
                    'deliverable': data.get('details', {}).get('deliverable', False),
                    'spoofable': data.get('details', {}).get('spoofable', False),
                    'malicious_activity': data.get('details', {}).get('malicious_activity', False),
                    'malicious_activity_recent': data.get('details', {}).get('malicious_activity_recent', False),
                    'blacklisted': data.get('details', {}).get('blacklisted', False),
                    'credentials_leaked': data.get('details', {}).get('credentials_leaked', False),
                    'data_breach': data.get('details', {}).get('data_breach', False)
                }
            }
        else:
            return {
                'error': f'EmailRep API returned status code {response.status_code}',
                'is_malicious': False
            }
    except Exception as e:
        return {
            'error': f'Error checking EmailRep: {str(e)}',
            'is_malicious': False
        }
def analyze_ssl_certificate(domain):
    """Analyze SSL certificate for a domain"""
    try:
        # Remove protocol if present
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
            
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate information
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                not_before = cert['notBefore']
                not_after = cert['notAfter']
                
                # Calculate certificate age and validity period
                from datetime import datetime
                
                # Check for advanced security features
                has_extended_validation = 'organizationIdentifier' in subject
                signature_algorithm = ssock.context.get_ciphers()[0].get('alg', 'Unknown')
                cipher_suite = ssock.cipher()[0]
                tls_version = ssock.version()
                
                # Check for certificate transparency
                has_sct = 'scts' in cert
                
                # Check for OCSP stapling
                has_ocsp_stapling = hasattr(ssock, 'ocsp_response') and ssock.ocsp_response is not None
                
                # Parse certificate dates
                date_format = r'%b %d %H:%M:%S %Y %Z'
                not_before_date = datetime.strptime(not_before, date_format)
                not_after_date = datetime.strptime(not_after, date_format)
                
                # Calculate age and remaining validity
                current_date = datetime.now()
                cert_age_days = (current_date - not_before_date).days
                remaining_days = (not_after_date - current_date).days
                
                # Evaluate overall security score (0-100)
                security_score = 100
                
                # Deduct points for security issues
                if remaining_days < 0:
                    security_score -= 50
                if issuer.get('commonName') == subject.get('commonName'):
                    security_score -= 40
                if (not_after_date - not_before_date).days < 90:
                    security_score -= 10
                if not has_extended_validation:
                    security_score -= 10
                if not has_sct:
                    security_score -= 5
                if not has_ocsp_stapling:
                    security_score -= 5
                
                # Ensure score is within bounds
                security_score = max(0, min(100, security_score))
                
                # Determine security level
                if security_score >= 80:
                    security_level = "HIGH"
                elif security_score >= 60:
                    security_level = "MEDIUM"
                else:
                    security_level = "LOW"
                
                return {
                    'valid': True,
                    'issuer': issuer.get('organizationName', 'Unknown'),
                    'subject': subject.get('commonName', 'Unknown'),
                    'age_days': cert_age_days,
                    'remaining_days': remaining_days,
                    'is_expired': remaining_days < 0,
                    'is_self_signed': issuer.get('commonName') == subject.get('commonName'),
                    'is_short_lived': (not_after_date - not_before_date).days < 90,
                    'valid_until': not_after_date.strftime('%Y-%m-%d'),
                    'security_score': security_score,
                    'security_level': security_level,
                    'advanced_security': {
                        'has_extended_validation': has_extended_validation,
                        'signature_algorithm': signature_algorithm,
                        'cipher_suite': cipher_suite,
                        'tls_version': tls_version,
                        'has_certificate_transparency': has_sct,
                        'has_ocsp_stapling': has_ocsp_stapling
                    }
                }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def check_virustotal(url):
    """Check URL against VirusTotal API"""
    if not API_KEYS['virustotal']:
        return None
        
    try:
        api_url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "x-apikey": API_KEYS['virustotal']
        }
        
        # First, get the URL ID by submitting for analysis
        data = {"url": url}
        response = cached_post(api_url, headers=headers, data=data, timeout=10)
        
        if response.status_code != 200:
            return None
            
        result = response.json()
        analysis_id = result.get('data', {}).get('id')
        
        if not analysis_id:
            return None
            
        # Wait a moment for analysis to complete
        time.sleep(2)
        
        # Get the analysis results
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = cached_get(analysis_url, headers=headers, timeout=10)
        
        if response.status_code != 200:
            return None
            
        result = response.json()
        stats = result.get('data', {}).get('attributes', {}).get('stats', {})
        
        return {
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'is_malicious': stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0
        }
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")
        return None

def check_google_safebrowsing(url):
    """Check URL against Google Safe Browsing API"""
    if not API_KEYS['google_safebrowsing']:
        return None
        
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEYS['google_safebrowsing']}"
        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [
                    {"url": url}
                ]
            }
        }
        response = cached_post(api_url, json=payload, timeout=5)

        if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])
        
        if matches:
            return {
                'is_malicious': True,
                'threat_type': matches[0].get('threatType', 'UNKNOWN'),
                'platform_type': matches[0].get('platformType', 'UNKNOWN')
            }
        else:
            return {
                'is_malicious': False
            }
    except Exception as e:
        print(f"Error checking Google Safe Browsing: {e}")
        return None

def check_urlscan(url):
    """Check URL against urlscan.io API"""
    if not API_KEYS['urlscan']:
        return None
        
    try:
        headers = {
            'API-Key': API_KEYS['urlscan'],
            'Content-Type': 'application/json'
        }
        
        # First, submit the URL for scanning
        submit_response = cached_post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json={'url': url, 'visibility': 'public'},
            timeout=10
        )
        
        if submit_response.status_code not in [200, 400]: # 400 means already scanned
            return None
            
        submit_result = submit_response.json()
        uuid = submit_result.get('uuid')
        
        if not uuid:
            # If already scanned, try to get the existing report
            search_response = cached_get(
                f'https://urlscan.io/api/v1/search/?q=url:{url}',
                headers=headers,
                timeout=10
            )
            if search_response.status_code == 200:
                search_result = search_response.json()
                if search_result.get('results'):
                    uuid = search_result['results'][0]['uuid']
            
        if not uuid:
            return None
            
        # Poll for the scan results
        for _ in range(10): # Try up to 10 times
            time.sleep(2) # Wait 2 seconds between polls
            report_response = cached_get(
                f'https://urlscan.io/api/v1/result/{uuid}/',
                headers=headers,
                timeout=10
            )
            
            if report_response.status_code == 200:
                report = report_response.json()
                verdicts = report.get('data', {}).get('verdicts', {})
                overall_verdict = verdicts.get('overall', {})
                
                return {
                    'is_malicious': overall_verdict.get('malicious', False),
                    'score': overall_verdict.get('score', 0),
                    'categories': overall_verdict.get('categories', []),
                    'urlscan_link': report.get('task', {}).get('reportURL')
                }
            elif report_response.status_code == 404: # Not found yet, continue polling
                continue
            else:
                break # Other error, stop polling
        
        return None
    except Exception as e:
        print(f"Error checking URLScan: {e}")
        return None

def check_for_model_update():
    """Check if model needs to be updated based on feedback data"""
    global current_model
    try:
        # Check if it's time to update or if model is not loaded yet
        if current_model is None:
            print("Model not loaded, attempting initial load or training.")
            # Attempt to load existing model
            model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'phishing_pipeline.pkl')
            if os.path.exists(model_path):
                current_model = joblib.load(model_path)
                print("Model loaded successfully during check_for_model_update.")
            else:
                print("No existing model found. Will train a new one if enough feedback data.")

        if current_model is not None and os.path.exists(LAST_UPDATE_PATH):
            with open(LAST_UPDATE_PATH, 'r') as f:
                last_update = datetime.fromisoformat(f.read().strip())
                if (datetime.now() - last_update).total_seconds() < MODEL_UPDATE_INTERVAL:
                    return False  # Not time to update yet
        elif current_model is not None: # If no last update file, but model exists, create one
            with open(LAST_UPDATE_PATH, 'w') as f:
                f.write(datetime.now().isoformat())
            return False

        # If model is still None and no feedback data, can't do anything
        if not os.path.exists(FEEDBACK_DATA_PATH):
            if current_model is None:
                print("No feedback data and no existing model. Cannot update or train.")
            return False
            
        with open(FEEDBACK_DATA_PATH, 'r') as f:
            feedback_data = json.load(f)
            
        if len(feedback_data) < 10:  # Need at least 10 feedback items to update
            if current_model is None:
                print("Not enough feedback data to train a new model.")
            return False
            
        # Implement actual model update logic
        try:
            # 1. Load the current model if not already loaded or if it needs retraining
            if current_model is None:
                current_model = OnlineLearningModel(feature_extractor=extractor)
                print("Initialized new OnlineLearningModel for training.")
            
            # 2. Create a training dataset from feedback
            X_new = []
            y_new = []
        
            for item in feedback_data:
                # Extract features from URL
                url = item.get('url', '')
                if url:
                    features = extractor.extract_all_features(url)
                    X_new.append(features)
                    # Use the corrected label from feedback
                    y_new.append(1 if item.get('is_phishing', False) else 0)
        
            if len(X_new) > 0:
                X_new_df = pd.DataFrame(X_new)
                current_model.incremental_update(X_new_df, y_new)
                current_model.save_model()
                print(f"Model updated with {len(X_new)} new samples")
                
                # Clear processed feedback to avoid retraining on same data
                with open(FEEDBACK_DATA_PATH, 'w') as f:
                    json.dump([], f)
        except Exception as model_error:
            print(f"Error during model update: {model_error}")
            # Continue execution even if model update fails
        
        # Update the timestamp
        with open(LAST_UPDATE_PATH, 'w') as f:
            f.write(datetime.now().isoformat())
            
        return True
    except Exception as e:
        print(f"Error checking for model update: {e}")
        return False

current_model = None

def load_model():
    global current_model
    model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'phishing_pipeline.pkl')
    if os.path.exists(model_path):
        current_model = joblib.load(model_path)
        print("Model loaded successfully.")
    else:
        print("No model found at startup. Model will be initialized on first update or training.")

with app.app_context():
    load_model()

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Check if model needs to be updated
        check_for_model_update()
        
        data = request.get_json()
        url = data.get('url', '')
        check_external_apis = data.get('check_external_apis', True)
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Extract features
        features = extractor.extract_all_features(url)
        
        # Parse URL components
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Analyze SSL certificate if HTTPS
        cert_analysis = None
        threat_details = []
        external_api_results = {}
        
        if parsed.scheme == 'https':
            cert_analysis = analyze_ssl_certificate(domain)
            
            # Add certificate issues to threat details
            if not cert_analysis['valid']:
                threat_details.append({
                    'type': 'certificate_invalid',
                    'description': 'SSL certificate is invalid or missing',
                    'severity': 'high'
                })
            elif cert_analysis['is_expired']:
                threat_details.append({
                    'type': 'certificate_expired',
                    'description': 'SSL certificate has expired',
                    'severity': 'high'
                })
            elif cert_analysis['is_self_signed']:
                threat_details.append({
                    'type': 'certificate_self_signed',
                    'description': 'SSL certificate is self-signed',
                    'severity': 'medium'
                })
            elif cert_analysis['is_short_lived']:
                threat_details.append({
                    'type': 'certificate_short_lived',
                    'description': 'SSL certificate has unusually short validity period',
                    'severity': 'medium'
                })
        
        # Check external APIs asynchronously if requested
        if check_external_apis:
            # Check VirusTotal
            vt_result = check_virustotal(url)
            if vt_result:
                external_api_results['virustotal'] = vt_result
                if vt_result.get('is_malicious'):
                    threat_details.append({
                        'type': 'virustotal_detection',
                        'description': f"VirusTotal detected this URL as malicious ({vt_result.get('malicious', 0)} engines)",
                        'severity': 'high'
                    })
            
            # Check Google Safe Browsing
            gsb_result = check_google_safebrowsing(url)
            if gsb_result:
                external_api_results['google_safebrowsing'] = gsb_result
                if gsb_result.get('is_malicious'):
                    threat_details.append({
                        'type': 'safebrowsing_detection',
                        'description': f"Google Safe Browsing detected this URL as {gsb_result.get('threat_type', 'malicious')}",
                        'severity': 'high'
                    })
            
            # Check URLScan.io
            urlscan_result = check_urlscan(url)
            if urlscan_result:
                external_api_results['urlscan'] = urlscan_result
                if urlscan_result.get('is_malicious'):
                    categories = ', '.join(urlscan_result.get('categories', ['unknown']))
                    threat_details.append({
                        'type': 'urlscan_detection',
                        'description': f"URLScan.io detected this URL as malicious (categories: {categories})",
                        'severity': 'high'
                    })
        
        # Simple heuristic scoring (replace with your model later)
        risk_score = 0.1  # Base low risk
        
        # Risk factors with detailed threat information
        if features['suspicious_keywords']:
            risk_score += 0.4
            threat_details.append({
                'type': 'suspicious_keywords',
                'description': 'URL contains suspicious keywords often used in phishing',
                'severity': 'high'
            })
            
        if features['has_ip']:
            risk_score += 0.3
            threat_details.append({
                'type': 'ip_address_url',
                'description': 'URL uses an IP address instead of a domain name',
                'severity': 'high'
            })
            
        if not features['has_https']:
            risk_score += 0.2
            threat_details.append({
                'type': 'no_https',
                'description': 'Website does not use secure HTTPS connection',
                'severity': 'medium'
            })
            
        if features['url_length'] > 100:
            risk_score += 0.2
            threat_details.append({
                'type': 'excessive_length',
                'description': 'URL is unusually long which may hide the true destination',
                'severity': 'medium'
            })
            
        if features['num_hyphens'] > 3:
            risk_score += 0.1
            threat_details.append({
                'type': 'excessive_hyphens',
                'description': 'Domain contains many hyphens, often used in phishing domains',
                'severity': 'low'
            })
        
        # Adjust risk score based on external API results
        if external_api_results:
            # If any external API detected it as malicious, increase risk
            if (external_api_results.get('virustotal', {}).get('is_malicious') or
                external_api_results.get('google_safebrowsing', {}).get('is_malicious') or
                external_api_results.get('urlscan', {}).get('is_malicious')):
                risk_score = max(risk_score, 0.8)  # At least HIGH risk
        
        risk_score = min(risk_score, 1.0)
        prediction = 1 if risk_score > 0.5 else 0
        
        # Risk level
        if risk_score > 0.8:
            risk_level = "VERY_HIGH"
        elif risk_score > 0.6:
            risk_level = "HIGH"
        elif risk_score > 0.4:
            risk_level = "MODERATE"
        elif risk_score > 0.2:
            risk_level = "LOW"
        else:
            risk_level = "VERY_LOW"
            
        # Create detailed response
        response = {
            'url': url,
            'is_phishing': is_phishing,
            'phishing_probability': phishing_probability,
            'risk_level': risk_level,
            'threat_details': threat_details,
            'certificate_analysis': cert_analysis,
            'external_api_results': external_api_results
        }

        # Store feedback data for continuous learning
        feedback_item = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'is_phishing_predicted': is_phishing,
            'phishing_probability': phishing_probability,
            'is_phishing': None  # To be filled by user feedback
        }
        with open(FEEDBACK_DATA_PATH, 'a+') as f:
            f.seek(0) # Go to the beginning of the file
            try:
                feedback_data = json.load(f)
            except json.JSONDecodeError:
                feedback_data = []
            feedback_data.append(feedback_item)
            f.seek(0) # Go to the beginning of the file again to overwrite
            json.dump(feedback_data, f, indent=4)

        return jsonify(response_data)

    except Exception as e:
        print(f"Error in predict endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/check_email', methods=['POST'])
def check_email():
    try:
        data = request.get_json()
        email = data.get('email', '')
        
        if not email:
            return jsonify({'error': 'Email is required'}), 400
        
        # Extract email parts
        try:
            username, domain = email.split('@')
        except ValueError:
            return jsonify({
                'email': email,
                'is_phishing': True,
                'risk_level': 'HIGH',
                'confidence': 0.9,
                'reasons': ['Invalid email format']
            })
        
        reasons = []
        risk_score = 0.1  # Base low risk

        # Perform external email reputation check
        emailrep_result = check_emailrep(email)
        if emailrep_result and emailrep_result.get('is_malicious'):
            risk_score += 0.5 # Significant increase for malicious email
            reasons.append(f"EmailRep detected this email as suspicious (reputation: {emailrep_result.get('reputation', 'Unknown')})")

        # Check username for suspicious patterns
        if len(username) > 20:
            risk_score += 0.1
            reasons.append('Unusually long username')
        
        if re.search(r'\d{4,}', username):
            risk_score += 0.1
            reasons.append('Username contains many numbers')
        
        # Check domain for suspicious patterns
        suspicious_tlds = ['xyz', 'top', 'work', 'date', 'racing', 'stream']
        domain_parts = domain.split('.')
        tld = domain_parts[-1].lower() if domain_parts else ''
        
        if tld in suspicious_tlds:
            risk_score += 0.3
            reasons.append(f'Suspicious TLD: .{tld}')
        
        if len(domain_parts) > 2 and len(domain_parts[0]) > 15:
            risk_score += 0.2
            reasons.append('Unusually complex domain structure')
        
        # Check for common phishing keywords
        phishing_keywords = ['secure', 'account', 'verify', 'update', 'bank', 'paypal', 'signin']
        for keyword in phishing_keywords:
            if keyword in username.lower() or keyword in domain.lower():
                risk_score += 0.2
                reasons.append(f'Contains phishing keyword: {keyword}')
                break
        
        # Determine risk level
        is_phishing = risk_score > 0.5
        
        if risk_score > 0.8:
            risk_level = "VERY_HIGH"
        elif risk_score > 0.6:
            risk_level = "HIGH"
        elif risk_score > 0.4:
            risk_level = "MODERATE"
        elif risk_score > 0.2:
            risk_level = "LOW"
        else:
            risk_level = "VERY_LOW"
        
        return jsonify({
            'email': email,
            'is_phishing': is_phishing,
            'risk_level': risk_level,
            'confidence': risk_score,
            'reasons': reasons,
            'external_api_results': {'emailrep': emailrep_result} if emailrep_result else {}
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Email analysis error',
            'message': str(e)
        }), 500

@app.route('/batch-predict', methods=['POST'])
def batch_predict():
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({'error': 'URLs list is required'}), 400
        
        results = []
        for url in urls:
            try:
                # Check if model needs to be updated
                check_for_model_update()

                # Extract features
                features = extractor.extract_all_features(url)
                
                # Simple risk calculation
                risk_score = 0.1
                if features['suspicious_keywords']:
                    risk_score += 0.4
                if features['has_ip']:
                    risk_score += 0.3
                if not features['has_https']:
                    risk_score += 0.2
                
                risk_score = min(risk_score, 1.0)
                prediction = 1 if risk_score > 0.5 else 0
                
                results.append({
                    'url': url,
                    'is_phishing': is_phishing,
                    'phishing_probability': phishing_probability,
                    'risk_level': risk_level,
                    'threat_details': threat_details,
                    'external_api_results': external_api_results
                })
                
            except Exception as e:
                results.append({
                    'url': url,
                    'error': f'Analysis failed: {str(e)}'
                })
        
        return jsonify({
            'count': len(results),
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': f'Batch prediction failed: {str(e)}'}), 500

@app.route('/explain', methods=['POST'])
def explain():
    url = request.json.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400

    explanation = current_model.explain_prediction(url)
    return jsonify(explanation)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
