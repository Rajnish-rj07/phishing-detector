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
import logging
from datetime import datetime, timedelta
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
from src.feature_extractor import EnhancedURLFeatureExtractor
from src.online_mode import OnlineLearningModel # Import OnlineLearningModel

# Initialize logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins for development

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

@app.route('/feedback', methods=['POST'])
def feedback():
    """Receive feedback from users about predictions"""
    data = request.get_json()
    if not data or 'url' not in data or 'is_phishing' not in data:
        return jsonify({'error': 'Invalid feedback data'}), 400

    url = data['url']
    is_phishing = data['is_phishing']

    # Store feedback for model retraining
    feedback_entry = {
        'url': url,
        'is_phishing': is_phishing,
        'timestamp': datetime.now().isoformat()
    }

    try:
        with open(FEEDBACK_DATA_PATH, 'a') as f:
            f.write(json.dumps(feedback_entry) + '\n')
        logging.info(f"Feedback received for {url}: {'phishing' if is_phishing else 'legitimate'}")
        return jsonify({'message': 'Feedback received successfully'}), 200
    except Exception as e:
        logging.error(f"Error saving feedback: {e}")
        return jsonify({'error': 'Failed to save feedback'}), 500

def retrain_model_from_feedback():
    """Retrain the model using collected feedback"""
    if not os.path.exists(FEEDBACK_DATA_PATH):
        logging.info("No feedback data found, skipping retraining.")
        return

    try:
        with open(FEEDBACK_DATA_PATH, 'r') as f:
            feedback_data = [json.loads(line) for line in f]

        if not feedback_data:
            logging.info("Feedback data is empty, skipping retraining.")
            return

        # Prepare data for retraining
        urls = [item['url'] for item in feedback_data]
        labels = [1 if item['is_phishing'] else 0 for item in feedback_data]

        # Create features
        feature_extractor = EnhancedURLFeatureExtractor(None)
        features = [feature_extractor.extract_all_features(url) for url in urls]

        # Convert to DataFrame
        df = pd.DataFrame(features)
        df['label'] = labels

        # Separate features and labels
        X = df.drop('label', axis=1)
        y = df['label']

        # Load the existing model
        online_model = OnlineLearningModel()
        online_model.load_model(MODEL_PATH)

        # Perform incremental training
        online_model.incremental_train(X, y)

        # Save the updated model
        online_model.save_model(MODEL_PATH)

        # Clear feedback data after retraining
        open(FEEDBACK_DATA_PATH, 'w').close()

        logging.info("Model retrained successfully from feedback.")

    except Exception as e:
        logging.error(f"Error during model retraining: {e}")

def check_and_retrain_model():
    """Check if model needs retraining and trigger it"""
    while True:
        time.sleep(MODEL_UPDATE_INTERVAL)
        logging.info("Checking for model update...")
        retrain_model_from_feedback()


# Replace before_first_request with a function that runs after app startup
def start_background_tasks():
    executor.submit(check_and_retrain_model)

# Register the function to run after app startup
with app.app_context():
    start_background_tasks()

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
    """Check email reputation using EmailRep API"""
    if not API_KEYS['emailrep']:
        return {'error': 'EmailRep API key not configured'}
    
    try:
        headers = {
            'Key': API_KEYS['emailrep'],
            'User-Agent': 'PhishingDetector/1.0'
        }
        response = requests.get(
            f'https://emailrep.io/{email}',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'reputation': data.get('reputation', 'unknown'),
                'suspicious': data.get('suspicious', False),
                'details': {
                    'blacklisted': data.get('details', {}).get('blacklisted', False),
                    'malicious_activity': data.get('details', {}).get('malicious_activity', False),
                    'recent_suspicious_activity': data.get('details', {}).get('recent_suspicious_activity', False),
                    'spam': data.get('details', {}).get('spam', False),
                    'disposable': data.get('details', {}).get('disposable', False),
                    'spoofable': data.get('details', {}).get('spoofable', False),
                    'profiles': data.get('details', {}).get('profiles', []),
                    'domain_exists': data.get('details', {}).get('domain_exists', False),
                    'domain_reputation': data.get('details', {}).get('domain_reputation', 'unknown'),
                    'first_seen': data.get('details', {}).get('first_seen', 'unknown'),
                    'last_seen': data.get('details', {}).get('last_seen', 'unknown')
                }
            }
        else:
            return {'error': f'EmailRep API returned status code {response.status_code}'}
            
    except Exception as e:
        return {'error': f'Error checking EmailRep: {str(e)}'}

@app.route('/api/check_email', methods=['POST'])
def analyze_email():
    """Analyze email address for potential threats"""
    try:
        data = request.get_json()
        email = data.get('email')
        
        if not email:
            return jsonify({'error': 'Email address is required'}), 400
            
        # Check if EmailRep API key is configured
        if not API_KEYS['emailrep']:
            return jsonify({'error': 'EmailRep API key not configured'}), 400
            
        # Get email reputation data
        email_rep_data = check_emailrep(email)
        
        if 'error' in email_rep_data:
            return jsonify(email_rep_data), 400
            
        # Prepare response with detailed analysis
        response = {
            'email': email,
            'timestamp': datetime.now().isoformat(),
            'reputation_data': email_rep_data,
            'risk_assessment': {
                'risk_level': calculate_email_risk_level(email_rep_data),
                'suspicious_indicators': get_suspicious_indicators(email_rep_data)
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logging.error(f"Error analyzing email: {str(e)}")
        return jsonify({'error': str(e)}), 500

def calculate_email_risk_level(email_data):
    """Calculate risk level based on email reputation data"""
    risk_score = 0
    
    # Check suspicious indicators
    if email_data.get('suspicious', False):
        risk_score += 30
    
    details = email_data.get('details', {})
    
    # Add points for various risk factors
    if details.get('blacklisted', False):
        risk_score += 25
    if details.get('malicious_activity', False):
        risk_score += 20
    if details.get('recent_suspicious_activity', False):
        risk_score += 15
    if details.get('spam', False):
        risk_score += 10
    if details.get('disposable', False):
        risk_score += 10
    if details.get('spoofable', False):
        risk_score += 10
    
    # Determine risk level
    if risk_score >= 70:
        return 'High'
    elif risk_score >= 40:
        return 'Medium'
    elif risk_score > 0:
        return 'Low'
    return 'Safe'

def get_suspicious_indicators(email_data):
    """Extract suspicious indicators from email reputation data"""
    indicators = []
    details = email_data.get('details', {})
    
    if email_data.get('suspicious', False):
        indicators.append('Suspicious activity detected')
    if details.get('blacklisted', False):
        indicators.append('Email is blacklisted')
    if details.get('malicious_activity', False):
        indicators.append('Malicious activity detected')
    if details.get('recent_suspicious_activity', False):
        indicators.append('Recent suspicious activity')
    if details.get('spam', False):
        indicators.append('Associated with spam')
    if details.get('disposable', False):
        indicators.append('Disposable email service')
    if details.get('spoofable', False):
        indicators.append('Email can be spoofed')
    if not details.get('domain_exists', True):
        indicators.append('Domain does not exist')
    
    return indicators
def validate_api_keys():
    """Validate that all required API keys are present"""
    missing_keys = []
    for service, key in API_KEYS.items():
        if not key:
            missing_keys.append(service)
    return missing_keys

def check_ssl_certificate(domain):
    """Analyze SSL certificate of the domain"""
    try:
        response = requests.get(f'https://{domain}', verify=True, timeout=5)
        cert = response.raw.connection.sock.getpeercert()
        return {
            'valid': True,
            'issuer': dict(x[0] for x in cert['issuer']),
            'subject': dict(x[0] for x in cert['subject']),
            'expiry': cert['notAfter']
        }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def aggregate_threat_details(url, domain, emails=None):
    """Aggregate threat details from all available sources"""
    threat_details = {
        'url': url,
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'risk_level': 'Unknown',
        'threat_indicators': [],
        'security_checks': {
            'ssl_certificate': None,
            'virustotal': None,
            'google_safebrowsing': None,
            'urlscan': None,
            'abuseipdb': None
        },
        'email_analysis': {},
        'recommendations': []
    }
    
    # Check SSL Certificate
    ssl_result = check_ssl_certificate(domain)
    threat_details['security_checks']['ssl_certificate'] = ssl_result
    if ssl_result.get('error'):
        threat_details['threat_indicators'].append('SSL Certificate issues detected')
        threat_details['recommendations'].append('Verify SSL certificate configuration')
    
    # VirusTotal Check
    if API_KEYS['virustotal']:
        vt_result = check_virustotal(url)
        threat_details['security_checks']['virustotal'] = vt_result
        if vt_result.get('malicious', 0) > 0:
            threat_details['threat_indicators'].append(
                f'VirusTotal: {vt_result.get("malicious", 0)} security vendors flagged as malicious'
            )
    
    # Google Safe Browsing Check
    if API_KEYS['safebrowsing']:
        gsb_result = check_google_safebrowsing(url)
        threat_details['security_checks']['google_safebrowsing'] = gsb_result
        if gsb_result.get('matches'):
            threat_details['threat_indicators'].append('Google Safe Browsing: Threats detected')
    
    # URLScan Check
    if API_KEYS['urlscan']:
        urlscan_result = check_urlscan(url)
        threat_details['security_checks']['urlscan'] = urlscan_result
        if urlscan_result.get('malicious'):
            threat_details['threat_indicators'].append('URLScan: Malicious indicators found')
    
    # AbuseIPDB Check
    if API_KEYS['abuseipdb']:
        abuse_result = check_abuseipdb(domain)
        threat_details['security_checks']['abuseipdb'] = abuse_result
        if abuse_result.get('abuseConfidenceScore', 0) > 25:
            threat_details['threat_indicators'].append(
                f'AbuseIPDB: Abuse confidence score {abuse_result.get("abuseConfidenceScore")}%'
            )
    
    # Email Analysis
    if emails and API_KEYS['emailrep']:
        threat_details['email_analysis'] = {}
        for email in emails:
            email_result = check_emailrep(email)
            threat_details['email_analysis'][email] = {
                'reputation': email_result.get('reputation'),
                'risk_level': calculate_email_risk_level(email_result),
                'indicators': get_suspicious_indicators(email_result)
            }
            if email_result.get('suspicious'):
                threat_details['threat_indicators'].append(f'Suspicious email detected: {email}')
    
    # Calculate overall risk level
    threat_details['risk_level'] = calculate_overall_risk_level(threat_details)
    
    # Generate recommendations
    threat_details['recommendations'].extend(generate_security_recommendations(threat_details))
    
    return threat_details

def calculate_overall_risk_level(threat_details):
    """Calculate overall risk level based on all security checks"""
    risk_score = 0
    
    # Count threat indicators
    risk_score += len(threat_details['threat_indicators']) * 10
    
    # Check VirusTotal results
    vt_results = threat_details['security_checks']['virustotal']
    if vt_results and vt_results.get('malicious', 0) > 0:
        risk_score += min(vt_results.get('malicious', 0) * 5, 30)
    
    # Check Google Safe Browsing results
    gsb_results = threat_details['security_checks']['google_safebrowsing']
    if gsb_results and gsb_results.get('matches'):
        risk_score += 30
    
    # Check URLScan results
    urlscan_results = threat_details['security_checks']['urlscan']
    if urlscan_results and urlscan_results.get('malicious'):
        risk_score += 25
    
    # Check AbuseIPDB score
    abuse_results = threat_details['security_checks']['abuseipdb']
    if abuse_results:
        risk_score += min(abuse_results.get('abuseConfidenceScore', 0) / 2, 25)
    
    # Check SSL certificate issues
    ssl_results = threat_details['security_checks']['ssl_certificate']
    if ssl_results and ssl_results.get('error'):
        risk_score += 15
    
    # Check email analysis
    for email_result in threat_details['email_analysis'].values():
        if email_result['risk_level'] == 'High':
            risk_score += 20
        elif email_result['risk_level'] == 'Medium':
            risk_score += 10
        elif email_result['risk_level'] == 'Low':
            risk_score += 5
    
    # Determine risk level
    if risk_score >= 70:
        return 'Critical'
    elif risk_score >= 50:
        return 'High'
    elif risk_score >= 30:
        return 'Medium'
    elif risk_score > 0:
        return 'Low'
    return 'Safe'

def generate_security_recommendations(threat_details):
    """Generate security recommendations based on threat analysis"""
    recommendations = []
    
    # SSL Certificate recommendations
    ssl_results = threat_details['security_checks']['ssl_certificate']
    if ssl_results and ssl_results.get('error'):
        recommendations.append('Update SSL certificate configuration')
        recommendations.append('Ensure proper SSL certificate installation')
    
    # VirusTotal recommendations
    vt_results = threat_details['security_checks']['virustotal']
    if vt_results and vt_results.get('malicious', 0) > 0:
        recommendations.append('Investigate and address malware indicators')
        recommendations.append('Scan website for malicious content')
    
    # Google Safe Browsing recommendations
    gsb_results = threat_details['security_checks']['google_safebrowsing']
    if gsb_results and gsb_results.get('matches'):
        recommendations.append('Address security issues flagged by Google Safe Browsing')
        recommendations.append('Submit site for review after fixing security issues')
    
    # URLScan recommendations
    urlscan_results = threat_details['security_checks']['urlscan']
    if urlscan_results and urlscan_results.get('malicious'):
        recommendations.append('Review and address suspicious URL patterns')
        recommendations.append('Implement URL filtering and monitoring')
    
    # AbuseIPDB recommendations
    abuse_results = threat_details['security_checks']['abuseipdb']
    if abuse_results and abuse_results.get('abuseConfidenceScore', 0) > 25:
        recommendations.append('Investigate reported abuse incidents')
        recommendations.append('Implement IP-based security controls')
    
    # Email security recommendations
    for email, email_result in threat_details['email_analysis'].items():
        if email_result['risk_level'] in ['High', 'Medium']:
            recommendations.append(f'Investigate suspicious email: {email}')
            recommendations.append('Implement additional email security measures')
    
    # General security recommendations
    if len(threat_details['threat_indicators']) > 0:
        recommendations.append('Enable real-time security monitoring')
        recommendations.append('Implement regular security assessments')
        recommendations.append('Update security policies and procedures')
    
    return list(set(recommendations))  # Remove duplicates

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for potential threats"""
    try:
        data = request.get_json()
        url = data.get('url')
        emails = data.get('emails', [])
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Extract domain from URL
        domain = extract_domain(url)
        if not domain:
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Validate API keys
        missing_keys = validate_api_keys()
        if missing_keys:
            logging.warning(f"Missing API keys: {', '.join(missing_keys)}")
        
        # Get comprehensive threat analysis
        threat_analysis = aggregate_threat_details(url, domain, emails)
        
        # Prepare response
        response = {
            'url': url,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'risk_level': threat_analysis['risk_level'],
            'threat_indicators': threat_analysis['threat_indicators'],
            'security_checks': threat_analysis['security_checks'],
            'recommendations': threat_analysis['recommendations']
        }
        
        if emails:
            response['email_analysis'] = threat_analysis['email_analysis']
        
        return jsonify(response)
        
    except Exception as e:
        logging.error(f"Error analyzing URL: {str(e)}")
        return jsonify({'error': str(e)}), 500

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
                # current_model = joblib.load(model_path) # Old line
                current_model_instance = OnlineLearningModel()
                if current_model_instance.load_model():
                    current_model = current_model_instance
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
        # current_model = joblib.load(model_path) # Old line
        current_model_instance = OnlineLearningModel()
        if current_model_instance.load_model():
            current_model = current_model_instance
        print("Model loaded successfully.")
    else:
        print("No model found at startup. Model will be initialized on first update or training.")

with app.app_context():
    load_model()

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        # Extract API keys from headers if available
        api_keys = {}
        for api_name in ['ABUSEIPDB', 'VIRUSTOTAL', 'GOOGLE_SAFE_BROWSING', 'URLSCAN']:
            header_key = f'X-{api_name.replace("_", "-")}-Key'
            if header_key in request.headers:
                api_keys[api_name.lower()] = request.headers.get(header_key)
                logging.info(f"Received API key for {api_name}")

        # Use the enhanced feature extractor
        feature_extractor = EnhancedURLFeatureExtractor()
        features = feature_extractor.extract_all_features(url)
        
        # Check URL reputation with external APIs if keys are provided
        reputation_results = {}
        if api_keys.get('virustotal'):
            try:
                from src.reputation_checker import ReputationChecker
                reputation_checker = ReputationChecker(api_keys)
                reputation_results = reputation_checker.check_all_reputations(url)
                logging.info(f"Reputation check completed for {url}")
            except Exception as e:
                logging.error(f"Error in reputation check: {e}")

        # Prepare features for the model
        # Create a DataFrame from the extracted features
        features_df = pd.DataFrame([features])
        features_df['url'] = url 

        # Get prediction
        # Use the online_model variable that's defined in the file
        if 'online_model' in globals() and online_model.is_fitted:
            prediction_proba = online_model.predict_proba(features_df)
            prediction = online_model.predict(features_df)
            
            response = {
                'prediction': int(prediction[0]),
                'prediction_proba': prediction_proba.tolist(),
                'features': features,
                'api_results': reputation_results
            }
        else:
            response = {
                'prediction': -1, # Indicate that the model is not ready
                'prediction_proba': [0.5, 0.5],
                'features': features,
                'api_results': reputation_results,
                'message': 'Model is not yet trained. Prediction is based on default values.'
            }

        return jsonify(response)

    except Exception as e:
        logging.error(f"Error during prediction: {e}")
        return jsonify({'error': 'An error occurred during prediction.'}), 500

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
