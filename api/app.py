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


# Initialize logging
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins for development


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

    # This endpoint will now only log feedback, not use it for retraining.
    url = data['url']
    is_phishing = data['is_phishing']
    logging.info(f"Feedback received for {url}: {'phishing' if is_phishing else 'legitimate'}")
    return jsonify({'message': 'Feedback received successfully'}), 200


def check_abuseipdb(ip, api_key):
    """Check IP reputation with AbuseIPDB"""
    if not api_key:
        return {'error': 'AbuseIPDB API key not configured', 'is_malicious': False}
    
    try:
        headers = {
            'Key': api_key,
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

def check_emailrep(email, api_key):
    """Check email reputation using EmailRep API"""
    if not api_key:
        return {'error': 'EmailRep API key not configured'}
    
    try:
        headers = {
            'Key': api_key,
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

def aggregate_threat_details(url, domain, api_keys, emails=None):
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
    if api_keys.get('virustotal'):
        vt_result = check_virustotal(url, api_keys['virustotal'])
        threat_details['security_checks']['virustotal'] = vt_result
        if vt_result and vt_result.get('malicious', 0) > 0:
            threat_details['threat_indicators'].append(
                f'VirusTotal: {vt_result.get("malicious", 0)} security vendors flagged as malicious'
            )
    
    # Google Safe Browsing Check
    if api_keys.get('google_safebrowsing'):
        gsb_result = check_google_safebrowsing(url, api_keys['google_safebrowsing'])
        threat_details['security_checks']['google_safebrowsing'] = gsb_result
        if gsb_result and gsb_result.get('matches'):
            threat_details['threat_indicators'].append('Google Safe Browsing: Threats detected')
    
    # URLScan Check
    if api_keys.get('urlscan'):
        urlscan_result = check_urlscan(url, api_keys['urlscan'])
        threat_details['security_checks']['urlscan'] = urlscan_result
        if urlscan_result and urlscan_result.get('malicious'):
            threat_details['threat_indicators'].append('URLScan: Malicious indicators found')
    
    # AbuseIPDB Check
    if api_keys.get('abuseipdb'):
        abuse_result = check_abuseipdb(domain, api_keys['abuseipdb'])
        threat_details['security_checks']['abuseipdb'] = abuse_result
        if abuse_result and abuse_result.get('abuseConfidenceScore', 0) > 25:
            threat_details['threat_indicators'].append(
                f'AbuseIPDB: Abuse confidence score {abuse_result.get("abuseConfidenceScore")}%'
            )
    
    # Email Analysis
    if emails and api_keys.get('emailrep'):
        threat_details['email_analysis'] = {}
        for email in emails:
            email_result = check_emailrep(email, api_keys['emailrep'])
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
        threat_analysis = aggregate_threat_details(url, domain, API_KEYS, emails)
        
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

def check_virustotal(url, api_key):
    """Check URL against VirusTotal API"""
    if not api_key:
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

def check_google_safebrowsing(url, api_key):
    """Check URL against Google Safe Browsing API"""
    if not api_key:
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

def check_urlscan(url, api_key):
    """Check URL against urlscan.io API"""
    if not api_key:
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

current_model = None

def load_model():
    global current_model
    model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'phishing_pipeline.pkl')
    if os.path.exists(model_path):
        try:
            current_model = joblib.load(model_path)
            print("Model loaded successfully.")
        except Exception as e:
            print(f"Error loading model: {e}")
            current_model = None
    else:
        print("No model found at startup. Predictions will rely on API checks only.")

with app.app_context():
    load_model()

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '')

        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        domain = urlparse(url).netloc

        # Extract API keys from headers if available, otherwise use environment variables
        api_keys = API_KEYS.copy()
        for api_name in ['ABUSEIPDB', 'VIRUSTOTAL', 'GOOGLE_SAFE_BROWSING', 'URLSCAN', 'EMAILREP']:
            header_key = f'X-{api_name.replace("_", "-")}-Key'
            if header_key in request.headers:
                api_keys[api_name.lower()] = request.headers.get(header_key)
                logging.info(f"Received API key for {api_name} from header")

        # Get comprehensive threat analysis from external APIs
        threat_analysis = aggregate_threat_details(url, domain, api_keys)

        # Use the loaded model for prediction
        prediction = -1
        prediction_proba = [0.5, 0.5]
        model_message = 'Model not loaded. Prediction is based on API checks.'

        if current_model:
            try:
                feature_extractor = EnhancedURLFeatureExtractor()
                features = feature_extractor.extract_all_features(url)
                features_df = pd.DataFrame([features])
                
                # This is a simplified approach; a more robust solution would handle column differences.
                if hasattr(current_model, 'steps'):
                    model_cols = current_model.steps[-1][1].feature_names_in_
                    features_df = features_df.reindex(columns=model_cols, fill_value=0)

                prediction_proba = current_model.predict_proba(features_df)
                prediction = int(current_model.predict(features_df)[0])
                model_message = 'Prediction from loaded model.'
            except Exception as e:
                logging.error(f"Error during model prediction: {e}")
                model_message = f"Error during model prediction: {e}"

        # Combine model prediction with API analysis
        final_risk_level = threat_analysis.get('risk_level', 'Unknown')
        confidence = 0.0

        if prediction == 1:
            final_risk_level = "High" if final_risk_level not in ["Critical", "High"] else final_risk_level
            confidence = max(confidence, prediction_proba[0][1])
        
        # Adjust confidence based on API results
        if final_risk_level == "Critical":
            confidence = max(confidence, 0.95)
        elif final_risk_level == "High":
            confidence = max(confidence, 0.8)
        elif final_risk_level == "Medium":
            confidence = max(confidence, 0.6)
        elif final_risk_level == "Low":
            confidence = max(confidence, 0.3)

        response = {
            'url': url,
            'riskLevel': final_risk_level,
            'confidence': round(confidence * 100, 2),
            'isPhishing': prediction == 1 or final_risk_level in ["High", "Critical"],
            'threatDetails': threat_analysis.get('threat_indicators', []),
            'externalApiResults': threat_analysis.get('security_checks', {}),
            'model_prediction': {
                'prediction': prediction,
                'prediction_proba': prediction_proba.tolist(),
                'message': model_message
            }
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
                # This endpoint now provides a simplified analysis without the full model prediction
                # for batch processing speed. For full analysis, use the /predict endpoint.
                # for batch processing speed. For full analysis, use the /predict endpoint.
                feature_extractor = EnhancedURLFeatureExtractor()
                features = feature_extractor.extract_all_features(url)
                
                risk_score = 0.1
                if features.get('suspicious_keywords', 0) > 0:
                    risk_score += 0.4
                if features.get('has_ip', 0) > 0:
                    risk_score += 0.3
                if features.get('has_https', 0) == 0:
                    risk_score += 0.2
                
                risk_score = min(risk_score, 1.0)
                is_phishing = risk_score > 0.5
                
                results.append({
                    'url': url,
                    'is_phishing': is_phishing,
                    'phishing_probability': risk_score,
                    'risk_level': "High" if is_phishing else "Low",
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
