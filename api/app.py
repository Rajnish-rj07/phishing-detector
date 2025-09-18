from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
import tldextract
import requests
import time
from datetime import datetime

app = Flask(__name__)
CORS(app)

class SimpleFeatureExtractor:
    def extract_all_features(self, url):
        """Extract basic features without complex imports"""
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        features = {
            'url_length': len(url),
            'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_slashes': url.count('/'),
            'has_https': 1 if parsed.scheme == 'https' else 0,
            'domain_length': len(extracted.domain),
            'path_length': len(parsed.path),
            'query_length': len(parsed.query) if parsed.query else 0,
            'suspicious_keywords': self.check_suspicious_keywords(url)
        }
        return features
    
    def check_suspicious_keywords(self, url):
        suspicious_words = ['verify', 'account', 'login', 'bank', 'secure', 'update']
        return 1 if any(word in url.lower() for word in suspicious_words) else 0

# Initialize
extractor = SimpleFeatureExtractor()

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

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Extract features
        features = extractor.extract_all_features(url)
        
        # Simple heuristic scoring (replace with your model later)
        risk_score = 0.1  # Base low risk
        
        # Risk factors
        if features['suspicious_keywords']:
            risk_score += 0.4
        if features['has_ip']:
            risk_score += 0.3
        if not features['has_https']:
            risk_score += 0.2
        if features['url_length'] > 100:
            risk_score += 0.2
        if features['num_hyphens'] > 3:
            risk_score += 0.1
        
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
        
        return jsonify({
            'url': url,
            'prediction': prediction,
            'prediction_label': 'Phishing' if prediction == 1 else 'Legitimate',
            'probability_legitimate': float(1 - risk_score),
            'probability_phishing': float(risk_score),
            'risk_level': risk_level,
            'confidence': float(max(risk_score, 1 - risk_score)),
            'features_analyzed': len(features),
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            'error': f'Prediction failed: {str(e)}',
            'url': url if 'url' in locals() else 'unknown'
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
                    'prediction': prediction,
                    'probability_legitimate': float(1 - risk_score),
                    'probability_phishing': float(risk_score),
                    'risk_level': 'HIGH' if risk_score > 0.6 else 'LOW'
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
