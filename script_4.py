# Phase 4: Flask API Development

flask_api_code = '''
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import pickle
import joblib
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from feature_extractor import URLFeatureExtractor
except ImportError:
    print("Warning: Could not import URLFeatureExtractor. Make sure to run from correct directory.")
    URLFeatureExtractor = None

import pandas as pd
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

class PhishingDetectorAPI:
    def __init__(self, model_path='../models/phishing_model.pkl'):
        self.model_package = None
        self.feature_extractor = URLFeatureExtractor() if URLFeatureExtractor else None
        self.load_model(model_path)
        
    def load_model(self, model_path):
        """Load the trained model and preprocessors"""
        try:
            # Try loading with joblib first
            joblib_path = model_path.replace('.pkl', '_joblib.pkl')
            if os.path.exists(joblib_path):
                self.model_package = joblib.load(joblib_path)
                logger.info(f"Model loaded successfully from {joblib_path}")
            else:
                with open(model_path, 'rb') as f:
                    self.model_package = pickle.load(f)
                logger.info(f"Model loaded successfully from {model_path}")
                
            logger.info(f"Model: {self.model_package.get('model_name', 'Unknown')}")
            logger.info(f"Training date: {self.model_package.get('training_date', 'Unknown')}")
            logger.info(f"Best score: {self.model_package.get('best_score', 'Unknown')}")
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            self.model_package = None
    
    def predict_url(self, url):
        """Predict if URL is phishing"""
        if not self.model_package or not self.feature_extractor:
            return {'error': 'Model not loaded properly'}
        
        try:
            # Extract features
            features = self.feature_extractor.extract_all_features(url)
            features_df = pd.DataFrame([features])
            
            # Fill missing values
            features_df = features_df.fillna(0)
            
            # Apply preprocessing
            scaler = self.model_package['scaler']
            features_scaled = scaler.transform(features_df)
            
            # Apply feature selection if used
            feature_selector = self.model_package.get('feature_selector')
            if feature_selector:
                features_scaled = feature_selector.transform(features_scaled)
            
            # Make prediction
            model = self.model_package['model']
            prediction = model.predict(features_scaled)[0]
            
            # Get prediction probability
            try:
                probabilities = model.predict_proba(features_scaled)[0]
                confidence = float(probabilities.max())
                prob_legitimate = float(probabilities[0])
                prob_phishing = float(probabilities[1])
            except:
                confidence = 0.5
                prob_legitimate = 0.5
                prob_phishing = 0.5
            
            return {
                'url': url,
                'prediction': int(prediction),
                'prediction_label': 'Phishing' if prediction == 1 else 'Legitimate',
                'confidence': confidence,
                'probability_legitimate': prob_legitimate,
                'probability_phishing': prob_phishing,
                'risk_level': self.get_risk_level(prob_phishing),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error predicting URL {url}: {e}")
            return {'error': f'Prediction failed: {str(e)}'}
    
    def get_risk_level(self, phishing_probability):
        """Convert probability to risk level"""
        if phishing_probability >= 0.8:
            return 'HIGH'
        elif phishing_probability >= 0.6:
            return 'MEDIUM'
        elif phishing_probability >= 0.4:
            return 'LOW'
        else:
            return 'VERY_LOW'

# Initialize the detector
detector = PhishingDetectorAPI()

@app.route('/')
def home():
    """API documentation homepage"""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Phishing Detection API</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { color: #333; border-bottom: 2px solid #007cba; padding-bottom: 10px; }
            .endpoint { background: #f5f5f5; padding: 15px; margin: 15px 0; border-radius: 5px; }
            .method { color: #007cba; font-weight: bold; }
            .url { color: #666; }
            .example { background: #e8f4fd; padding: 10px; border-radius: 3px; margin: 10px 0; }
            .json { background: #f8f8f8; padding: 10px; border-left: 4px solid #007cba; }
        </style>
    </head>
    <body>
        <h1 class="header">🛡️ Phishing Detection API</h1>
        
        <p>Real-time phishing website detection using machine learning.</p>
        
        <div class="endpoint">
            <h3><span class="method">GET</span> <span class="url">/</span></h3>
            <p>API documentation (this page)</p>
        </div>
        
        <div class="endpoint">
            <h3><span class="method">POST</span> <span class="url">/predict</span></h3>
            <p>Analyze a URL for phishing indicators</p>
            
            <h4>Request Body:</h4>
            <div class="json">
            <pre>{
    "url": "https://example.com"
}</pre>
            </div>
            
            <h4>Response:</h4>
            <div class="json">
            <pre>{
    "url": "https://example.com",
    "prediction": 0,
    "prediction_label": "Legitimate",
    "confidence": 0.95,
    "probability_legitimate": 0.95,
    "probability_phishing": 0.05,
    "risk_level": "VERY_LOW",
    "timestamp": "2024-01-01T12:00:00.000000"
}</pre>
            </div>
        </div>
        
        <div class="endpoint">
            <h3><span class="method">GET</span> <span class="url">/health</span></h3>
            <p>API health check</p>
        </div>
        
        <div class="endpoint">
            <h3><span class="method">GET</span> <span class="url">/model-info</span></h3>
            <p>Information about the loaded model</p>
        </div>
        
        <h3>Risk Levels:</h3>
        <ul>
            <li><strong>VERY_LOW</strong>: 0-40% phishing probability</li>
            <li><strong>LOW</strong>: 40-60% phishing probability</li>
            <li><strong>MEDIUM</strong>: 60-80% phishing probability</li>
            <li><strong>HIGH</strong>: 80-100% phishing probability</li>
        </ul>
    </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/predict', methods=['POST'])
def predict():
    """Main prediction endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL in request body'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'Empty URL provided'}), 400
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Make prediction
        result = detector.predict_url(url)
        
        if 'error' in result:
            return jsonify(result), 500
        
        logger.info(f"Prediction for {url}: {result['prediction_label']} ({result['confidence']:.2f})")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in predict endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/batch-predict', methods=['POST'])
def batch_predict():
    """Batch prediction endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'urls' not in data:
            return jsonify({'error': 'Missing URLs in request body'}), 400
        
        urls = data['urls']
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs must be a list'}), 400
        
        if len(urls) > 100:  # Limit batch size
            return jsonify({'error': 'Too many URLs. Maximum 100 per batch.'}), 400
        
        results = []
        for url in urls:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            result = detector.predict_url(url)
            results.append(result)
        
        return jsonify({'results': results, 'count': len(results)})
        
    except Exception as e:
        logger.error(f"Error in batch-predict endpoint: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'model_loaded': detector.model_package is not None,
        'feature_extractor_loaded': detector.feature_extractor is not None
    }
    
    return jsonify(status)

@app.route('/model-info', methods=['GET'])
def model_info():
    """Model information endpoint"""
    if not detector.model_package:
        return jsonify({'error': 'No model loaded'}), 500
    
    info = {
        'model_name': detector.model_package.get('model_name', 'Unknown'),
        'training_date': detector.model_package.get('training_date', 'Unknown'),
        'best_score': detector.model_package.get('best_score', 'Unknown'),
        'timestamp': datetime.now().isoformat()
    }
    
    return jsonify(info)

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Development server
    app.run(host='0.0.0.0', port=5000, debug=True)
'''

# Save the Flask API script
with open('phishing-detector/api/app.py', 'w') as f:
    f.write(flask_api_code)

# Create requirements.txt for the API
requirements_txt = '''
Flask==2.3.3
Flask-CORS==4.0.0
pandas==1.5.3
numpy==1.24.3
scikit-learn==1.3.0
tldextract==3.4.4
joblib==1.3.2
gunicorn==21.2.0
requests==2.31.0
'''

with open('phishing-detector/api/requirements.txt', 'w') as f:
    f.write(requirements_txt)

# Create Procfile for Heroku deployment
procfile_content = '''web: gunicorn app:app --workers=1 --timeout=60'''

with open('phishing-detector/api/Procfile', 'w') as f:
    f.write(procfile_content)

print("✅ Phase 4: Flask API created!")
print("📄 Files created:")
print("  - phishing-detector/api/app.py")
print("  - phishing-detector/api/requirements.txt") 
print("  - phishing-detector/api/Procfile")