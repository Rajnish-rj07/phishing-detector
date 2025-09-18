from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import numpy as np
import os
import logging
from datetime import datetime, timedelta

# Import your enhanced modules
import sys
sys.path.append('..')
from src.feature_extractor import EnhancedURLFeatureExtractor
from src.online_model import OnlineLearningModel
from src.data_collector import RealTimeDataCollector

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Initialize components
try:
    extractor = EnhancedURLFeatureExtractor()
    model = OnlineLearningModel()
    data_collector = RealTimeDataCollector()
    
    # Try to load existing model, otherwise train new one
    if not model.load_model():
        logging.info("No existing model found, performing initial training...")
        # Get initial training data
        df = data_collector.get_recent_data(hours=168)  # Last week
        if len(df) > 100:
            # Extract features for training data
            X_train = []
            for url in df['url']:
                try:
                    features = extractor.extract_all_features(url)
                    X_train.append(features)
                except Exception as e:
                    logging.error(f"Error extracting features for {url}: {e}")
            
            if X_train:
                X_train_df = pd.DataFrame(X_train)
                X_train_df = X_train_df.fillna(0)  # Handle missing values
                
                model.initial_training(
                    X_train_df.values, 
                    df['label'].values, 
                    X_train_df.columns.tolist()
                )
    
    logging.info("Model and components initialized successfully")
    
except Exception as e:
    logging.error(f"Error initializing components: {e}")
    # Fallback to basic functionality

@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "message": "Real-Time Phishing Detection API",
        "version": "2.0",
        "endpoints": ["/health", "/predict", "/batch-predict", "/update-model", "/stats"]
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_loaded": model.is_fitted if 'model' in globals() else False,
        "last_update": model.performance_history[-1]['timestamp'].isoformat() if model.performance_history else None
    })

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Extract enhanced features
        features = extractor.extract_all_features(url)
        logging.info(f"Extracted features for {url}: {len(features)} features")
        
        # Convert to DataFrame
        df = pd.DataFrame([features])
        df = df.fillna(0)
        
        # Make prediction
        probabilities = model.predict_proba(df)[0]
        prediction = int(probabilities[1] > 0.5)
        
        # Enhanced risk assessment
        risk_level = "VERY_LOW"
        if probabilities[1] > 0.8:
            risk_level = "VERY_HIGH"
        elif probabilities[1] > 0.6:
            risk_level = "HIGH"
        elif probabilities[1] > 0.4:
            risk_level = "MODERATE"
        elif probabilities[1] > 0.2:
            risk_level = "LOW"
        
        return jsonify({
            'url': url,
            'prediction': prediction,
            'prediction_label': 'Phishing' if prediction == 1 else 'Legitimate',
            'probability_legitimate': float(probabilities[0]),
            'probability_phishing': float(probabilities[1]),
            'risk_level': risk_level,
            'confidence': float(max(probabilities)),
            'features_analyzed': len(features),
            'reputation_score': features.get('reputation_score', 0.5),
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        logging.error(f"Prediction error for {url}: {e}")
        return jsonify({
            'error': f'Prediction failed: {str(e)}',
            'url': url
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
                df = pd.DataFrame([features]).fillna(0)
                
                probabilities = model.predict_proba(df)[0]
                prediction = int(probabilities[1] > 0.5)
                
                results.append({
                    'url': url,
                    'prediction': prediction,
                    'probability_legitimate': float(probabilities[0]),
                    'probability_phishing': float(probabilities[1]),
                    'risk_level': 'HIGH' if probabilities[1] > 0.6 else 'LOW'
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
        logging.error(f"Batch prediction error: {e}")
        return jsonify({'error': f'Batch prediction failed: {str(e)}'}), 500

@app.route('/update-model', methods=['POST'])
def update_model():
    """Trigger model update with latest threat data"""
    try:
        # Collect latest data
        logging.info("Updating model with latest threat data...")
        data_collector.update_threat_database()
        
        # Get recent data for incremental learning
        df = data_collector.get_recent_data(hours=24)
        
        if len(df) > 10:  # Minimum samples for update
            X_new = []
            for url in df['url']:
                try:
                    features = extractor.extract_all_features(url)
                    X_new.append(features)
                except:
                    continue
            
            if X_new:
                X_new_df = pd.DataFrame(X_new).fillna(0)
                model.incremental_update(X_new_df.values, df['label'].values)
                
                return jsonify({
                    'message': 'Model updated successfully',
                    'samples_processed': len(X_new),
                    'timestamp': datetime.now().isoformat()
                })
        
        return jsonify({
            'message': 'No new samples available for update',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logging.error(f"Model update error: {e}")
        return jsonify({'error': f'Model update failed: {str(e)}'}), 500

@app.route('/stats', methods=['GET'])
def stats():
    """Get model performance statistics"""
    try:
        return jsonify({
            'model_fitted': model.is_fitted,
            'feature_count': len(model.feature_names) if model.feature_names else 0,
            'performance_history': model.performance_history[-10:],  # Last 10 updates
            'last_updated': model.performance_history[-1]['timestamp'].isoformat() if model.performance_history else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
