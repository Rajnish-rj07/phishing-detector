import os
import pickle
import pandas as pd
from flask import Flask, request, jsonify


# Ensure your project root is on PYTHONPATH
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

# Import the same extractor used in training
from src.feature_extractor import URLFeatureExtractor

# Load the pipeline
import os
PIPELINE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'models', 'phishing_pipeline.pkl'))

with open(PIPELINE_PATH, 'rb') as f:
    pkg = pickle.load(f)

model       = pkg['model']
scaler_std  = pkg['scaler_std']
scaler_mm   = pkg['scaler_mm']
selector    = pkg['selector']
model_name  = pkg.get('model_name', 'Unknown')
best_score  = pkg.get('accuracy', 'Unknown')
train_date  = pkg.get('timestamp', 'Unknown')

# Initialize feature extractor
extractor = URLFeatureExtractor()

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'model_loaded': True,
        'feature_extractor_loaded': True,
        'timestamp': pd.Timestamp.now().isoformat()
    })

@app.route('/model-info', methods=['GET'])
def model_info():
    return jsonify({
        'model_name': model_name,
        'best_score': best_score,
        'training_date': train_date,
        'timestamp': pd.Timestamp.now().isoformat()
    })

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json() or {}
    url  = data.get('url','').strip()
    if not url:
        return jsonify({'error': 'Missing or empty URL'}), 400

    # Extract exactly the same features as during training
    features_dict = extractor.extract_all_features(url)
    df_features  = pd.DataFrame([features_dict])

    try:
        # Preprocess with the saved scalers and selector
        X_std = scaler_std.transform(df_features)
        X_mm  = scaler_mm.transform(X_std)
        X_sel = selector.transform(X_mm)

        # Predict
        pred   = model.predict(X_sel)[0]
        proba  = model.predict_proba(X_sel)[0]
        conf   = float(proba.max())
        p_legit = float(proba[0])
        p_phish = float(proba[1])

        # Define risk levels
        if p_phish >= 0.8:
            risk = 'HIGH'
        elif p_phish >= 0.6:
            risk = 'MEDIUM'
        elif p_phish >= 0.4:
            risk = 'LOW'
        else:
            risk = 'VERY_LOW'

        return jsonify({
            'url': url,
            'prediction': int(pred),
            'prediction_label': 'Phishing' if pred == 1 else 'Legitimate',
            'confidence': conf,
            'probability_legitimate': p_legit,
            'probability_phishing': p_phish,
            'risk_level': risk,
            'timestamp': pd.Timestamp.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': f'Prediction failed: {str(e)}'}), 500
    
@app.route('/batch-predict', methods=['POST'])
def batch_predict():
    payload = request.get_json() or {}
    urls = payload.get('urls')
    if not isinstance(urls, list) or not urls:
        return jsonify({'error': 'Missing or invalid `urls` list'}), 400

    records = []
    for url in urls:
        url_str = str(url).strip()
        feats = extractor.extract_all_features(url_str)
        df = pd.DataFrame([feats])
        try:
            X_std = scaler_std.transform(df)
            X_mm  = scaler_mm.transform(X_std)
            X_sel = selector.transform(X_mm)
            pred = model.predict(X_sel)[0]
            proba = model.predict_proba(X_sel)[0]
            records.append({
                'url': url_str,
                'prediction': int(pred),
                'probability_legitimate': float(proba[0]),
                'probability_phishing': float(proba[1])
            })
        except Exception as e:
            records.append({
                'url': url_str,
                'error': f'Prediction failed: {str(e)}'
            })

    return jsonify({
        'count': len(records),
        'results': records
    }), 200



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
