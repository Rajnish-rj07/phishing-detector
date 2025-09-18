import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import joblib
import os
from datetime import datetime
import sqlite3

class OnlineLearningModel:
    def __init__(self, model_dir="models"):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        
        # Online learning model
        self.model = SGDClassifier(
            loss='log',  # logistic regression
            learning_rate='adaptive',
            eta0=0.01,
            random_state=42
        )
        
        self.scaler_std = StandardScaler()
        self.scaler_mm = MinMaxScaler()
        self.selector = SelectKBest(f_classif, k=20)
        
        self.is_fitted = False
        self.feature_names = []
        self.performance_history = []
        
    def initial_training(self, X, y, feature_names):
        """Initial training with historical data"""
        print("Performing initial model training...")
        
        self.feature_names = feature_names
        
        # Fit preprocessing pipeline
        X_std = self.scaler_std.fit_transform(X)
        X_mm = self.scaler_mm.fit_transform(X_std)
        X_selected = self.selector.fit_transform(X_mm, y)
        
        # Initial model training
        self.model.fit(X_selected, y)
        self.is_fitted = True
        
        # Save initial model
        self.save_model()
        
        print(f"Initial training completed with {len(X)} samples")
        print(f"Selected {X_selected.shape[1]} features")
    
    def incremental_update(self, X_new, y_new):
        """Update model with new data"""
        if not self.is_fitted:
            raise ValueError("Model must be initially trained first")
        
        if len(X_new) == 0:
            return
        
        try:
            # Preprocess new data
            X_std = self.scaler_std.transform(X_new)
            X_mm = self.scaler_mm.transform(X_std)
            X_selected = self.selector.transform(X_mm)
            
            # Incremental learning
            self.model.partial_fit(X_selected, y_new)
            
            # Evaluate performance
            y_pred = self.model.predict(X_selected)
            accuracy = accuracy_score(y_new, y_pred)
            
            self.performance_history.append({
                'timestamp': datetime.now(),
                'samples': len(y_new),
                'accuracy': accuracy
            })
            
            print(f"Updated model with {len(X_new)} new samples, accuracy: {accuracy:.3f}")
            
            # Save updated model
            self.save_model()
            
        except Exception as e:
            print(f"Error in incremental update: {e}")
    
    def predict_proba(self, X):
        """Predict probabilities"""
        if not self.is_fitted:
            return np.array([[0.5, 0.5]] * len(X))
        
        try:
            X_std = self.scaler_std.transform(X)
            X_mm = self.scaler_mm.transform(X_std)
            X_selected = self.selector.transform(X_mm)
            
            return self.model.predict_proba(X_selected)
        except Exception as e:
            print(f"Prediction error: {e}")
            return np.array([[0.5, 0.5]] * len(X))
    
    def predict(self, X):
        """Predict classes"""
        probas = self.predict_proba(X)
        return (probas[:, 1] > 0.5).astype(int)
    
    def save_model(self):
        """Save model and preprocessing components"""
        model_path = os.path.join(self.model_dir, "online_phishing_model.pkl")
        
        model_data = {
            'model': self.model,
            'scaler_std': self.scaler_std,
            'scaler_mm': self.scaler_mm,
            'selector': self.selector,
            'feature_names': self.feature_names,
            'is_fitted': self.is_fitted,
            'performance_history': self.performance_history,
            'last_updated': datetime.now()
        }
        
        joblib.dump(model_data, model_path)
        print(f"Model saved to {model_path}")
    
    def load_model(self):
        """Load saved model"""
        model_path = os.path.join(self.model_dir, "online_phishing_model.pkl")
        
        if os.path.exists(model_path):
            model_data = joblib.load(model_path)
            
            self.model = model_data['model']
            self.scaler_std = model_data['scaler_std']
            self.scaler_mm = model_data['scaler_mm']
            self.selector = model_data['selector']
            self.feature_names = model_data['feature_names']
            self.is_fitted = model_data['is_fitted']
            self.performance_history = model_data.get('performance_history', [])
            
            print(f"Model loaded from {model_path}")
            return True
        else:
            print(f"No saved model found at {model_path}")
            return False
