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
from sklearn.feature_extraction.text import TfidfVectorizer
from src.feature_extractor import EnhancedURLFeatureExtractor
from lime.lime_text import LimeTextExplainer
from sklearn.pipeline import Pipeline

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
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000) # Initialize TF-IDF
        self.selected_feature_names = []

        # LIME Explainer
        self.explainer = LimeTextExplainer(class_names=['legitimate', 'phishing'])
        self.feature_extractor = EnhancedURLFeatureExtractor() # Initialize feature extractor

    def _preprocess_features(self, X_combined):
        """Helper function to preprocess features (scaling and selection)."""
        # Ensure all columns are numeric before scaling
        X_combined = X_combined.apply(pd.to_numeric, errors='coerce').fillna(0)

        # Align columns with the features the model was trained on
        if self.is_fitted and self.feature_names:
            X_processed = pd.DataFrame(columns=self.feature_names)
            for col in self.feature_names:
                if col in X_combined.columns:
                    X_processed[col] = X_combined[col]
                else:
                    X_processed[col] = 0 # Fill missing features with 0
        else:
            X_processed = X_combined

        X_std = self.scaler_std.transform(X_processed)
        X_mm = self.scaler_mm.transform(X_std)
        X_selected = self.selector.transform(X_mm)
        return X_selected

    def initial_training(self, X, y, feature_names):
        """Initial training with historical data"""
        print("Performing initial model training...")
        
        # Extract text content and fit TF-IDF if 'url' column is present in X
        if 'url' in X.columns:
            print("Extracting text content for TF-IDF in initial training...")
            text_content = X['url'].apply(self.feature_extractor.extract_text_content)
            self.tfidf_vectorizer.fit(text_content.fillna(''))
            tfidf_features = self.tfidf_vectorizer.transform(text_content.fillna('')).toarray()
            tfidf_feature_names = [f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
            tfidf_df = pd.DataFrame(tfidf_features, columns=tfidf_feature_names, index=X.index)
            
            # Combine numerical and TF-IDF features
            X_numeric = X.select_dtypes(include=[np.number])
            X_combined = pd.concat([X_numeric, tfidf_df], axis=1)
            self.feature_names = X_combined.columns.tolist()
        else:
            X_combined = X
            self.feature_names = feature_names

        # Fit preprocessing pipeline
        X_std = self.scaler_std.fit_transform(X_combined)
        X_mm = self.scaler_mm.fit_transform(X_std)
        self.selector.fit(X_mm, y)
        
        # Preprocess features using the new helper
        X_selected = self._preprocess_features(X_combined)
        
        # Update selected feature names
        selected_feature_indices = self.selector.get_support(indices=True)
        self.selected_feature_names = [self.feature_names[i] for i in selected_feature_indices]
        
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
            # Extract text content and transform with TF-IDF if 'url' column is present in X_new
            if 'url' in X_new.columns:
                text_content_new = X_new['url'].apply(self.feature_extractor.extract_text_content)
                tfidf_features_new = self.tfidf_vectorizer.transform(text_content_new.fillna('')).toarray()
                tfidf_feature_names_new = [f'tfidf_{i}' for i in range(tfidf_features_new.shape[1])]
                tfidf_df_new = pd.DataFrame(tfidf_features_new, columns=tfidf_feature_names_new, index=X_new.index)
                
                # Combine numerical and TF-IDF features
                X_numeric_new = X_new.select_dtypes(include=[np.number])
                X_combined_new = pd.concat([X_numeric_new, tfidf_df_new], axis=1)
            else:
                X_combined_new = X_new

            # Preprocess new data using the new helper
            X_selected = self._preprocess_features(X_combined_new)
            
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
            # Extract text content and transform with TF-IDF if 'url' column is present in X
            if 'url' in X.columns:
                text_content = X['url'].apply(self.feature_extractor.extract_text_content)
                tfidf_features = self.tfidf_vectorizer.transform(text_content.fillna('')).toarray()
                tfidf_feature_names = [f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
                tfidf_df = pd.DataFrame(tfidf_features, columns=tfidf_feature_names, index=X.index)
                
                # Combine numerical and TF-IDF features
                X_numeric = X.select_dtypes(include=[np.number])
                X_combined = pd.concat([X_numeric, tfidf_df], axis=1)
            else:
                X_combined = X

            # Preprocess features using the new helper
            X_selected = self._preprocess_features(X_combined)
            
            return self.model.predict_proba(X_selected)
        except Exception as e:
            print(f"Prediction error: {e}")
            return np.array([[0.5, 0.5]] * len(X))

    def predict_proba_lime(self, raw_urls):
        """Predict probabilities for LIME explainer from raw URLs."""
        if not self.is_fitted:
            return np.array([[0.5, 0.5]] * len(raw_urls))

        try:
            # Create a DataFrame from raw URLs
            X_raw = pd.DataFrame({'url': raw_urls})

            # Extract text content and transform with TF-IDF
            text_content = X_raw['url'].apply(self.feature_extractor.extract_text_content)
            tfidf_features = self.tfidf_vectorizer.transform(text_content.fillna('')).toarray()
            tfidf_feature_names = [f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
            tfidf_df = pd.DataFrame(tfidf_features, columns=tfidf_feature_names, index=X_raw.index)

            # Extract numerical features
            numerical_features_list = []
            for url in raw_urls:
                numerical_features_list.append(self.feature_extractor.extract_all_features(url))
            numerical_df = pd.DataFrame(numerical_features_list, index=X_raw.index)
            numerical_df = numerical_df.select_dtypes(include=[np.number])

            # Combine numerical and TF-IDF features
            X_combined = pd.concat([numerical_df, tfidf_df], axis=1)

            # Preprocess features using the new helper
            X_selected = self._preprocess_features(X_combined)

            return self.model.predict_proba(X_selected)
        except Exception as e:
            print(f"LIME prediction error: {e}")
            return np.array([[0.5, 0.5]] * len(raw_urls))

    def explain_prediction(self, url, num_features=10):
        """Generates a LIME explanation for a given URL."""
        if not self.is_fitted:
            return {'error': 'Model not fitted, cannot generate explanation.'}

        try:
            explanation = self.explainer.explain_instance(
                url,
                self.predict_proba_lime,
                num_features=num_features,
                labels=(0, 1) # Assuming 0 for legitimate, 1 for phishing
            )
            
            # Format explanation for easier consumption
            explanation_list = explanation.as_list()
            formatted_explanation = []
            for feature, weight in explanation_list:
                formatted_explanation.append({'feature': feature, 'weight': weight})
            
            return formatted_explanation
        except Exception as e:
            print(f"Error generating LIME explanation: {e}")
            return {'error': f'Failed to generate explanation: {e}'}

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
            self.tfidf_vectorizer = model_data.get('tfidf_vectorizer', None)
            self.selected_feature_names = model_data.get('selected_feature_names', [])

            # Set the tfidf_vectorizer in the feature_extractor
            if self.tfidf_vectorizer:
                self.feature_extractor.tfidf_vectorizer = self.tfidf_vectorizer
                self.feature_extractor.tfidf_feature_names = self.tfidf_vectorizer.get_feature_names_out().tolist()
            
            print(f"Model loaded from {model_path}")
            return True
        else:
            print(f"No saved model found at {model_path}")
            return False
