# Phase 3: Model Development

model_development_code = '''
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
import pickle
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class PhishingModelTrainer:
    def __init__(self):
        self.models = {
            'Random Forest': RandomForestClassifier(random_state=42),
            'SVM': SVC(random_state=42, probability=True),
            'Logistic Regression': LogisticRegression(random_state=42, max_iter=1000),
            'Decision Tree': DecisionTreeClassifier(random_state=42),
            'Naive Bayes': GaussianNB()
        }
        
        self.best_model = None
        self.best_score = 0
        self.scaler = StandardScaler()
        self.feature_selector = None
        
    def load_data(self, features_file):
        """Load the processed features dataset"""
        print(f"Loading features from {features_file}")
        df = pd.read_csv(features_file)
        
        # Separate features and target
        X = df.drop(['url', 'label'], axis=1)
        y = df['label']
        
        print(f"Dataset shape: {X.shape}")
        print(f"Features: {list(X.columns)}")
        print(f"Class distribution: {y.value_counts().to_dict()}")
        
        return X, y
    
    def preprocess_data(self, X_train, X_test, use_feature_selection=True, k_features=20):
        """Preprocess the data with scaling and feature selection"""
        print("Preprocessing data...")
        
        # Handle missing values
        X_train = X_train.fillna(0)
        X_test = X_test.fillna(0)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Feature selection
        if use_feature_selection and X_train_scaled.shape[1] > k_features:
            print(f"Selecting top {k_features} features...")
            self.feature_selector = SelectKBest(chi2, k=k_features)
            X_train_scaled = self.feature_selector.fit_transform(X_train_scaled, y_train)
            X_test_scaled = self.feature_selector.transform(X_test_scaled)
            
            # Get selected feature names
            selected_features = X_train.columns[self.feature_selector.get_support()].tolist()
            print(f"Selected features: {selected_features}")
        
        return X_train_scaled, X_test_scaled
    
    def train_models(self, X_train, X_test, y_train, y_test):
        """Train multiple models and compare performance"""
        print("Training multiple models...")
        
        results = {}
        
        for name, model in self.models.items():
            print(f"\\nTraining {name}...")
            
            # Train model
            model.fit(X_train, y_train)
            
            # Make predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            try:
                auc = roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else 0
            except:
                auc = 0
            
            # Store results
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'auc_score': auc,
                'predictions': y_pred
            }
            
            # Update best model
            if accuracy > self.best_score:
                self.best_score = accuracy
                self.best_model = model
                self.best_model_name = name
            
            print(f"{name} - Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
        
        return results
    
    def hyperparameter_tuning(self, X_train, y_train):
        """Perform hyperparameter tuning for the best models"""
        print("\\nPerforming hyperparameter tuning...")
        
        # Random Forest hyperparameter tuning
        rf_params = {
            'n_estimators': [50, 100, 200],
            'max_depth': [5, 10, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        rf_grid = GridSearchCV(
            RandomForestClassifier(random_state=42),
            rf_params,
            cv=5,
            scoring='f1',
            n_jobs=-1,
            verbose=1
        )
        
        rf_grid.fit(X_train, y_train)
        
        print(f"Best RF parameters: {rf_grid.best_params_}")
        print(f"Best RF score: {rf_grid.best_score_:.4f}")
        
        # Update best model if tuned version is better
        tuned_score = rf_grid.best_score_
        if tuned_score > self.best_score:
            self.best_model = rf_grid.best_estimator_
            self.best_score = tuned_score
            self.best_model_name = 'Random Forest (Tuned)'
        
        return rf_grid.best_estimator_
    
    def evaluate_model(self, model, X_test, y_test, model_name="Model"):
        """Detailed model evaluation"""
        print(f"\\n📊 Detailed evaluation for {model_name}")
        
        y_pred = model.predict(X_test)
        
        # Classification report
        print("Classification Report:")
        print(classification_report(y_test, y_pred))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("Confusion Matrix:")
        print(cm)
        
        return y_pred
    
    def save_model(self, model, model_path='models/phishing_model.pkl'):
        """Save the trained model and preprocessors"""
        print(f"\\n💾 Saving model to {model_path}")
        
        model_package = {
            'model': model,
            'scaler': self.scaler,
            'feature_selector': self.feature_selector,
            'model_name': self.best_model_name,
            'training_date': datetime.now().isoformat(),
            'best_score': self.best_score
        }
        
        with open(model_path, 'wb') as f:
            pickle.dump(model_package, f)
        
        print(f"✅ Model saved successfully!")
        
        # Also save with joblib for better performance
        joblib.dump(model_package, model_path.replace('.pkl', '_joblib.pkl'))
        
        return model_path
    
    def load_model(self, model_path):
        """Load a saved model"""
        with open(model_path, 'rb') as f:
            model_package = pickle.load(f)
        
        self.best_model = model_package['model']
        self.scaler = model_package['scaler']
        self.feature_selector = model_package.get('feature_selector')
        self.best_model_name = model_package.get('model_name', 'Unknown')
        
        return model_package
    
    def predict_url(self, url, feature_extractor):
        """Predict if a single URL is phishing"""
        if self.best_model is None:
            raise ValueError("No model trained yet!")
        
        # Extract features
        features = feature_extractor.extract_all_features(url)
        features_df = pd.DataFrame([features])
        
        # Fill missing values
        features_df = features_df.fillna(0)
        
        # Scale features
        features_scaled = self.scaler.transform(features_df)
        
        # Apply feature selection if used
        if self.feature_selector:
            features_scaled = self.feature_selector.transform(features_scaled)
        
        # Make prediction
        prediction = self.best_model.predict(features_scaled)[0]
        confidence = self.best_model.predict_proba(features_scaled)[0].max()
        
        return {
            'url': url,
            'prediction': int(prediction),
            'prediction_label': 'Phishing' if prediction == 1 else 'Legitimate',
            'confidence': float(confidence)
        }
    
    def train_complete_pipeline(self, features_file):
        """Complete training pipeline"""
        print("🚀 Starting complete model training pipeline...")
        
        # Load data
        X, y = self.load_data(features_file)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"Training set size: {X_train.shape}")
        print(f"Test set size: {X_test.shape}")
        
        # Preprocess data
        X_train_processed, X_test_processed = self.preprocess_data(X_train, X_test)
        
        # Train models
        results = self.train_models(X_train_processed, X_test_processed, y_train, y_test)
        
        # Hyperparameter tuning for best model
        tuned_model = self.hyperparameter_tuning(X_train_processed, y_train)
        
        # Final evaluation
        print(f"\\n🏆 Best Model: {self.best_model_name}")
        print(f"🎯 Best Score: {self.best_score:.4f}")
        
        self.evaluate_model(self.best_model, X_test_processed, y_test, self.best_model_name)
        
        # Save model
        model_path = self.save_model(self.best_model)
        
        return self.best_model, results, model_path

# Store global variables for later use
global y_train
y_train = None

if __name__ == "__main__":
    trainer = PhishingModelTrainer()
    
    # Train the complete pipeline
    best_model, results, model_path = trainer.train_complete_pipeline('data/features_dataset.csv')
    
    print("\\n✅ Model training completed!")
    print(f"📁 Model saved at: {model_path}")
'''

# Save the model development script
with open('phishing-detector/src/model_trainer.py', 'w') as f:
    f.write(model_development_code)

print("✅ Phase 3: Model development script created!")
print("📄 File: phishing-detector/src/model_trainer.py")