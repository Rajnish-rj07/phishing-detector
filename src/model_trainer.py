import os
import pickle
import joblib
import pandas as pd
import numpy as np
from datetime import datetime

from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score
from sklearn.feature_extraction.text import TfidfVectorizer
from src.feature_extractor import EnhancedURLFeatureExtractor
import warnings
warnings.filterwarnings('ignore')

# Optional XGBoost
try:
    from xgboost import XGBClassifier
    USE_XGB = True
except ImportError:
    USE_XGB = False

class PhishingModelTrainer:
    def __init__(self):
        self.models = {
            'RandomForest': RandomForestClassifier(random_state=42),
            'SVM': SVC(probability=True, random_state=42)
        }
        if USE_XGB:
            self.models['XGBoost'] = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
        self.best_model = None
        self.best_name = None
        self.best_score = 0.0
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english') # Initialize TF-IDF
        self.feature_extractor = EnhancedURLFeatureExtractor() # Initialize feature extractor

    def load_data(self, path='data/features_dataset.csv'):
        df = pd.read_csv(path)
        # Assuming 'url' column exists for text extraction
        if 'url' in df.columns:
            # Extract text content for TF-IDF
            print("Extracting text content for TF-IDF...")
            df['text_content'] = df['url'].apply(self.feature_extractor.extract_text_content)
            # Fit TF-IDF vectorizer on the text content
            self.tfidf_vectorizer.fit(df['text_content'].fillna(''))
            # Transform text content into TF-IDF features
            tfidf_features = self.tfidf_vectorizer.transform(df['text_content'].fillna('')).toarray()
            tfidf_feature_names = [f'tfidf_{i}' for i in range(tfidf_features.shape[1])]
            tfidf_df = pd.DataFrame(tfidf_features, columns=tfidf_feature_names, index=df.index)
            # Concatenate TF-IDF features with existing numerical features
            X = df.select_dtypes(include=[np.number]).drop(columns=['label'], errors='ignore')
            X = pd.concat([X, tfidf_df], axis=1)
        else:
            X = df.select_dtypes(include=[np.number]).drop(columns=['label'], errors='ignore')

        y = df['label']
        print(f"Loaded {len(df)} samples with {X.shape[1]} features (including TF-IDF if applicable)")
        return X, y

    def preprocess(self, X_train, X_test, k=20):
        # Ensure all columns are numeric before scaling
        X_train = X_train.apply(pd.to_numeric, errors='coerce').fillna(0)
        X_test = X_test.apply(pd.to_numeric, errors='coerce').fillna(0)

        # 1. Standard scaling
        std = StandardScaler()
        X_train_std = std.fit_transform(X_train)
        X_test_std = std.transform(X_test)
        # 2. MinMax scaling to [0,1]
        mm = MinMaxScaler(feature_range=(0,1))
        X_train_mm = mm.fit_transform(X_train_std)
        X_test_mm = mm.transform(X_test_std)
        # 3. Feature selection
        selector = SelectKBest(f_classif, k=min(k, X_train_mm.shape[1]))
        X_train_sel = selector.fit_transform(X_train_mm, y_train)
        X_test_sel = selector.transform(X_test_mm)
        
        # Get selected feature names
        selected_feature_indices = selector.get_support(indices=True)
        original_feature_names = X_train.columns.tolist()
        selected_feature_names = [original_feature_names[i] for i in selected_feature_indices]

        print(f"Selected top {X_train_sel.shape[1]} features")
        return X_train_sel, X_test_sel, std, mm, selector, selected_feature_names

    def train(self, X_tr, y_tr):
        trained = {}
        for name, model in self.models.items():
            model.fit(X_tr, y_tr)
            trained[name] = model
        return trained

    def evaluate(self, model, X_te, y_te):
        pred = model.predict(X_te)
        return accuracy_score(y_te, pred)

    def tune_rf(self, X_tr, y_tr):
        params = {
            'n_estimators':[100,200],
            'max_depth':[None,10],
            'min_samples_split':[2,5]
        }
        grid = GridSearchCV(RandomForestClassifier(random_state=42),
                            params, cv=3, scoring='accuracy', n_jobs=-1)
        grid.fit(X_tr, y_tr)
        print("RF tuned params:", grid.best_params_)
        return grid.best_estimator_, grid.best_score_

    def save_pipeline(self, model, std, mm, selector, tfidf_vectorizer, selected_feature_names,
                      path='models/phishing_pipeline.pkl'):
        os.makedirs('models', exist_ok=True)
        pkg = {
            'model': model,
            'scaler_std': std,
            'scaler_mm': mm,
            'selector': selector,
            'tfidf_vectorizer': tfidf_vectorizer, # Save TF-IDF vectorizer
            'selected_feature_names': selected_feature_names, # Save selected feature names
            'model_name': self.best_name,
            'accuracy': self.best_score,
            'timestamp': datetime.now().isoformat()
        }
        with open(path, 'wb') as f:
            pickle.dump(pkg, f)
        joblib.dump(pkg, path.replace('.pkl','_joblib.pkl'))
        print("Saved pipeline to", path)

    def run(self):
        X, y = self.load_data()
        global y_train  # needed for SelectKBest
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        X_tr, X_te, std, mm, selector, selected_feature_names = self.preprocess(X_train, X_test)

        # Train base models
        trained = self.train(X_tr, y_train)
        for name, model in trained.items():
            score = self.evaluate(model, X_te, y_test)
            print(f"{name} accuracy: {score:.4f}")
            if score > self.best_score:
                self.best_score = score
                self.best_model = model
                self.best_name = name

        # Hyperparameter tune RandomForest
        rf_tuned, rf_score = self.tune_rf(X_tr, y_train)
        print(f"RF tuned accuracy: {rf_score:.4f}")
        if rf_score > self.best_score:
            self.best_score = rf_score
            self.best_model = rf_tuned
            self.best_name = 'RandomForest_Tuned'

        print(f"\nBest model: {self.best_name} (accuracy: {self.best_score:.4f})")
        self.save_pipeline(self.best_model, std, mm, selector, self.tfidf_vectorizer, selected_feature_names)

if __name__ == "__main__":
    trainer = PhishingModelTrainer()
    trainer.run()
