#!/usr/bin/env python3
import sys
import os
sys.path.append('..')

from src.data_collector import RealTimeDataCollector
from src.online_model import OnlineLearningModel
from src.feature_extractor import EnhancedURLFeatureExtractor
import pandas as pd

def update_model():
    """Automated model update script"""
    print("Starting automated model update...")
    
    # Initialize components
    collector = RealTimeDataCollector()
    model = OnlineLearningModel()
    extractor = EnhancedURLFeatureExtractor()
    
    # Load existing model
    model.load_model()
    
    # Collect latest data
    collector.update_threat_database()
    
    # Get recent data
    df = collector.get_recent_data(hours=6)  # Last 6 hours
    
    if len(df) > 5:
        print(f"Processing {len(df)} new samples...")
        
        X_new = []
        for url in df['url']:
            try:
                features = extractor.extract_all_features(url)
                X_new.append(features)
            except Exception as e:
                print(f"Error processing {url}: {e}")
        
        if X_new:
            X_new_df = pd.DataFrame(X_new).fillna(0)
            model.incremental_update(X_new_df.values, df['label'].values)
            print("Model update completed successfully")
        else:
            print("No valid features extracted")
    else:
        print("No new samples available")

if __name__ == "__main__":
    update_model()
