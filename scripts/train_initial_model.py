import os
import sys
import pandas as pd

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from src.feature_extractor import EnhancedURLFeatureExtractor
from src.online_mode import OnlineLearningModel

def train_initial_model():
    """Train the initial model using the dataset."""
    try:
        # Load the dataset
        dataset_path = os.path.join(project_root, 'data', 'phishing_dataset.csv')
        if not os.path.exists(dataset_path):
            print(f"Dataset not found at {dataset_path}")
            return False

        # Read the dataset
        df = pd.read_csv(dataset_path)
        print(f"Loaded dataset with {len(df)} samples")

        # Initialize feature extractor and model
        extractor = EnhancedURLFeatureExtractor()
        model = OnlineLearningModel(model_dir=os.path.join(project_root, 'models'))

        # Extract features for each URL
        print("Extracting features...")
        features_list = []
        for url in df['url']:
            features = extractor.extract_all_features(url)
            features_list.append(features)

        # Create features DataFrame
        X = pd.DataFrame(features_list)
        X['url'] = df['url']  # Add URL column for text features
        y = df['label']

        # Train the model
        print("Training model...")
        model.initial_training(X, y, X.columns.tolist())
        print("Model training completed")

        return True

    except Exception as e:
        print(f"Error training model: {e}")
        return False

if __name__ == '__main__':
    if train_initial_model():
        print("Initial model training successful")
    else:
        print("Failed to train initial model")