import os
import sys
import joblib

# Add project root to Python path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

def inspect_model():
    """Inspect the contents of the model file."""
    try:
        model_path = os.path.join(project_root, 'models', 'phishing_pipeline.pkl')
        if not os.path.exists(model_path):
            print(f"Model file not found at {model_path}")
            return

        # Load the model
        model_data = joblib.load(model_path)
        print("Model type:", type(model_data))
        print("\nModel contents:")
        if isinstance(model_data, dict):
            for key, value in model_data.items():
                print(f"\n{key}:")
                print(f"  Type: {type(value)}")
                if hasattr(value, 'get_params'):
                    print("  Parameters:", value.get_params())
    except Exception as e:
        print(f"Error inspecting model: {e}")

if __name__ == '__main__':
    inspect_model()