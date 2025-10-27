import sys
import os

# Add the project root directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the Flask app
from api.app import app

# This allows Gunicorn to find the app
if __name__ == "__main__":
    app.run()