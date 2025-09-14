# Phase 1: Data Collection & Setup
# Create the project structure and data collection scripts

import os
import requests
import pandas as pd
import json
import time
from datetime import datetime
import csv

# Create project directory structure
project_dirs = [
    'phishing-detector',
    'phishing-detector/data',
    'phishing-detector/src',
    'phishing-detector/models', 
    'phishing-detector/api',
    'phishing-detector/extension',
    'phishing-detector/extension/css',
    'phishing-detector/extension/js',
    'phishing-detector/tests',
    'phishing-detector/docs'
]

for dir_path in project_dirs:
    os.makedirs(dir_path, exist_ok=True)
    print(f"Created directory: {dir_path}")

print("\n✅ Project structure created successfully!")