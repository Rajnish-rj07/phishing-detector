# Create GitHub Actions workflow for CI/CD
github_workflow = '''name: Phishing Detector CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.8, 3.9, '3.10']

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Cache pip packages
      uses: actions/cache@v3
      with:
        path: ~/.cache/pip
        key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements.txt') }}
        restore-keys: |
          ${{ runner.os }}-pip-
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov flake8
    
    - name: Lint with flake8
      run: |
        # Stop the build if there are Python syntax errors or undefined names
        flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
        # Exit-zero treats all errors as warnings
        flake8 . --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
    
    - name: Run unit tests
      run: |
        pytest tests/ --cov=src --cov-report=xml --cov-report=html
    
    - name: Upload coverage reports
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella

  deploy-heroku:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Deploy to Heroku
      uses: akhileshns/heroku-deploy@v3.12.12
      with:
        heroku_api_key: ${{secrets.HEROKU_API_KEY}}
        heroku_app_name: "your-phishing-detector-api"
        heroku_email: "your-email@example.com"
        appdir: "api"
        
  build-extension:
    needs: test
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Chrome Extension
      run: |
        cd extension
        zip -r phishing-shield-extension.zip . -x "*.git*" "README.md" "*.DS_Store"
    
    - name: Upload Extension Artifact
      uses: actions/upload-artifact@v3
      with:
        name: chrome-extension
        path: extension/phishing-shield-extension.zip
'''

# Create GitHub directory and workflow file
os.makedirs('phishing-detector/.github/workflows', exist_ok=True)
with open('phishing-detector/.github/workflows/ci-cd.yml', 'w') as f:
    f.write(github_workflow)

# Create Dockerfile for containerized deployment
dockerfile = '''FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    gcc \\
    g++ \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ src/
COPY api/ api/
COPY models/ models/

# Set environment variables
ENV FLASK_APP=api/app.py
ENV FLASK_ENV=production
ENV PYTHONPATH=/app

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \\
    CMD curl -f http://localhost:5000/health || exit 1

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "60", "api.app:app"]
'''

with open('phishing-detector/Dockerfile', 'w') as f:
    f.write(dockerfile)

# Create docker-compose.yml for local development
docker_compose = '''version: '3.8'

services:
  phishing-detector-api:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=development
      - PYTHONPATH=/app
    volumes:
      - ./models:/app/models
      - ./src:/app/src
      - ./api:/app/api
    command: flask run --host=0.0.0.0 --port=5000
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - phishing-detector-api
    restart: unless-stopped

volumes:
  models:
'''

with open('phishing-detector/docker-compose.yml', 'w') as f:
    f.write(docker_compose)

print("✅ Created Docker configurations and GitHub Actions workflow")

# Create run_pipeline.py - Main execution script
run_pipeline = '''#!/usr/bin/env python3
"""
Phishing Detection System - Complete Pipeline Runner

This script runs the complete 7-phase phishing detection system pipeline:
1. Data Collection & Setup
2. Feature Engineering  
3. Model Development
4. API Development (starts server)
5. Browser Extension (provides instructions)
6. Integration & Testing
7. Deployment (provides instructions)
"""

import os
import sys
import subprocess
import time
import argparse
from pathlib import Path

def print_banner():
    """Print system banner"""
    print("=" * 70)
    print("🛡️  PHISHING DETECTION SYSTEM - COMPLETE PIPELINE")
    print("=" * 70)
    print()

def print_phase(phase_num, phase_name):
    """Print phase header"""
    print(f"\\n🚀 PHASE {phase_num}: {phase_name.upper()}")
    print("-" * 50)

def run_command(command, cwd=None, description=""):
    """Run a system command and handle errors"""
    if description:
        print(f"  ⚡ {description}")
    
    try:
        result = subprocess.run(
            command, 
            cwd=cwd, 
            shell=True, 
            check=True,
            capture_output=True,
            text=True
        )
        print(f"  ✅ Success: {description}")
        return result
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Error: {description}")
        print(f"     Command: {command}")
        print(f"     Error: {e.stderr}")
        return None

def check_dependencies():
    """Check if required dependencies are installed"""
    print("🔍 Checking dependencies...")
    
    # Check Python
    try:
        import sys
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print("❌ Python 3.8+ required")
            return False
        print(f"✅ Python {version.major}.{version.minor}")
    except:
        print("❌ Python not found")
        return False
    
    # Check pip packages
    required_packages = [
        'pandas', 'numpy', 'scikit-learn', 'flask', 
        'requests', 'tldextract', 'beautifulsoup4'
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} (missing)")
    
    if missing_packages:
        print(f"\\n📦 Installing missing packages: {', '.join(missing_packages)}")
        install_cmd = f"pip install {' '.join(missing_packages)}"
        result = run_command(install_cmd, description="Installing packages")
        if not result:
            return False
    
    print("✅ All dependencies satisfied\\n")
    return True

def phase1_data_collection():
    """Phase 1: Data Collection & Setup"""
    print_phase(1, "Data Collection & Setup")
    
    # Create data directory
    os.makedirs("data", exist_ok=True)
    
    # Run data collection
    result = run_command(
        "python src/data_collector.py",
        description="Collecting phishing and legitimate URLs"
    )
    
    if result:
        print("  📊 Dataset created: data/phishing_dataset.csv")
        return True
    return False

def phase2_feature_engineering():
    """Phase 2: Feature Engineering"""
    print_phase(2, "Feature Engineering")
    
    result = run_command(
        "python src/feature_extractor.py",
        description="Extracting URL features"
    )
    
    if result:
        print("  🔧 Features extracted: data/features_dataset.csv")
        return True
    return False

def phase3_model_development():
    """Phase 3: Model Development"""
    print_phase(3, "Model Development")
    
    # Create models directory
    os.makedirs("models", exist_ok=True)
    
    result = run_command(
        "python src/model_trainer.py",
        description="Training machine learning models"
    )
    
    if result:
        print("  🤖 Model trained: models/phishing_model.pkl")
        return True
    return False

def phase4_api_development():
    """Phase 4: API Development"""
    print_phase(4, "API Development")
    
    print("  🌐 Flask API ready to start")
    print("  📍 Location: api/app.py")
    print("  🚀 To start API: cd api && python app.py")
    print("  🔗 API will be available at: http://localhost:5000")
    
    # Ask user if they want to start the API now
    response = input("\\n  ❓ Start API server now? (y/n): ").lower().strip()
    
    if response == 'y':
        print("  🚀 Starting Flask API server...")
        print("  ⚠️  Press Ctrl+C to stop the server")
        try:
            subprocess.run("python app.py", cwd="api", shell=True)
        except KeyboardInterrupt:
            print("\\n  🛑 API server stopped")
    
    return True

def phase5_browser_extension():
    """Phase 5: Browser Extension Development"""
    print_phase(5, "Browser Extension Development")
    
    print("  🔧 Chrome Extension ready for installation")
    print("  📁 Location: extension/")
    print()
    print("  📋 Installation Instructions:")
    print("     1. Open Chrome and go to chrome://extensions/")
    print("     2. Enable 'Developer mode' in the top right")
    print("     3. Click 'Load unpacked' and select the 'extension' folder")
    print("     4. The extension should appear in your toolbar")
    print()
    print("  ⚙️  Make sure the API is running before using the extension!")
    
    return True

def phase6_integration_testing():
    """Phase 6: Integration & Testing"""
    print_phase(6, "Integration & Testing")
    
    print("  🧪 Running integration tests...")
    result = run_command(
        "python tests/integration_tests.py",
        description="Running system integration tests"
    )
    
    if result:
        print("  ✅ All tests passed!")
        return True
    else:
        print("  ⚠️  Some tests failed. Check API is running.")
        return False

def phase7_deployment():
    """Phase 7: Deployment"""
    print_phase(7, "Deployment")
    
    print("  🚀 Deployment Options:")
    print()
    print("  🐳 Docker Deployment:")
    print("     docker build -t phishing-detector .")
    print("     docker run -p 5000:5000 phishing-detector")
    print()
    print("  ☁️  Heroku Deployment:")
    print("     cd api")
    print("     heroku create your-app-name")
    print("     git push heroku main")
    print()
    print("  🌐 Chrome Web Store:")
    print("     1. Zip the extension folder")
    print("     2. Upload to Chrome Web Store Developer Dashboard")
    print()
    print("  📚 See README.md for detailed deployment instructions")
    
    return True

def main():
    """Main pipeline execution"""
    parser = argparse.ArgumentParser(description='Phishing Detection System Pipeline')
    parser.add_argument('--skip-deps', action='store_true', help='Skip dependency check')
    parser.add_argument('--phase', type=int, choices=range(1,8), help='Run specific phase only')
    parser.add_argument('--skip-api', action='store_true', help='Skip API server start')
    args = parser.parse_args()
    
    print_banner()
    
    # Check dependencies
    if not args.skip_deps:
        if not check_dependencies():
            print("❌ Dependency check failed. Install required packages first.")
            sys.exit(1)
    
    # Change to project directory
    os.chdir(Path(__file__).parent)
    
    # Track success of each phase
    phases = []
    
    # Run specific phase or all phases
    if args.phase:
        phase_functions = [
            None,  # Index 0 (unused)
            phase1_data_collection,
            phase2_feature_engineering, 
            phase3_model_development,
            phase4_api_development,
            phase5_browser_extension,
            phase6_integration_testing,
            phase7_deployment
        ]
        
        success = phase_functions[args.phase]()
        phases.append((args.phase, success))
    else:
        # Run all phases
        phases.append((1, phase1_data_collection()))
        phases.append((2, phase2_feature_engineering()))
        phases.append((3, phase3_model_development()))
        
        if not args.skip_api:
            phases.append((4, phase4_api_development()))
        else:
            print_phase(4, "API Development (Skipped)")
            phases.append((4, True))
        
        phases.append((5, phase5_browser_extension()))
        phases.append((6, phase6_integration_testing()))
        phases.append((7, phase7_deployment()))
    
    # Print final summary
    print("\\n" + "=" * 70)
    print("📊 PIPELINE EXECUTION SUMMARY")
    print("=" * 70)
    
    for phase_num, success in phases:
        phase_names = {
            1: "Data Collection & Setup",
            2: "Feature Engineering", 
            3: "Model Development",
            4: "API Development",
            5: "Browser Extension",
            6: "Integration & Testing",
            7: "Deployment"
        }
        
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"Phase {phase_num}: {phase_names[phase_num]:<25} {status}")
    
    successful_phases = sum(1 for _, success in phases if success)
    total_phases = len(phases)
    
    print(f"\\n🎯 Overall Success Rate: {successful_phases}/{total_phases} phases completed")
    
    if successful_phases == total_phases:
        print("🎉 All phases completed successfully!")
        print("\\n🛡️ Your phishing detection system is ready to use!")
        print("\\n📖 Next steps:")
        print("   1. Start the API: cd api && python app.py")
        print("   2. Install the Chrome extension from the extension/ folder")
        print("   3. Test the system with various URLs")
        print("   4. Deploy to production following the deployment guide")
    else:
        print("⚠️ Some phases failed. Check the error messages above.")
        print("💡 You can run specific phases with --phase <number>")
    
    print("\\n📚 For detailed documentation, see README.md")
    print("🐛 For issues and support: https://github.com/yourusername/phishing-detector/issues")

if __name__ == "__main__":
    main()
'''

with open('phishing-detector/run_pipeline.py', 'w') as f:
    f.write(run_pipeline)

# Make it executable
os.chmod('phishing-detector/run_pipeline.py', 0o755)

print("✅ Created complete pipeline runner script")
print("📄 File: phishing-detector/run_pipeline.py")