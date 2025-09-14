#!/usr/bin/env python3
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
    print(f"\n🚀 PHASE {phase_num}: {phase_name.upper()}")
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
        print(f"\n📦 Installing missing packages: {', '.join(missing_packages)}")
        install_cmd = f"pip install {' '.join(missing_packages)}"
        result = run_command(install_cmd, description="Installing packages")
        if not result:
            return False

    print("✅ All dependencies satisfied\n")
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
    response = input("\n  ❓ Start API server now? (y/n): ").lower().strip()

    if response == 'y':
        print("  🚀 Starting Flask API server...")
        print("  ⚠️  Press Ctrl+C to stop the server")
        try:
            subprocess.run("python app.py", cwd="api", shell=True)
        except KeyboardInterrupt:
            print("\n  🛑 API server stopped")

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
    print("\n" + "=" * 70)
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

    print(f"\n🎯 Overall Success Rate: {successful_phases}/{total_phases} phases completed")

    if successful_phases == total_phases:
        print("🎉 All phases completed successfully!")
        print("\n🛡️ Your phishing detection system is ready to use!")
        print("\n📖 Next steps:")
        print("   1. Start the API: cd api && python app.py")
        print("   2. Install the Chrome extension from the extension/ folder")
        print("   3. Test the system with various URLs")
        print("   4. Deploy to production following the deployment guide")
    else:
        print("⚠️ Some phases failed. Check the error messages above.")
        print("💡 You can run specific phases with --phase <number>")

    print("\n📚 For detailed documentation, see README.md")
    print("🐛 For issues and support: https://github.com/yourusername/phishing-detector/issues")

if __name__ == "__main__":
    main()
