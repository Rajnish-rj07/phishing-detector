import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.data_collector import PhishingDataCollector
from src.feature_extractor import URLFeatureExtractor
import unittest
import sys
import os
import requests
import json
import time
from datetime import datetime

# Add src directory to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from data_collector import PhishingDataCollector
    from feature_extractor import URLFeatureExtractor
    from model_trainer import PhishingModelTrainer
except ImportError as e:
    print(f"Warning: Could not import modules: {e}")

class TestPhishingDetectionSystem(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures"""
        self.test_urls = {
            'legitimate': [
                'https://www.google.com',
                'https://www.github.com',
                'https://www.stackoverflow.com',
                'https://www.wikipedia.org',
                'https://www.microsoft.com'
            ],
            'suspicious': [
                'http://secure-bank-login.suspicious-domain.com/login.php',
                'https://paypal-verification.fake-site.net/verify.html',
                'http://amazon-security.malicious.org/update-payment.php',
                'https://microsoft-account.phishing.site/signin.aspx',
                'http://apple-id-verification.scam.info/authenticate.html'
            ]
        }

        self.api_url = 'http://localhost:5000'
        self.feature_extractor = URLFeatureExtractor()

    def test_feature_extraction(self):
        """Test URL feature extraction"""
        print("\n🧪 Testing feature extraction...")

        for url in self.test_urls['legitimate'][:2]:
            features = self.feature_extractor.extract_all_features(url)

            # Check that features are extracted
            self.assertIsInstance(features, dict)
            self.assertGreater(len(features), 0)

            # Check required features exist
            required_features = ['url_length', 'num_dots', 'domain_length', 'is_https']
            for feature in required_features:
                self.assertIn(feature, features)

            print(f"✅ Features extracted for {url}: {len(features)} features")

    def test_api_health(self):
        """Test API health endpoint"""
        print("\n🧪 Testing API health...")

        try:
            response = requests.get(f'{self.api_url}/health', timeout=5)
            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertIn('status', data)
            self.assertEqual(data['status'], 'healthy')

            print("✅ API health check passed")

        except requests.exceptions.RequestException as e:
            print(f"❌ API health check failed: {e}")
            self.skipTest(f"API not available: {e}")

    def test_api_prediction(self):
        """Test API prediction endpoint"""
        print("\n🧪 Testing API predictions...")

        try:
            for url_type, urls in self.test_urls.items():
                for url in urls[:2]:  # Test first 2 URLs of each type

                    payload = {'url': url}
                    response = requests.post(
                        f'{self.api_url}/predict',
                        json=payload,
                        timeout=10
                    )

                    self.assertEqual(response.status_code, 200)

                    data = response.json()
                    required_fields = [
                        'url', 'prediction', 'prediction_label',
                        'confidence', 'probability_phishing'
                    ]

                    for field in required_fields:
                        self.assertIn(field, data)

                    # Check data types
                    self.assertIsInstance(data['prediction'], int)
                    self.assertIn(data['prediction'], [0, 1])
                    self.assertIsInstance(data['confidence'], float)
                    self.assertIsInstance(data['probability_phishing'], float)

                    print(f"✅ API prediction for {url}: {data['prediction_label']} "
                          f"({data['confidence']:.2f} confidence)")

                    time.sleep(0.5)  # Rate limiting

        except requests.exceptions.RequestException as e:
            print(f"❌ API prediction test failed: {e}")
            self.skipTest(f"API not available: {e}")

    def test_batch_prediction(self):
        """Test batch prediction endpoint"""
        print("\n🧪 Testing batch predictions...")

        try:
            test_urls = self.test_urls['legitimate'][:3]
            payload = {'urls': test_urls}

            response = requests.post(
                f'{self.api_url}/batch-predict',
                json=payload,
                timeout=15
            )

            self.assertEqual(response.status_code, 200)

            data = response.json()
            self.assertIn('results', data)
            self.assertIn('count', data)
            self.assertEqual(data['count'], len(test_urls))
            self.assertEqual(len(data['results']), len(test_urls))

            print(f"✅ Batch prediction successful: {data['count']} URLs processed")

        except requests.exceptions.RequestException as e:
            print(f"❌ Batch prediction test failed: {e}")
            self.skipTest(f"API not available: {e}")

    def test_model_accuracy(self):
        """Test model accuracy on known examples"""
        print("\n🧪 Testing model accuracy...")

        try:
            correct_predictions = 0
            total_predictions = 0

            # Test legitimate URLs (should predict 0)
            for url in self.test_urls['legitimate']:
                payload = {'url': url}
                response = requests.post(f'{self.api_url}/predict', json=payload, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    if 'error' not in data:
                        prediction = data['prediction']
                        if prediction == 0:  # Should be legitimate
                            correct_predictions += 1
                        total_predictions += 1
                        print(f"  {url}: {data['prediction_label']} "
                              f"(Expected: Legitimate)")

                time.sleep(0.5)

            # Test suspicious URLs (should predict 1)
            for url in self.test_urls['suspicious']:
                payload = {'url': url}
                response = requests.post(f'{self.api_url}/predict', json=payload, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    if 'error' not in data:
                        prediction = data['prediction']
                        if prediction == 1:  # Should be phishing
                            correct_predictions += 1
                        total_predictions += 1
                        print(f"  {url}: {data['prediction_label']} "
                              f"(Expected: Phishing)")

                time.sleep(0.5)

            if total_predictions > 0:
                accuracy = correct_predictions / total_predictions
                print(f"\n📊 Test Accuracy: {accuracy:.2%} "
                      f"({correct_predictions}/{total_predictions})")

                # We expect at least 70% accuracy on these obvious examples
                self.assertGreaterEqual(accuracy, 0.7, 
                    f"Model accuracy {accuracy:.2%} is below expected 70%")

        except requests.exceptions.RequestException as e:
            print(f"❌ Model accuracy test failed: {e}")
            self.skipTest(f"API not available: {e}")

    def test_error_handling(self):
        """Test API error handling"""
        print("\n🧪 Testing error handling...")

        try:
            # Test empty URL
            response = requests.post(f'{self.api_url}/predict', json={}, timeout=5)
            self.assertEqual(response.status_code, 400)

            # Test invalid URL format
            invalid_payload = {'url': 'not-a-valid-url'}
            response = requests.post(f'{self.api_url}/predict', json=invalid_payload, timeout=5)
            # Should still return 200 but with error handling
            self.assertIn(response.status_code, [200, 400, 500])

            print("✅ Error handling tests passed")

        except requests.exceptions.RequestException as e:
            print(f"❌ Error handling test failed: {e}")
            self.skipTest(f"API not available: {e}")

    def test_performance(self):
        """Test API response performance"""
        print("\n🧪 Testing performance...")

        try:
            test_url = self.test_urls['legitimate'][0]
            payload = {'url': test_url}

            # Test response time
            start_time = time.time()
            response = requests.post(f'{self.api_url}/predict', json=payload, timeout=10)
            end_time = time.time()

            response_time = end_time - start_time

            self.assertEqual(response.status_code, 200)
            self.assertLess(response_time, 5.0, "API response too slow (>5 seconds)")

            print(f"✅ API response time: {response_time:.2f} seconds")

        except requests.exceptions.RequestException as e:
            print(f"❌ Performance test failed: {e}")
            self.skipTest(f"API not available: {e}")

class TestDataPipeline(unittest.TestCase):

    def test_data_collection(self):
        """Test data collection process"""
        print("\n🧪 Testing data collection...")

        try:
            collector = PhishingDataCollector()

            # Test phishing data collection
            phishing_data = collector.collect_phishtank_data(10)
            self.assertIsInstance(phishing_data, list)
            self.assertGreater(len(phishing_data), 0)

            # Test legitimate data collection
            legitimate_data = collector.collect_legitimate_data(10)
            self.assertIsInstance(legitimate_data, list)
            self.assertGreater(len(legitimate_data), 0)

            print(f"✅ Data collection: {len(phishing_data)} phishing, "
                  f"{len(legitimate_data)} legitimate URLs")

        except Exception as e:
            print(f"❌ Data collection test failed: {e}")
            self.fail(f"Data collection failed: {e}")

def run_integration_tests():
    """Run all integration tests"""
    print("🚀 Starting Phishing Detection System Integration Tests")
    print("=" * 60)

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTest(loader.loadTestsFromTestCase(TestDataPipeline))
    suite.addTest(loader.loadTestsFromTestCase(TestPhishingDetectionSystem))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("=" * 60)
    if result.wasSuccessful():
        print("🎉 All integration tests passed!")
    else:
        print(f"❌ {len(result.failures)} tests failed, {len(result.errors)} errors")
        for test, error in result.failures + result.errors:
            print(f"   - {test}: {error.split('AssertionError:')[-1].strip()}")

    return result.wasSuccessful()

if __name__ == '__main__':
    run_integration_tests()
