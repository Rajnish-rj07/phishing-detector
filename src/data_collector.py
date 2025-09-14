
import requests
import pandas as pd
import json
import time
import csv
from datetime import datetime
import random

class PhishingDataCollector:
    def __init__(self):
        self.phishtank_url = "http://data.phishtank.com/data/online-valid.json"
        self.legitimate_urls = [
            "https://www.google.com", "https://www.youtube.com", "https://www.facebook.com",
            "https://www.amazon.com", "https://www.wikipedia.org", "https://www.twitter.com",
            "https://www.instagram.com", "https://www.linkedin.com", "https://www.netflix.com",
            "https://www.apple.com", "https://www.microsoft.com", "https://www.github.com",
            "https://www.stackoverflow.com", "https://www.reddit.com", "https://www.ebay.com",
            "https://www.paypal.com", "https://www.dropbox.com", "https://www.spotify.com",
            "https://www.adobe.com", "https://www.salesforce.com", "https://www.oracle.com",
            "https://www.ibm.com", "https://www.cisco.com", "https://www.intel.com"
        ]

    def collect_phishtank_data(self, max_records=1000):
        """Collect phishing URLs from PhishTank"""
        try:
            print("Fetching data from PhishTank...")
            # Note: In real implementation, you'd use the actual PhishTank API
            # For demo purposes, we'll create sample phishing URLs

            phishing_data = []
            sample_phishing_urls = [
                "http://secure-bank-login.suspicious-domain.com/login.php",
                "https://paypal-verification.fake-site.net/verify.html",
                "http://amazon-security.malicious.org/update-payment.php",
                "https://microsoft-account.phishing.site/signin.aspx",
                "http://apple-id-verification.scam.info/authenticate.html",
                "https://facebook-security-check.fake.com/confirm.php",
                "http://google-account-recovery.suspicious.org/recover.html",
                "https://netflix-billing-update.scam.net/payment.php",
                "http://instagram-verification.phish.com/verify-account.html",
                "https://linkedin-security.malicious.site/login-confirm.php"
            ]

            for i, url in enumerate(sample_phishing_urls[:max_records//2]):
                phishing_data.append({
                    'url': url,
                    'label': 1,  # 1 for phishing
                    'verification': 'yes',
                    'submission_time': datetime.now().isoformat(),
                    'target': 'various'
                })

            print(f"Collected {len(phishing_data)} phishing URLs")
            return phishing_data

        except Exception as e:
            print(f"Error collecting PhishTank data: {e}")
            return []

    def collect_legitimate_data(self, max_records=1000):
        """Collect legitimate URLs"""
        legitimate_data = []

        # Add our known legitimate URLs
        for url in self.legitimate_urls:
            legitimate_data.append({
                'url': url,
                'label': 0,  # 0 for legitimate
                'verification': 'legitimate',
                'submission_time': datetime.now().isoformat(),
                'target': 'legitimate'
            })

        # Generate additional legitimate-looking URLs
        domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'protonmail.com']
        paths = ['/', '/inbox', '/compose', '/settings', '/help', '/about', '/contact']

        for i in range(max_records - len(legitimate_data)):
            domain = random.choice(domains)
            path = random.choice(paths)
            url = f"https://{domain}{path}"

            legitimate_data.append({
                'url': url,
                'label': 0,
                'verification': 'legitimate',
                'submission_time': datetime.now().isoformat(),
                'target': 'legitimate'
            })

        print(f"Collected {len(legitimate_data)} legitimate URLs")
        return legitimate_data

    def save_dataset(self, data, filename):
        """Save collected data to CSV"""
        df = pd.DataFrame(data)
        df.to_csv(filename, index=False)
        print(f"Dataset saved to {filename}")
        return df

    def create_balanced_dataset(self, output_file='data/phishing_dataset.csv'):
        """Create a balanced dataset with phishing and legitimate URLs"""
        print("Creating balanced phishing detection dataset...")

        # Collect data
        phishing_data = self.collect_phishtank_data(500)
        legitimate_data = self.collect_legitimate_data(500)

        # Combine datasets
        all_data = phishing_data + legitimate_data

        # Shuffle the data
        random.shuffle(all_data)

        # Save to CSV
        df = self.save_dataset(all_data, output_file)

        print(f"\nDataset Summary:")
        print(f"Total URLs: {len(df)}")
        print(f"Phishing URLs: {len(df[df['label'] == 1])}")
        print(f"Legitimate URLs: {len(df[df['label'] == 0])}")

        return df

if __name__ == "__main__":
    collector = PhishingDataCollector()
    dataset = collector.create_balanced_dataset()
