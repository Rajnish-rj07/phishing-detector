import requests
import json
import pandas as pd
import time
from datetime import datetime, timedelta
import sqlite3
import os

class RealTimeDataCollector:
    def __init__(self):
        self.db_path = "data/realtime_threats.db"
        self.sources = {
            'phishtank': 'http://data.phishtank.com/data/online-valid.json',
            'openphish': 'https://openphish.com/feed.txt',
        }
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for storing threat data"""
        os.makedirs("data", exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_urls (
                id INTEGER PRIMARY KEY,
                url TEXT UNIQUE,
                label INTEGER,  -- 1 for phishing, 0 for legitimate
                source TEXT,
                confidence REAL,
                first_seen TIMESTAMP,
                last_updated TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def collect_phishtank_data(self):
        """Collect from PhishTank API"""
        try:
            response = requests.get(self.sources['phishtank'], timeout=30)
            data = response.json()
            
            threats = []
            for item in data:
                if item.get('verified') == 'yes':
                    threats.append({
                        'url': item['url'],
                        'label': 1,  # phishing
                        'source': 'phishtank',
                        'confidence': 0.9
                    })
            
            return threats[:1000]  # Limit to prevent overload
        except Exception as e:
            print(f"Error collecting PhishTank data: {e}")
            return []
    
    def collect_openphish_data(self):
        """Collect from OpenPhish feed"""
        try:
            response = requests.get(self.sources['openphish'], timeout=30)
            urls = response.text.strip().split('\n')
            
            threats = []
            for url in urls[:500]:  # Limit to prevent overload
                if url.strip():
                    threats.append({
                        'url': url.strip(),
                        'label': 1,  # phishing
                        'source': 'openphish',
                        'confidence': 0.8
                    })
            
            return threats
        except Exception as e:
            print(f"Error collecting OpenPhish data: {e}")
            return []
    
    def update_threat_database(self):
        """Update database with latest threats"""
        print("Collecting real-time threat data...")
        
        # Collect from all sources
        all_threats = []
        all_threats.extend(self.collect_phishtank_data())
        all_threats.extend(self.collect_openphish_data())
        
        # Add legitimate URLs (you can expand this)
        legitimate_urls = [
            'https://www.google.com', 'https://www.facebook.com',
            'https://www.amazon.com', 'https://www.microsoft.com',
            'https://www.apple.com', 'https://www.github.com'
        ]
        
        for url in legitimate_urls:
            all_threats.append({
                'url': url,
                'label': 0,  # legitimate
                'source': 'manual',
                'confidence': 0.95
            })
        
        # Update database
        conn = sqlite3.connect(self.db_path)
        current_time = datetime.now()
        
        for threat in all_threats:
            try:
                conn.execute('''
                    INSERT OR REPLACE INTO threat_urls 
                    (url, label, source, confidence, first_seen, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    threat['url'], threat['label'], threat['source'], 
                    threat['confidence'], current_time, current_time
                ))
            except Exception as e:
                print(f"Error inserting {threat['url']}: {e}")
        
        conn.commit()
        conn.close()
        print(f"Updated database with {len(all_threats)} threats")
    
    def get_recent_data(self, hours=24):
        """Get recent threat data for training"""
        conn = sqlite3.connect(self.db_path)
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        df = pd.read_sql_query('''
            SELECT url, label, confidence, source
            FROM threat_urls 
            WHERE last_updated > ?
            ORDER BY last_updated DESC
        ''', conn, params=(cutoff_time,))
        
        conn.close()
        return df

if __name__ == "__main__":
    collector = RealTimeDataCollector()
    collector.update_threat_database()
