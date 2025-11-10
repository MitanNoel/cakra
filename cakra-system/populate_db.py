#!/usr/bin/env python3
"""
Populate CAKRA database with sample scan results for testing
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime, timedelta
import random

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from cakra.core.config import ConfigLoader
from cakra.core.database import Database

# Sample data
SAMPLE_DOMAINS = [
    "suspicious-gambling-site.xyz",
    "fake-bank-phishing.com",
    "scam-investment.net",
    "illegal-streaming.org",
    "gambling-online.id",
    "pharma-scam.co.id",
    "lottery-fraud.com",
    "casino-illegal.net",
    "betting-unauthorized.xyz",
    "crypto-scam.com",
]

CATEGORIES = ["gambling", "phishing", "scam", "harmful", "drugs", "illegal_streaming"]
OPERATORS = ["ISP1", "ISP2", "ISP3", "Cloudflare", "AWS", "Unknown"]

async def populate_database():
    """Populate database with sample scan results"""
    
    # Load configuration and initialize database
    config = ConfigLoader().get_config()
    db = Database(config.database)
    await db.init_db()
    
    print("🔄 Populating database with sample scan results...")
    
    for i, domain in enumerate(SAMPLE_DOMAINS):
        # Generate realistic data
        illegal_rate = random.randint(60, 95)
        risk_score = illegal_rate // 10
        category = random.choice(CATEGORIES)
        operator = random.choice(OPERATORS)
        confidence = random.randint(75, 95) / 100.0
        
        # Create scan result matching the ScanResult model
        scan_result = {
            "url": f"https://{domain}",
            "domain": domain,
            "illegal_rate": illegal_rate,
            "confidence": confidence,
            "classification": category,
            "text_analysis": {
                "category": category,
                "confidence": confidence,
                "illegal_rate": illegal_rate,
                "defacement_detected": random.choice([True, False]),
                "suspicious_elements": random.randint(1, 10)
            },
            "visual_analysis": {
                "screenshots_analyzed": 1,
                "suspicious_visuals": random.randint(0, 3)
            },
            "payment_info": {
                "payment_channels": [
                    {
                        "type": random.choice(["bank", "qris", "ewallet"]),
                        "identifier": f"{random.randint(1000000000, 9999999999)}",
                        "confidence": random.randint(70, 95)
                    }
                ] if random.random() > 0.3 else []
            },
            "vulnerabilities": {
                "weaknesses": ["Outdated SSL", "No HTTPS"],
                "suspicious_scripts": random.randint(0, 5)
            },
            "server_info": {
                "operator": operator,
                "ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "server_version": random.choice(["nginx/1.20", "Apache/2.4", "Unknown"])
            },
            "whois_data": {
                "country": "Indonesia" if ".id" in domain else "Unknown",
                "registrar": "Unknown"
            },
            "linked_domains": []
        }
        
        await db.add_scan_result(scan_result)
        print(f"✅ Added: {domain} (Category: {category}, Risk: {risk_score}/10)")
    
    # Add some payment channels
    print("\n🔄 Adding sample payment channels...")
    payment_channels = [
        {
            "identifier": "1234567890",
            "channel_type": "bank",
            "risk_score": 8,
            "associated_urls": [f"https://{SAMPLE_DOMAINS[0]}", f"https://{SAMPLE_DOMAINS[1]}"],
            "channel_metadata": {"provider": "BCA", "detection_count": 2}
        },
        {
            "identifier": "081234567890",
            "channel_type": "ewallet",
            "risk_score": 7,
            "associated_urls": [f"https://{SAMPLE_DOMAINS[2]}"],
            "channel_metadata": {"provider": "GoPay", "detection_count": 1}
        },
    ]
    
    for channel in payment_channels:
        await db.add_payment_channel(channel)
        provider = channel['channel_metadata'].get('provider', 'Unknown')
        print(f"✅ Added payment channel: {provider} - {channel['identifier']}")
    
    print("\n✨ Database populated successfully!")
    print(f"📊 Total scan results: {len(SAMPLE_DOMAINS)}")
    print(f"💳 Total payment channels: {len(payment_channels)}")

if __name__ == "__main__":
    asyncio.run(populate_database())
