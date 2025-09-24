#!/usr/bin/env python3
"""
Test script for QR creation endpoint
"""

import requests
import json

# Test data
base_url = "http://127.0.0.1:8000"
supervisor_login_data = {
    "email": "test@example.com",  # Replace with actual supervisor email
    "password": "test123"  # Replace with actual password
}

def test_qr_creation():
    """Test the QR creation endpoint"""
    
    print("🔐 Logging in as supervisor...")
    
    # Login to get token
    login_response = requests.post(f"{base_url}/auth/supervisor/login", json=supervisor_login_data)
    
    if login_response.status_code != 200:
        print(f"❌ Login failed: {login_response.status_code}")
        print(login_response.text)
        return
    
    login_data = login_response.json()
    token = login_data.get("access_token")
    
    if not token:
        print("❌ No access token received")
        return
    
    print("✅ Login successful!")
    
    # Test QR creation
    headers = {"Authorization": f"Bearer {token}"}
    qr_data = {
        "site": "Google",
        "post_name": "Main Gate"
    }
    
    print(f"🔧 Creating QR code for site: {qr_data['site']}, post: {qr_data['post_name']}")
    
    qr_response = requests.post(f"{base_url}/qr/create", json=qr_data, headers=headers)
    
    print(f"📊 Response status: {qr_response.status_code}")
    print(f"📊 Response headers: {dict(qr_response.headers)}")
    
    if qr_response.status_code == 200:
        if qr_response.headers.get('content-type') == 'image/png':
            print("✅ QR code generated successfully! (PNG image received)")
            # Save the QR code image
            with open("test_qr_code.png", "wb") as f:
                f.write(qr_response.content)
            print("💾 QR code saved as test_qr_code.png")
        else:
            print("⚠️ Expected image/png but got:", qr_response.headers.get('content-type'))
    else:
        print(f"❌ QR creation failed: {qr_response.status_code}")
        print(qr_response.text)
    
    # Test creating the same QR again (should return existing one)
    print(f"\n🔄 Testing duplicate QR creation...")
    qr_response2 = requests.post(f"{base_url}/qr/create", json=qr_data, headers=headers)
    
    print(f"📊 Second response status: {qr_response2.status_code}")
    
    if qr_response2.status_code == 200:
        if qr_response2.headers.get('content-type') == 'image/png':
            print("✅ Existing QR code returned successfully!")
            # Save the second QR code image
            with open("test_qr_code_2.png", "wb") as f:
                f.write(qr_response2.content)
            print("💾 Second QR code saved as test_qr_code_2.png")
        else:
            print("⚠️ Expected image/png but got:", qr_response2.headers.get('content-type'))
    else:
        print(f"❌ Second QR creation failed: {qr_response2.status_code}")
        print(qr_response2.text)

if __name__ == "__main__":
    test_qr_creation()
