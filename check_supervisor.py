import requests
import json

def check_existing_supervisors():
    """Check existing supervisors in database"""
    
    base_url = "http://localhost:8000"
    
    # Admin login
    login_response = requests.post(
        f"{base_url}/auth/login",
        data={"username": "admin@lh.io.in", "password": "Test@123"}
    )
    
    if login_response.status_code != 200:
        print("❌ Admin login failed!")
        return
    
    admin_token = login_response.json()["access_token"]
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json"
    }
    
    print("✅ Admin login successful!")
    
    # Try to get admin dashboard to see stats
    dashboard_response = requests.get(
        f"{base_url}/admin/dashboard",
        headers=headers
    )
    
    if dashboard_response.status_code == 200:
        dashboard_data = dashboard_response.json()
        print(f"📊 Dashboard Stats:")
        print(f"   Total Users: {dashboard_data['stats']['totalUsers']}")
        print(f"   Total Supervisors: {dashboard_data['stats']['totalSupervisors']}")
        print(f"   Total Guards: {dashboard_data['stats']['totalGuards']}")
    
    # Try creating supervisor with unique email
    print("\n🧪 Testing supervisor creation with unique email...")
    unique_supervisor_data = {
        "name": "Unique Test Supervisor",
        "email": f"unique.test.{int(requests.get('http://worldtimeapi.org/api/timezone/UTC').json()['unixtime'])}@lh.io.in",
        "phone": "8765432100",
        "password": "Test@123",
        "areaCity": "UniqueCity"
    }
    
    create_response = requests.post(
        f"{base_url}/admin/add-supervisor",
        headers=headers,
        json=unique_supervisor_data
    )
    
    print(f"📊 Creation Status: {create_response.status_code}")
    if create_response.status_code == 200:
        result = create_response.json()
        print("✅ Supervisor created successfully!")
        print(f"📋 Response: {json.dumps(result, indent=2)}")
    else:
        print(f"❌ Creation failed: {create_response.text}")

if __name__ == "__main__":
    check_existing_supervisors()
