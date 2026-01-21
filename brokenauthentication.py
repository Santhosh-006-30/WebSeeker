import requests

# Common weak username/password combinations
weak_credentials = [
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "root"),
    ("user", "user"),
    ("test", "test"),
    ("admin", "123456"),
    ("admin", "admin123")
]

def test_broken_authentication(url):
    vulnerabilities = []
    login_url = f"{url}/login.php"  # Adjust based on the actual login page

    print("🔍 Testing for Weak Authentication...")

    for username, password in weak_credentials:
        data = {"username": username, "password": password}
        
        try:
            session = requests.Session()
            response = session.post(login_url, data=data, timeout=5)

            if "incorrect" not in response.text.lower() and response.status_code == 200:
                print(f"❌ Weak credentials found: {username}:{password}")
                vulnerabilities.append({
                    "type": "Broken Authentication",
                    "payload": f"{username}:{password}",
                    "recommendation": "Enforce strong password policies and implement account lockout mechanisms."
                })

            # Checking if session tokens change after login
            session_token_before = session.cookies.get_dict()
            session.post(login_url, data=data)
            session_token_after = session.cookies.get_dict()

            if session_token_before == session_token_after:
                print("❌ Session Fixation detected!")
                vulnerabilities.append({
                    "type": "Broken Authentication",
                    "payload": "Session Fixation",
                    "recommendation": "Regenerate session tokens after login."
                })

        except requests.exceptions.RequestException:
            print("⚠️ Connection error. Skipping this test.")
    
    return vulnerabilities
