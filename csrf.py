import requests

def test_csrf(url):
    """
    Tests for CSRF vulnerability by attempting a sensitive action without authentication headers.
    """
    test_url = f"{url}/change_password.php"  # Change this endpoint if needed

    data = {
        "new_password": "hacked123",
        "confirm_password": "hacked123"
    }
    
    # Mimic a real browser request
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Referer": url  # Some CSRF protections check this
    }

    try:
        print(f"🔍 Testing CSRF on {test_url} ...")
        response = requests.post(test_url, data=data, headers=headers)

        vulnerabilities = []
        
        if response.status_code == 200 and "Password changed successfully" in response.text:
            vulnerabilities.append({
                "type": "Cross-Site Request Forgery (CSRF)",
                "payload": "CSRF request without authentication",
                "recommendation": "Implement CSRF tokens, use SameSite cookies, and validate request origins."
            })

        return vulnerabilities

    except requests.exceptions.RequestException as e:
        print(f"❌ Error: {e}")
        return []
