import requests
import re

# Regex patterns to detect sensitive data
sensitive_patterns = {
    "API Key": r"(?i)(api[_-]?key\s*=\s*['\"]?[A-Za-z0-9]{16,}['\"]?)",
    "Password in Response": r"(?i)(password\s*=\s*['\"]?[A-Za-z0-9@#\$\%\^\&\*\!]{6,}['\"]?)",
    "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Credit Card Number": r"\b(?:\d[ -]*?){13,16}\b"
}

def test_sensitive_data_exposure(url):
    vulnerabilities = []
    
    print("🔍 Testing for Sensitive Data Exposure...")
    
    try:
        response = requests.get(url, timeout=5)
        page_content = response.text

        for data_type, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, page_content)
            if matches:
                print(f"❌ {data_type} found: {matches[:3]} (Showing first 3 matches)")
                vulnerabilities.append({
                    "type": "Sensitive Data Exposure",
                    "payload": f"{data_type} - {matches[:3]}",
                    "recommendation": "Remove sensitive data from public-facing pages and use environment variables."
                })

    except requests.exceptions.RequestException:
        print("⚠️ Could not fetch the page content.")

    return vulnerabilities
