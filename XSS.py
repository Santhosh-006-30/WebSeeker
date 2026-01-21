import requests

def test_xss(url):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "'\"><script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>"
    ]
    
    vulnerabilities = []
    
    for payload in xss_payloads:
        test_url = f"{url}?q={payload}" # Modify this based on site input structure
        print(f"  🔹 Testing payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5)

            if payload in response.text:
                vulnerabilities.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "payload": payload,
                    "recommendation": "Use Content Security Policy (CSP) and sanitize user inputs."
                })
                print("  ❌ Vulnerability Found!")

        except requests.exceptions.RequestException:
            print(" ⚠️ Connection Error. Skipping payload.")

    return vulnerabilities
