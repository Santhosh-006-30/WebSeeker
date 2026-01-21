import requests

# Common sensitive files to check
sensitive_files = [
    "/robots.txt",
    "/.git/",
    "/.htaccess",
    "/.env"
]

def test_security_misconfiguration(url):
    vulnerabilities = []

    print("🔍 Testing for Security Misconfigurations...")

    for file in sensitive_files:
        test_url = url + file
        try:
            response = requests.get(test_url, timeout=5)

            if response.status_code == 200:
                print(f"❌ Exposed file found: {file}")
                vulnerabilities.append({
                    "type": "Security Misconfiguration",
                    "payload": file,
                    "recommendation": "Restrict public access to sensitive files and configure proper access control."
                })

        except requests.exceptions.RequestException:
            print(f"⚠️ Could not connect to {test_url}. Skipping.")

    # Checking Server Headers
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        if "server" in headers:
            server_info = headers["server"]
            print(f"🔍 Server Header: {server_info}")

            if "apache/2.4.49" in server_info.lower():  # Example vulnerable version
                vulnerabilities.append({
                    "type": "Security Misconfiguration",
                    "payload": f"Server Header: {server_info}",
                    "recommendation": "Update to the latest secure version of your web server."
                })

    except requests.exceptions.RequestException:
        print("⚠️ Could not retrieve server headers.")

    return vulnerabilities
