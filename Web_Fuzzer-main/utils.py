import os
import requests
from config import TIMEOUT
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def check_endpoint_alive(url):
    """Fast check to see if endpoint is responsive before heavy scanning."""
    try:
        requests.get(url, timeout=3, verify=False, stream=True)
        return True
    except:
        return False

def load_payloads_from_file(file_path):
    """Loads payloads from a single file, returning a list of lines."""
    payloads = []
    if not os.path.exists(file_path):
        print(f"⚠️ Warning: Payload file {file_path} not found.")
        return payloads
        
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:
                    payloads.append(stripped_line)
    except Exception as e:
        print(f"⚠️ Error reading {file_path}: {e}")
    
    return payloads

def load_payloads_from_dir(directory_path, extensions=None):
    """Loads payloads from all files in a directory."""
    all_payloads = []
    if not os.path.exists(directory_path):
        print(f"⚠️ Warning: Payload directory {directory_path} not found.")
        return all_payloads

    for root, _, files in os.walk(directory_path):
        for file in files:
            if extensions and not file.endswith(tuple(extensions)):
                continue
            
            file_path = os.path.join(root, file)
            all_payloads.extend(load_payloads_from_file(file_path))
            
    return all_payloads

def generate_fuzzed_urls(url, payload):
    """
    Generates a list of dictionaries containing URLs where the payload is injected into each query parameter.
    Returns: [{'url': '...', 'param': '...'}, ...]
    """
    fuzzed_entries = []
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    
    if query_params:
        # Inject into each existing parameter
        for target_param in query_params:
            # Reconstruct params: keep others as is, replace target with payload
            # parse_qs returns {key: [val1, val2]}
            
            # We want to build a list of (key, value) tuples for urlencode
            current_params_list = []
            
            # Add all OTHER parameters first
            for k, v_list in query_params.items():
                if k != target_param:
                    for v in v_list:
                        current_params_list.append((k, v))
            
            # Add the TARGET parameter with the payload
            # Note: We replace ALL instances of this param with the single payload
            current_params_list.append((target_param, payload))
            
            new_query = urlencode(current_params_list)
            new_url = urlunparse(parsed._replace(query=new_query))
            
            fuzzed_entries.append({
                "url": new_url,
                "param": target_param
            })
    else:
        # Fallback: If no parameters, don't just blindly spray 'id'. 
        # But for an "active scanner", we might want to try appending '?id=' if the user gave a static URL.
        # However, accurate context-aware scanning usually relies on crawling finding the params.
        # Let's support a minimal set of common params purely for the case where the user provided "example.com"
        # and expects us to find something.
        
        common_inputs = ['id', 'q', 'search', 'query', 'page', 'cmd', 'file']
        for param in common_inputs:
             new_query = urlencode({param: payload})
             new_url = urlunparse(parsed._replace(query=new_query))
             fuzzed_entries.append({
                "url": new_url,
                "param": param
            })
            
    return fuzzed_entries

def get_vuln_details(vuln_type, context=None):
    """
    Returns dynamic Impact and Remediation details based on the vulnerability type and specific context.
    
    Args:
        vuln_type (str): The category of vulnerability (e.g., 'SQL Injection', 'Sensitive Data Exposure')
        context (str): Specific details found (e.g., matched error signature, filename found)
    
    Returns:
        dict: containing 'impact' and 'recommendation' strings
    """
    details = {
        "impact": "Security impact varies based on specific exploitation.",
        "recommendation": "Investigate and apply security best practices."
    }

    if vuln_type == "SQL Injection":
        db_type = "Generic SQL"
        if context:
            context = context.lower()
            if "mysql" in context: db_type = "MySQL"
            elif "sqlserver" in context or "microsoft" in context: db_type = "Microsoft SQL Server"
            elif "postgresql" in context: db_type = "PostgreSQL"
            elif "ora-" in context or "oracle" in context: db_type = "Oracle"

        details["impact"] = (
            f"Likely {db_type} database vulnerability. An attacker could bypass authentication, "
            "access, modify, or delete data within the entire database structure, and potentially "
            "gain administrative rights over the database server."
        )
        details["recommendation"] = (
            f"Ensure all inputs interacting with the {db_type} database are sanitized. "
            "Use prepared statements (Parameterized Queries) heavily. "
            "Enforce Least Privilege principles on the database user account."
        )

    elif vuln_type == "Sensitive Data Exposure":
        if context:
            if "api" in context.lower() or "key" in context.lower():
                details["impact"] = "Leaked API keys can allow attackers to access third-party services, cloud resources, or internal APIs with your quota and billing."
                details["recommendation"] = "Revoke the exposed key immediately. Rotate credentials and implement secret scanning in your CI/CD pipeline. Use environment variables."
            
            elif "password" in context.lower() or "credential" in context.lower():
                details["impact"] = "Exposed credentials allow direct unauthorized access to user accounts or administrative panels, leading to full system compromise."
                details["recommendation"] = "Force password resets for affected accounts. Ensure passwords are hashed (Argon2/bcrypt) and never logged or displayed in cleartext."
            
            elif ".env" in context or "config" in context:
                details["impact"] = "Configuration files often contain database connection strings, secret keys (for encryption/sessions), and debug settings."
                details["recommendation"] = "Configure the web server (Apache/Nginx) to deny access to dotfiles (.env, .git) and configuration files. Move configs outside the web root."
            
            elif "backup" in context or ".sql" in context or ".bak" in context:
                details["impact"] = "Backup files can provide a full snapshot of the database or source code at a point in time, revealing all logic and user data."
                details["recommendation"] = "Delete old backup files from production servers. Store backups in secure, access-controlled offsite storage (e.g., S3 private buckets)."

            elif "id_rsa" in context or "ssh" in context:
                details["impact"] = "Compromised SSH private keys grant immediate remote access to the server, potentially as the root user."
                details["recommendation"] = "Regenerate SSH keys immediately. Disable password authentication for SSH and ensure private keys are never in the web root."

    elif vuln_type == "Cross-Site Scripting (XSS)":
        details["impact"] = (
            "Reflected XSS allows an attacker to inject malicious scripts into the browser session of a victim. "
            "This leads to Session Hijacking (cookie theft), Phishing, or unauthorized actions performed on behalf of the user."
        )
        details["recommendation"] = (
            "Implement a strong Content Security Policy (CSP). "
            "Context-aware encoding should be applied to all user input before rendering it in HTML, JavaScript, or CSS contexts. "
            "Use frameworks that auto-escape data (e.g., React, Vue, Angular)."
        )

    return details
