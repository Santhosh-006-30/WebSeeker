# WebSeeker - Enterprise Grade API Security Scanner

![Security Score A](https://img.shields.io/badge/Security_Score-A-brightgreen?style=flat-square) ![Python Version](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square) ![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)

**WebSeeker** is a powerful, automated API vulnerability scanner designed for security professionals and developers. It helps identify critical security flaws in web applications and APIs before attackers do.

## 🚀 Features

- **Comprehensive Scanning**: Detects SQL Injection, XSS, SSRF, IDOR, Misconfigurations, and more.
- **Intelligent Analysis**: Calculates a "Security Grade" (A-F) based on findings.
- **Professional Reporting**: Generates interactive HTML, JSON, and CSV reports.
- **Top Vulnerable Endpoints**: Automatically identifies the most critical areas of your application.
- **Remediation Guides**: Provides developer-friendly code fixes for every vulnerability found.
- **Parallel Processing**: Multi-threaded architecture for fast and efficient scanning.

## 🛠️ Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/webseeker.git
    cd WebSeeker
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## ⚡ Usage

Run the scanner against a target URL:

```bash
python main.py https://example.com
```

### Options

The scanner is designed to be interactive and easy to use. Simply provide the URL, and let the tool do the heavy lifting.

## 📊 Reports

After a scan is complete, reports are automatically generated in the root directory:

-   `report.html`: Interactive dashboard with graphs and detailed findings.
-   `report.json`: Machine-readable format for integration with other tools.
-   `report.csv`: Spreadsheet-friendly format for auditing.

## 🔐 Project Methodology: Correct Identification of Web Application Vulnerabilities

### 1. Understanding Where Vulnerabilities Actually Exist

Modern web applications are divided into **frontend (client-side)** and **backend (server-side)** components.
While user interaction happens in the frontend, **all security-critical operations are handled by the backend**.
Therefore, this project focuses on **backend-driven vulnerability discovery**, using frontend elements only as **entry points**, not trust points.

**Key principle used in this project:**

> *Frontend is used to reach vulnerabilities; backend is where vulnerabilities are confirmed.*

---

## 2. Correct Vulnerability Discovery Approach (Adopted in This Project)

Instead of blindly scanning URLs, the system follows a **layered and evidence-based approach**:

### Phase 1: Attack Surface Mapping

The scanner first identifies:

* Available endpoints (URLs, API routes)
* Input vectors:
  * Query parameters
  * POST bodies
  * Headers
  * Cookies
  * File upload fields

This prevents false positives caused by testing non-existent or non-exploitable inputs.

### Phase 2: Context-Aware Input Injection

Each input is tested **based on its execution context**:

| Input Location | Vulnerability Tested          |
| -------------- | ----------------------------- |
| URL Parameters | SQL Injection, XSS            |
| POST Data      | SQLi, Command Injection       |
| Headers        | Host Header Injection, SSRF   |
| Cookies        | Session Fixation, Auth Bypass |
| File Upload    | Malicious File Execution      |

Payloads are **not reused blindly**—they are adapted to the input type.

### Phase 3: Backend Response Analysis (Core Strength)

Instead of assuming vulnerability from payload delivery, the project validates issues by analyzing:

* HTTP status changes
* Response length deviations
* Error patterns (DB, server, framework)
* Reflection and execution indicators
* Time-based delays (for blind injections)

This ensures that:

* Reflected payload ≠ Vulnerability
* Error-based proof ≠ Guess
* Exploitation is **confirmed**, not assumed

---

## 3. Vulnerability Categories Accurately Identified

The project focuses on **high-impact, real-world vulnerabilities**, including:

### 🔴 Backend-Critical Vulnerabilities

* SQL Injection (Error-based, Boolean, Time-based)
* Command Injection
* Server-Side Request Forgery (SSRF)
* Insecure File Upload
* Broken Authentication
* Authorization Bypass (IDOR)
* Insecure Deserialization

### 🟠 Entry-Point Vulnerabilities

* Reflected & Stored XSS
* CSRF misconfigurations
* Client-side trust abuse
* Sensitive data exposure

Each finding includes **proof-of-execution**, not just payload evidence.

---

## 4. Exact Vulnerability Location Reporting

Unlike basic scanners, this project reports vulnerabilities with **precise technical context**, including:

* Affected URL / endpoint
* Exact parameter name
* Injection location (query, body, header, cookie)
* Payload used
* Server response evidence
* Risk severity (Low → Critical)
* Recommended mitigation

This makes the output **developer-usable**, not just informative.

---

## 5. Why This Approach Is Correct and Industry-Relevant

### Problems with Traditional Scanners

* Blind payload spraying
* High false positives
* No backend confirmation
* Poor vulnerability context

### Improvements Introduced in This Project

* Backend-focused validation
* Context-aware payloads
* Evidence-based detection
* Minimal false positives
* Real exploitation logic

This aligns with **real penetration testing workflows**, not just academic scanning.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License.

---
*Disclaimer: This tool is for educational and authorized testing purposes only. Usage against targets without prior mutual consent is illegal.*
