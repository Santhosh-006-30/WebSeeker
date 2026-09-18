# WebSeeker Pro - Advanced Agentic Security Scanner

![Security Score A](https://img.shields.io/badge/Security_Score-A-brightgreen?style=flat-square) ![Python Version](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square) ![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square) ![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat-square)

**WebSeeker Pro** is an enterprise-grade, multi-threaded automated API vulnerability scanner. Designed for security engineers and modern startups, it aggressively maps attack surfaces, intelligently identifies endpoints, and executes parallelized payloads to uncover critical security flaws before attackers do.

## 🚀 Key Capabilities

- **Massive Parallelism**: Spins up hundreds of lightweight threads to test endpoints and payloads simultaneously.
- **Agentic Logic**: Avoids blind spraying; intelligently discovers and verifies backend logic flaws.
- **Cyber-Corporate Dashboard**: Generates a stunning interactive HTML report tailored for both Executives (Grades/Scores) and Developers (Code Fixes/Payloads).
- **OWASP Top 10 Coverage**: Comprehensive checks for SQLi, XSS, SSRF, IDOR, LFI/RFI, and Auth Bypass.
- **Zero-Friction Deployment**: Fully Dockerized with CI/CD GitHub Actions built-in.

---

## ⚡ Quickstart

### Option 1: Docker (Recommended)
The fastest way to get started without polluting your local environment.

```bash
git clone https://github.com/yourusername/webseeker.git
cd WebSeeker
docker-compose up --build
```
Navigate to `http://localhost:5000` to access the Web UI Dashboard.

### Option 2: Local Python Environment
Ensure you have Python 3.9+ installed.

```bash
git clone https://github.com/yourusername/webseeker.git
cd WebSeeker
pip install -r requirements.txt
```

#### Run the Web UI
```bash
python web_app.py
```

#### Run the CLI Scanner
```bash
python main.py https://example.com
```

---

## 📁 Repository Structure

- `core/`: The multi-threaded engine, crawler, API discovery, and centralized logger.
- `scanners/`: Individual vulnerability detection modules (SQLi, XSS, etc.).
- `reporting/`: Generators for the hybrid Cyber-Corporate HTML dashboard, JSON, and CSV.
- `Payloads/`: Comprehensive, categorized directories of attack payloads.
- `ARCHITECTURE.md`: Detailed breakdown of the multi-threaded scanning design.

---

## 📊 Beautiful Reporting

WebSeeker Pro generates an interactive, dark-themed dashboard (`report.html`) in the root directory upon scan completion. 
- **Executives**: Instantly see a 0-100 Security Score and Grade (A-F).
- **Engineers**: Filter by critical findings, view exact payload evidence, and copy-paste secure code remediation snippets.

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
