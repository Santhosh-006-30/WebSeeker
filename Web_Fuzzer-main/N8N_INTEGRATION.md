# Web Fuzzer n8n Integration

This guide explains how to integrate the Web Fuzzer vulnerability scanner with n8n for automated security scanning workflows.

## Quick Start

### 1. Start the API Server

```bash
cd D:\Project\36 Hrs\Web_Fuzzer-main\Web_Fuzzer-main
python api_server.py
```

The server will start at `http://localhost:5000`

### 2. Import the n8n Workflow

1. Open n8n
2. Go to **Workflows** > **Import from File**
3. Select one of the workflow files:
   - `n8n_workflow.json` - Manual trigger workflow
   - `n8n_webhook_workflow.json` - Webhook trigger workflow

### 3. Configure and Run

1. In the workflow, update the **"Set Target URL"** node with your target URL
2. Click **Execute Workflow**
3. View the scan results in the output

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Health check - verify server is running |
| `/scan` | POST | Start an async vulnerability scan |
| `/scan/<id>/status` | GET | Get the status of a running scan |
| `/scan/<id>` | GET | Get the results of a completed scan |
| `/quick-scan` | POST/GET | Synchronous scan - waits for results (best for n8n) |

## Using in n8n

### Option 1: HTTP Request Node (Recommended)

Add an **HTTP Request** node with these settings:

- **Method**: POST
- **URL**: `http://localhost:5000/quick-scan`
- **Body Content Type**: JSON
- **Body Parameters**:
  ```json
  {
    "url": "https://your-target-url.com"
  }
  ```

### Option 2: Webhook Workflow

1. Import `n8n_webhook_workflow.json`
2. Activate the workflow
3. Copy the webhook URL
4. Send POST requests to trigger scans:

```bash
curl -X POST https://your-n8n-url/webhook/web-fuzzer-scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Response Format

The API returns a JSON object with:

```json
{
  "scan_id": "abc12345",
  "target_url": "https://example.com",
  "grade": "A",
  "risk_score": 15,
  "total_vulnerabilities": 3,
  "endpoints_discovered": [...],
  "vulnerabilities": [...],
  "summary": {
    "SQL Injection": 0,
    "Cross-Site Scripting (XSS)": 2,
    "Command Injection": 0,
    ...
  },
  "formatted_report": "Human-readable report text..."
}
```

## Using n8n Expressions

Access scan results using n8n expressions:

- `{{ $json.grade }}` - Security grade (A+ to F)
- `{{ $json.risk_score }}` - Risk score (0-100)
- `{{ $json.total_vulnerabilities }}` - Count of vulnerabilities
- `{{ $json.formatted_report }}` - Human-readable report
- `{{ $json.vulnerabilities[0].type }}` - First vulnerability type
- `{{ $json.summary["SQL Injection"] }}` - SQL Injection count

## Example Workflows

### Scheduled Security Scan

1. **Schedule Trigger** - Run daily at midnight
2. **Set** - Configure target URLs
3. **HTTP Request** - Call `/quick-scan`
4. **IF** - Check if vulnerabilities found
5. **Email/Slack** - Send alert if issues detected

### Multi-Site Scanning

1. **Manual Trigger**
2. **Code** - Define list of URLs
3. **SplitInBatches** - Process each URL
4. **HTTP Request** - Scan each URL
5. **Merge** - Combine all results
6. **Set** - Format final report

## Troubleshooting

### Server won't start
- Check if port 5000 is available
- Install dependencies: `pip install -r requirements.txt`

### n8n can't connect
- Ensure API server is running
- Check firewall settings
- Use `http://127.0.0.1:5000` instead of `localhost`

### Scan takes too long
- The quick-scan endpoint has a 5-minute timeout
- Reduce the number of endpoints being scanned
- Use async `/scan` endpoint for large sites

## Files

- `api_server.py` - Flask API server
- `n8n_workflow.json` - Manual trigger workflow
- `n8n_webhook_workflow.json` - Webhook trigger workflow
