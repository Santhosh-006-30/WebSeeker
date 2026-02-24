
import json
import os
from datetime import datetime

class JsonGenerator:
    def generate_report(self, user_name, target_url, vulnerabilities, scan_summary, filename="report.json"):
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "scanner": "WebSeeker V3.0",
                "scanned_by": user_name,
                "target_url": target_url
            },
            "summary": {
                "total_findings": len(vulnerabilities),
                "module_stats": {k: len(v) for k, v in scan_summary.items()}
            },
            "findings": vulnerabilities
        }
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False)
            return os.path.abspath(filename)
        except Exception as e:
            return None
