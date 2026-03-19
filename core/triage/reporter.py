import os
import logging
from datetime import datetime
from core.config import Config
from core.memory_cortex import MemoryCortex
from core.triage.constants import SEVERITIES

logger = Config.setup_logger("BugBot.Triage", "bugbot_triage.log")

class BugReporter:
    """Motor atómico para generación de reportes estructurados para HackerOne."""
    
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.cortex = MemoryCortex()

    def get_severity(self, bug_type: str) -> str:
        return SEVERITIES.get(bug_type, "Low")

    def _build_impact(self, bug_type: str, bug_data: dict) -> str:
        """Genera descripción de impacto realista basada en el tipo de bug."""
        impacts = {
            "AWS_KEY_EXPOSED": "An attacker could use these credentials to access AWS services, potentially reading S3 buckets, modifying infrastructure, or escalating privileges to full account takeover.",
            "STRIPE_KEY_EXPOSED": "An attacker could use this key to read payment data, issue refunds, or create charges on the merchant's Stripe account.",
            "SLACK_TOKEN_EXPOSED": "An attacker could use this token to read private messages, access internal channels, download files, and impersonate the bot user in the workspace.",
            "GITHUB_TOKEN_EXPOSED": "An attacker could use this token to access private repositories, read source code, modify code, or create releases depending on the token's scopes.",
            "SENDGRID_KEY_EXPOSED": "An attacker could use this key to send phishing emails from the organization's trusted domain, bypassing SPF/DKIM/DMARC protections.",
            "GOOGLE_KEY_EXPOSED": "An attacker could use this API key to consume billing quota (maps, geocoding, etc.), potentially causing significant financial impact.",
            "CLOUD_BUCKET": "An open cloud bucket could expose sensitive customer data, internal documents, backups, or application secrets.",
            "TAKEOVER": "An attacker could claim the abandoned subdomain and serve malicious content under the organization's trusted domain, enabling phishing and cookie stealing.",
            "WAF_BYPASSED": "The WAF protection can be circumvented, exposing the backend application to direct attacks including injection and unauthorized access.",
            "BLIND_SSRF_OOB": "Server-Side Request Forgery allows an attacker to make the server perform requests to internal services, potentially accessing cloud metadata, internal APIs, or pivoting to internal network.",
            "XSS_REFLECTED": "An attacker could execute arbitrary JavaScript in a victim's browser in the context of the target domain, enabling session hijacking, credential theft, and phishing.",
        }
        
        base_impact = bug_data.get('impact_description', '')
        if not base_impact:
            # Buscar coincidencia parcial
            for key, impact in impacts.items():
                if key.lower() in bug_type.lower():
                    base_impact = impact
                    break
        
        if not base_impact:
            base_impact = "Unauthorized access or data leak potential. This vulnerability could be chained with other findings for greater impact."
        
        return base_impact

    def _build_curl_poc(self, bug_data: dict) -> str:
        """Genera curl PoC reproducible."""
        # Si el finding ya tiene curl_poc del validador
        if bug_data.get('curl_poc'):
            return bug_data['curl_poc']
        
        url = bug_data.get('target_url', '')
        bug_type = bug_data.get('bug_type', '')
        
        if 'WAF' in bug_type and bug_data.get('waf_bypass_headers'):
            headers_str = " ".join([f'-H "{k}: {v}"' for k, v in bug_data['waf_bypass_headers'].items()])
            return f'curl -v {headers_str} "{url}"'
        
        if 'SSRF' in bug_type:
            return f'curl -v "{url}"  # Observe OOB callback at interactsh'
        
        if 'XSS' in bug_type:
            return f'# Open in browser:\n{url}'
        
        if 'REDIRECT' in bug_type:
            return f'curl -v -L "{url}"  # Observe Location header redirect'
        
        if 'LFI' in bug_type:
            return f'curl -v "{url}"  # Observe /etc/passwd or win.ini content in response'
        
        return f'curl -I "{url}"'

    def generate_h1(self, bug_data: dict) -> str:
        """Crea el archivo Markdown del reporte en formato HackerOne."""
        bug_type = bug_data.get('bug_type', 'UNKNOWN_VULNERABILITY')
        url = bug_data.get('target_url', '')
        
        if not self.cortex.should_store_finding(url, bug_type):
            return ""

        severity = self.get_severity(bug_type)
        poc = self._build_curl_poc(bug_data)
        impact = self._build_impact(bug_type, bug_data)
        validation_details = bug_data.get('validation_details', '')
        
        # Sección de validación activa (solo si existe)
        validation_section = ""
        if validation_details:
            validation_section = f"""
### Active Validation Results:
```
{validation_details}
```
> This secret was automatically validated against the live API and confirmed to be active.
"""
        
        report = f"""## Title: {bug_type} found on {self.target_domain}

### Weakness
{bug_type}

### Description:
A `{bug_type}` vulnerability was discovered at `{url}`. 
This allows bypassing security controls and could lead to unauthorized access or data exposure.

### Severity: {severity}
{validation_section}
### Steps To Reproduce:
1. Open a terminal and run the following command:
```bash
{poc}
```
2. Observe the response confirming the vulnerability.
3. Note: This was discovered via automated scanning and verified programmatically.

### Supporting Material / References:
- URL: `{url}`
- Discovery timestamp: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}`

### Impact:
{impact}

---
*Report auto-generated by BugBot Triage Engine on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        return self._save(report, bug_type)

    def _save(self, content: str, bug_type: str) -> str:
        reports_dir = self.cortex.get_workspace_path("reports_dir")
        if reports_dir:
            target_dir = os.path.join(reports_dir, self.target_domain.replace(".", "_"))
        else:
            workspace = self.cortex.get_workspace_path("targets_dir") or os.path.join(Config.BASE_DIR, "targets")
            target_dir = os.path.join(workspace, self.target_domain.replace(".", "_"))
            
        os.makedirs(target_dir, exist_ok=True)
        safe_type = "".join([c if c.isalnum() else "_" for c in bug_type])
        filename = f"H1_Report_{safe_type}_{int(datetime.now().timestamp())}.md"
        path = os.path.join(target_dir, filename)

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
