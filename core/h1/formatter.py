import os
from typing import List, Dict
from core.h1.tactical_assistant import TacticalAssistant

class H1Formatter:
    """
    HackerOne Formatter & Exploit AI (v2.1):
    - Genera reportes listos para enviar con plantillas dinámicas.
    - Provee instrucciones tácticas independientes por tipo de hallazgo.
    - Robusto contra KeyErrors y filtros de ruido.
    """

    def __init__(self, target: str):
        self.target = target
        self.tactical_assistant = TacticalAssistant()

    def format_report(self, findings: List[Dict] = None, fuzz_findings: List[Dict] = None, takeovers: List[Dict] = None, auth_findings: List[Dict] = None, analyzer_findings: List[Dict] = None) -> str:
        """Genera el contenido del reporte formateado para HackerOne de forma dinámica."""
        findings = findings or []
        fuzz_findings = fuzz_findings or []
        takeovers = takeovers or []
        auth_findings = auth_findings or []
        analyzer_findings = analyzer_findings or []
        
        # Robustez: Si se pasan todos los hallazgos en una sola lista (caso Auditor), los clasificamos
        if findings and not any([fuzz_findings, takeovers, auth_findings, analyzer_findings]):
            temp_findings = []
            for f in findings:
                tipo = f.get('tipo', f.get('tipo_secreto', ''))
                if "TAKEOVER" in tipo: takeovers.append(f)
                elif tipo in ["IDOR", "BOLA", "AUTH"]: auth_findings.append(f)
                elif "path" in f: fuzz_findings.append(f)
                elif "entropia" in f: analyzer_findings.append(f)
                else: temp_findings.append(f)
            findings = temp_findings
        
        # 1. Definir Título y Resumen Dinámico
        report_title = f"[Information Disclosure] Sensitive data/PII exposed on {self.target}"
        report_summary = f"While performing security research on `{self.target}`, I discovered several endpoints leaking sensitive information and configuration files."

        if takeovers:
            report_title = f"[Subdomain Takeover] Critical infrastructure vulnerability on {self.target}"
            report_summary = f"While performing security research on `{self.target}`, I discovered a critical Subdomain Takeover vulnerability."
        elif auth_findings:
            report_title = f"[Broken Access Control] Unauthorized data access on {self.target}"
            report_summary = f"While performing security research on `{self.target}`, I discovered a Broken Access Control (IDOR/BOLA) vulnerability allowing unauthorized data access."
        elif findings and any("PII:" in f.get('tipo_secreto', '') for f in findings):
            report_title = f"[PII Exposure] Sensitive user data found in {self.target} (Double Bounty Campaign)"
            report_summary = f"While performing security research on `{self.target}`, I discovered several endpoints leaking Personally Identifiable Information (PII). This vulnerability falls directly under the current campaign for PII exposure."

        # 2. Resumen de lo más impactante (Prevención de KeyErrors)
        categories = set([f.get('tipo_secreto', 'Sensitive Data') for f in findings] + [a.get('tipo_secreto', 'Sensitive Data') for a in analyzer_findings])
        fuzz_categories = set([ff.get('path', 'Unknown Path') for ff in fuzz_findings])
        takeover_categories = set([t.get('tipo', 'Subdomain Takeover') for t in takeovers])
        
        findings_summary = ", ".join(list(categories) + list(fuzz_categories) + list(takeover_categories))
        
        # URL de Prueba de Concepto
        poc_url = findings[0].get('url_archivo', 'N/A') if findings else (fuzz_findings[0].get('url', 'N/A') if fuzz_findings else "N/A")
        
        # Tabla de hallazgos
        findings_table = "| URL | Type |\n| :--- | :--- |\n"
        for f in findings[:10]:
            findings_table += f"| {f.get('url_archivo', 'N/A')} | {f.get('tipo_secreto', 'Sensitive Data')} |\n"
            
        for a in analyzer_findings:
            findings_table += f"| `{a.get('ruta_local', 'N/A')}` | **☢️ {a.get('tipo_secreto', 'Secret')}** (Entropy: {a.get('entropia', 'N/A')}) |\n"
        
        for f in fuzz_findings[:5]:
            findings_table += f"| {f.get('url', 'N/A')} | Sensitive File: {f.get('path', 'N/A')} |\n"
            
        for a in auth_findings:
            findings_table += f"| {a.get('url', 'N/A')} | **🚨 {a.get('tipo', 'IDOR')}** |\n"
            
        for t in takeovers:
            findings_table += f"| {t.get('url', 'N/A')} | **SUBDOMAIN TAKEOVER** |\n"
            
        # 🤖 Asistente de Explotación
        exploit_guide = self.tactical_assistant.generate_exploit_guide(findings, fuzz_findings, takeovers, auth_findings, analyzer_findings, self.target)

        # 🔍 Evidencia Técnica (Leaked Data)
        technical_evidence = ""
        all_evidence = {}
        
        # Consolidar evidencias de todos los tipos de hallazgos
        for source in [findings, analyzer_findings, fuzz_findings, auth_findings]:
            for f in source:
                if f.get('evidence'):
                    for etype, ematches in f['evidence'].items():
                        if etype not in all_evidence: all_evidence[etype] = []
                        all_evidence[etype].extend(ematches)

        if all_evidence:
            technical_evidence = "## 🔍 Technical Evidence (Leaked Data)\n"
            for etype, ematches in all_evidence.items():
                technical_evidence += f"### {etype}\n"
                for m in ematches[:5]: # Límite de 5 por tipo para no saturar
                    technical_evidence += f"- {m}\n"
            technical_evidence += "\n"

        # Construcción del Markdown final
        report = f"""# {report_title}

## Summary
{report_summary}

## Severity
**High (or Critical depending on the data context)**

## Steps To Reproduce
1. Access the following URL: `{poc_url}`
2. Inspect the file content or the network traffic.
3. Observe the exposure of: {findings_summary}

{technical_evidence}## Findings
The following assets are compromised:
{findings_table}

## Impact
Exposing PII or internal configurations allows attackers to perform targeted phishing, account takeover, or gain a deeper understanding of the internal infrastructure for further attacks.

## Recommendations
- Restrict public access to these sensitive files immediately.
- Clean up any JS files containing hardcoded sensitive data.

---
Report generated by BugBot v2.1 - Elite Hunter Edition
"""
        return report + exploit_guide

    def save_h1_report(self, content: str) -> str:
        """Guarda el reporte en disco."""
        from core.config import Config
        target_dir = Config.get_target_path(self.target)
        os.makedirs(target_dir, exist_ok=True)
        h1_path = os.path.join(target_dir, "hackerone_report.md")
        with open(h1_path, "w", encoding="utf-8") as f:
            f.write(content)
        return os.path.abspath(h1_path)
