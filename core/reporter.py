import os
from datetime import datetime
from typing import List, Dict
from core.config import Config
from core.file_manager import FileManager

class Reporter:
    """
    Módulo Reporter Senior (v1.1):
    - Generación de informes de grado profesional.
    - Delegación de persistencia al FileManager (Shielded).
    - Uso de Config centralizada.
    """

    def __init__(self, target: str):
        self.target = target
        self.report_name = "audit_report.md"

    def generate_markdown_content(self, findings: List[Dict], fuzz_findings: List[Dict] = [], dast_findings: List[Dict] = [], takeover_findings: List[Dict] = []) -> str:
        """Genera el contenido del informe en memoria."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_secrets = len(findings)
        total_fuzz = len(fuzz_findings)
        total_dast = len(dast_findings)
        total_takeover = len(takeover_findings)
        
        risk_level = "CRÍTICO" if (total_secrets > 0 or total_fuzz > 0 or total_dast > 0 or total_takeover > 0) else "BAJO"
        
        md_content = f"""# 🛡️ BugBot v1.1: Informe de Auditoría de Ciberseguridad (APSEC EDITION)
**Objetivo:** `{self.target}`
**Fecha y Hora:** {now}
**Nivel de Riesgo Detectado:** `{risk_level}`

---

## 1. Resumen Ejecutivo
Se ha realizado una auditoría exhaustiva de seguridad (Recon Pro + PII Hunter + Infra) sobre el objetivo.

**Hallazgos Totales:**
- **Infraestructura Crítica (Takeovers):** {total_takeover} potenciales.
- **Vulnerabilidades Activas (XSS):** {total_dast} confirmadas.
- **Secretos/PII:** {total_secrets} potenciales fugas detectadas.
- **Archivos Sensibles:** {total_fuzz} archivos encontrados.

---

"""
        if takeover_findings:
            md_content += """## 2. Infraestructura Crítica (Subdomain Takeover) 🚀
| Host | Servicio Detectado | Tipo de Riesgo |
| :--- | :--- | :--- |
"""
            for t in takeover_findings:
                md_content += f"| `{t['host']}` | `{t['service']}` | `{t['type']}` |\n"
            md_content += "\n---\n\n"

        if dast_findings:
            md_content += """## 3. Vulnerabilidades Activas (DAST) 💉
| Tipo de Fallo | Parámetro | Prueba de Concepto (Clickeable) | Payload (Safe) |
| :--- | :--- | :--- | :--- |
"""
            for d in dast_findings:
                safe_payload = d.get('payload_safe', 'N/A')
                md_content += f"| `{d['type']}` | `{d['param']}` | {d['auto_poc']} | `{safe_payload}` |\n"
            md_content += "\n---\n\n"

        md_content += """## 4. Detalle de Vulnerabilidades (Secretos & PII)
"""

        # Separar secretos validados de potenciales
        live_secrets = [f for f in findings if f.get('validated') is True]
        dead_secrets = [f for f in findings if f.get('validated') is False]
        unknown_secrets = [f for f in findings if f.get('validated') is None]

        if live_secrets:
            md_content += """### 🔥 SECRETOS CONFIRMADOS (Validados contra API)
| URL del Archivo | Tipo de Hallazgo | Match (Fragmento) | PoC |
| :--- | :--- | :--- | :--- |
"""
            for f in live_secrets:
                match_snippet = f['match'][:40] + "..." if len(f['match']) > 40 else f['match']
                poc = f.get('curl_poc', 'N/A')
                poc_snippet = poc[:60] + "..." if len(poc) > 60 else poc
                md_content += f"| {f['url_archivo']} | `{f['tipo_secreto']}` | `{match_snippet}` | `{poc_snippet}` |\n"
            md_content += "\n"

        if unknown_secrets:
            md_content += """### ❓ Secretos Potenciales (Sin validación activa)
| URL del Archivo | Tipo de Hallazgo | Match (Fragmento) |
| :--- | :--- | :--- |
"""
            for f in unknown_secrets:
                match_snippet = f['match'][:50] + "..." if len(f['match']) > 50 else f['match']
                md_content += f"| {f['url_archivo']} | `{f['tipo_secreto']}` | `{match_snippet}` |\n"
            md_content += "\n"

        if dead_secrets:
            md_content += f"""### ❌ Secretos Inválidos ({len(dead_secrets)} descartados)
> Estos secretos fueron validados contra la API real y están inactivos. No reportar.

"""

        if not findings:
            md_content += "| N/A | No se detectaron secretos ni PII | N/A |\n"

        if fuzz_findings:
            md_content += """
---

## 5. Archivos Sensibles Descubiertos (Fuzzing)
| URL del Archivo | Status | Tamaño (Bytes) |
| :--- | :--- | :--- |
"""
            for ff in fuzz_findings:
                md_content += f"| {ff['url']} | `{ff['status']}` | `{ff['size']}` |\n"

        md_content += """
---

## 6. Recomendaciones Técnicas
1. **Takeover Remediation:** Verificar apuntamientos DNS de subdominios huérfanos.
2. **Saneamiento de Parámetros:** Implementar validación estricta y escape de salida para mitigar XSS.
3. **PII Cleanup:** Eliminar cualquier dato personal expuesto para cumplir con el programa de Playtika.

---
*Generado automáticamente por BugBot v1.1 - APSEC PRINCIPAL EDITION*
"""
        return md_content

    def save_to_disk(self, md_content: str) -> str:
        """Persistencia delegada al FileManager con rutas de Config."""
        abs_path = os.path.join(Config.get_target_path(self.target), self.report_name)
        return FileManager.write_file(abs_path, md_content)

if __name__ == "__main__":
    rep = Reporter("example.com")
    content = rep.generate_markdown_content([{'url_archivo': 'test.js', 'tipo_secreto': 'PII', 'match': 'test'}])
    print(content)
