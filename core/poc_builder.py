import logging
import html
from urllib.parse import quote
from typing import List, Dict

from core.config import Config

# Configuración de Logging
logger = Config.setup_logger("BugBot.PoCBuilder", "bugbot_poc.log")

class PoCBuilder:
    """
    PoC Builder (v1.1):
    - Genera evidencias de clic automáticas para hallazgos confirmados.
    - [Anti-AV] Codificación HTML/URL para evitar detecciones locales.
    """

    def __init__(self):
        pass

    def build_xss_poc(self, finding: Dict) -> str:
        """Crea una PoC clickable con evasión de AV local."""
        vulnerable_url = finding['url_vulnerable']
        
        # El href ya debe estar URL encoded por el injector (urllib.parse.urlencode)
        # Pero nos aseguramos de que el texto visible del PoC sea seguro
        safe_url = html.escape(vulnerable_url)
        html_poc = f"<a href='{safe_url}' target='_blank'>[Reproduce XSS PoC]</a>"
        
        return html_poc

    def process_findings(self, findings: List[Dict]) -> List[Dict]:
        """Añade la clave auto_poc y sanitiza payloads para evitar bloqueos del SO."""
        for finding in findings:
            if finding['type'] == "VULNERABLE_XSS":
                # 1. Generar PoC HTML safe
                finding['auto_poc'] = self.build_xss_poc(finding)
                
                # 2. Ofuscar el payload original para que no active el AV al leer el JSON/MD
                # Convertimos <script> en &lt;script&gt;
                finding['payload_safe'] = html.escape(finding['payload'])
                
                logger.info(f"[+] PoC generada (Safe Mode) para XSS en {finding['url_vulnerable']}")
        
        return findings

if __name__ == '__main__':
    # Test rápido
    builder = PoCBuilder()
    test_finding = {
        "type": "VULNERABLE_XSS",
        "url_vulnerable": "http://example.com/search?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E",
        "param": "q"
    }
    updated = builder.process_findings([test_finding])
    print(f"PoC Generada: {updated[0]['auto_poc']}")
