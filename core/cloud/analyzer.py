import xml.etree.ElementTree as ET
import logging
from typing import List, Dict
from core.config import Config
from core.file_analyzer import FileAnalyzer

logger = logging.getLogger("BugBot.Cloud.Analyzer")

class CloudAnalyzer:
    """Motor atómico para análisis de contenido de buckets."""
    
    @staticmethod
    def extract_files(xml_content: str, base_url: str) -> List[str]:
        """Extrae rutas de archivos de un XML de listing (S3/GCP)."""
        juicy = []
        try:
            # Limpieza básica de namespaces para parsing universal
            xml_clean = xml_content.replace('xmlns="http://s3.amazonaws.com/doc/2006-03-01/"', '')
            xml_clean = xml_clean.replace('xmlns="http://doc.s3.amazonaws.com/2006-03-01"', '')
            root = ET.fromstring(xml_clean)
            
            for contents in root.findall('Contents'):
                key = contents.find('Key')
                if key is not None and key.text:
                    fn = key.text
                    ext = fn.split('.')[-1].lower() if '.' in fn else ''
                    if ext in ['env', 'sql', 'db', 'zip', 'tar', 'gz', 'json', 'yml', 'yaml', 'config', 'bak', 'pem', 'key']:
                        juicy.append(f"{base_url.rstrip('/')}/{fn}")
        except Exception: pass
        return juicy

    @staticmethod
    async def analyze_ram_secrets(session, urls: List[str]) -> List[Dict]:
        """Descarga y analiza archivos en memoria para detectar secretos."""
        analyzer = FileAnalyzer(target_domain="cloud.ram")
        found = []
        for url in urls[:20]: # Límite de seguridad por bucket
            try:
                async with session.get(url, headers={"User-Agent": Config.get_random_user_agent()}, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.text(errors='ignore')
                        if len(content) < 5 * 1024 * 1024:
                            secrets = analyzer.detect_secrets_by_entropy(content)
                            if secrets:
                                for s in secrets: s['origen_ram'] = url
                                found.extend(secrets)
            except Exception: pass
        return found
