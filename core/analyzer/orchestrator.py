import asyncio
import aiohttp
import logging
import os
from typing import List, Dict
from urllib.parse import urlparse

from core.config import Config
from core.analyzer.constants import INTERESTING_EXTENSIONS
from core.analyzer.downloader import FileDownloader
from core.analyzer.unpacker import FileUnpacker
from core.analyzer.entropy import EntropyHunter

logger = Config.setup_logger("BugBot.Analyzer", "bugbot_analyzer.log")

class AnalyzerOrchestrator:
    """Orquestador atómico del File Analyzer."""
    
    def __init__(self, target_domain: str, concurrency: int = 5):
        self.target_domain = target_domain
        self.semaphore = asyncio.Semaphore(concurrency)
        target_path = Config.get_target_path(target_domain)
        self.downloads_dir = os.path.join(target_path, "downloads")
        
        self.downloader = FileDownloader(self.downloads_dir, self.semaphore)
        self.unpacker = FileUnpacker(os.path.join(self.downloads_dir, 'unpacked'))
        self.hunter = EntropyHunter()

    async def run(self, urls: List[str]) -> List[Dict]:
        target_urls = [u for u in urls if any(urlparse(u).path.lower().endswith(ext) for ext in INTERESTING_EXTENSIONS)]
        if not target_urls: return []
        
        logger.info(f"[*] Analizando {len(target_urls)} archivos sensibles en {self.target_domain}")
        
        async with aiohttp.ClientSession(connector=Config.get_connector()) as session:
            # 1. Descarga
            tasks = [self.downloader.download(session, url) for url in target_urls]
            paths = await asyncio.gather(*tasks)
            paths = [p for p in paths if p]
            
            # 2. Análisis
            all_findings = []
            for path in paths:
                extract_path = self.unpacker.unpack(path)
                scan_target = extract_path if extract_path else path
                
                content = self.unpacker.read_text(scan_target)
                if content:
                    secrets = self.hunter.detect_secrets(content)
                    if secrets:
                        for s in secrets:
                            s.update({
                                "url_archivo": os.path.basename(path),
                                "impacto": "HIGH",
                                "detalles": f"Entropía detectada: {s['entropia']}",
                                "ruta_local": scan_target
                            })
                        all_findings.extend(secrets)
                
                if extract_path and not secrets:
                    self.unpacker.cleanup(extract_path)
                    
        return all_findings
