import json
import logging
from typing import List, Dict
from core.config import Config

logger = logging.getLogger("BugBot.Scanner.Extractor")

class SourceMapExtractor:
    """Motor atómico para desempaquetar y extraer SourceMaps."""
    
    def __init__(self, semaphore, timeout):
        self.semaphore = semaphore
        self.timeout = timeout

    async def check_sourcemap(self, session, js_url: str, analyzer_func) -> List[Dict]:
        """Verifica si el archivo JS tiene un sourcemap (.map) expuesto y lo desempaqueta."""
        # Sanitizar la URL: Quitar parámetros como ?v=1.2.3 antes de agregar .map
        clean_url = js_url.split('?')[0].split('#')[0]
        map_url = f"{clean_url}.map"
        
        filename = clean_url.split('/')[-1].lower()
        
        # [ALTA PRIORIDAD] Whitelist estricta - NUNCA bloquear el núcleo de la App
        whitelist = ['main', 'app', 'chunk', 'webpack']
        is_high_value = any(w in filename for w in whitelist)

        if not is_high_value:
            blacklisted_names = ['vendor', 'jquery', 'bootstrap', 'chunk-vendors', 'polyfill'] 
            if any(b in filename for b in blacklisted_names) or "hsstatic" in map_url or "hubspot" in map_url:
                return []
        
        async with self.semaphore:
            try:
                headers = {"User-Agent": Config.get_random_user_agent()}
                headers.update(Config.CUSTOM_HEADERS)
                async with session.get(map_url, headers=headers, timeout=self.timeout, allow_redirects=False) as response:
                    if response.status == 200:
                        # Límite duro de 15MB para evitar fugas de RAM
                        MAX_MAP_BYTES = 15 * 1024 * 1024
                        raw_bytes = await response.read()
                        if len(raw_bytes) > MAX_MAP_BYTES:
                            logger.warning(f"[Extractor] SourceMap demasiado grande: {map_url}")
                            return []
                        
                        content = raw_bytes.decode('utf-8', errors='ignore')
                        
                        # Auto-Unpacking SourceMap
                        if content.strip().startswith('{') and ("sourcesContent" in content or "mappings" in content):
                            try:
                                map_data = json.loads(content)
                                findings = [{
                                    'url_archivo': map_url,
                                    'tipo_secreto': "SOURCEMAP_EXPOSED",
                                    'match': "[Código Fuente Original Extraído]"
                                }]
                                
                                # Deep Scan en el código fuente desempaquetado
                                if "sourcesContent" in map_data:
                                    for source in map_data.get("sourcesContent", []):
                                        if isinstance(source, str) and source.strip():
                                            deep_findings = analyzer_func(f"{map_url} [UNPACKED]", source)
                                            if deep_findings:
                                                findings.extend(deep_findings)
                                
                                return findings
                            except Exception:
                                pass
            except Exception:
                pass
        return []
