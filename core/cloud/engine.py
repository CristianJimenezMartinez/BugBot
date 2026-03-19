import asyncio
import random
import logging
from urllib.parse import urlparse
from typing import Optional, Dict

from core.config import Config
from core.memory_cortex import MemoryCortex
from core.cloud.analyzer import CloudAnalyzer

logger = logging.getLogger("BugBot.Cloud.Engine")

class CloudEngine:
    """Motor de auditoría atómico para buckets."""
    
    def __init__(self, semaphore: asyncio.Semaphore, timeout: int = 8, strict_mode: bool = True):
        self.semaphore = semaphore
        self.timeout = timeout
        self.strict_mode = strict_mode
        self.cortex = MemoryCortex()
        self.jitter_base = 0.5
        self.analyzer = CloudAnalyzer()

    async def audit_url(self, session, url: str, cname_propietario: str = None) -> Optional[Dict]:
        """Prueba un bucket individual con manejo de bloqueos y backoff."""
        domain_host = urlparse(url).netloc
        if self.cortex.is_currently_banned(domain_host): return None

        # Stealth Jitter
        await asyncio.sleep(random.uniform(self.jitter_base, self.jitter_base + 1.2))

        # Lógica de modo estricto (auditar solo lo validado por CNAME)
        if self.strict_mode and not cname_propietario: return None

        async with self.semaphore:
            try:
                headers = {"User-Agent": Config.get_random_user_agent()}
                async with session.get(url, headers=headers, timeout=self.timeout, allow_redirects=True) as resp:
                    content = await resp.text(errors='ignore')
                    
                    if resp.status in [403, 429] and "AccessDenied" not in content:
                        # Bloqueo de red detectado
                        self.cortex.record_waf_ban(domain_host, waf_type="CloudWAF", severity=2)
                        self.jitter_base = min(self.jitter_base * 1.5, 8.0)
                        return None

                    ownership_msg = f" [CNAME: {cname_propietario}]" if cname_propietario else ""

                    if resp.status == 200:
                        is_list = ("<ListBucketResult" in content or "<EnumerationResults" in content) or \
                                  ("windows.net" in url and ("<Blob" in content or "BlobBlock" in content))
                        
                        if is_list:
                            files = self.analyzer.extract_files(content, url)
                            secrets = await self.analyzer.analyze_ram_secrets(session, files) if files else []
                            return {
                                "tipo": "EXPOSED_CLOUD_BUCKET_LISTING",
                                "impacto": "CRITICAL" if cname_propietario else "HIGH",
                                "url": url,
                                "detalles": f"Listing Abierto{ownership_msg}. Files: {len(files)}",
                                "archivos_sensibles": files,
                                "secretos_en_ram": secrets
                            }
                    
                    elif resp.status == 403 and "AccessDenied" in content:
                        return {
                            "tipo": "CLOUD_BUCKET_EXISTS",
                            "impacto": "LOW",
                            "url": url,
                            "detalles": f"Bucket privado detectado{ownership_msg}."
                        }
                    
                    elif resp.status == 404 and cname_propietario:
                        if "NoSuchBucket" in content or "BlobNotFound" in content:
                            return {
                                "tipo": "CLOUD_TAKEOVER_CANDIDATE",
                                "impacto": "CRITICAL",
                                "url": url,
                                "detalles": f"¡TAKEOVER! CNAME apunta a bucket inexistente: {cname_propietario}"
                            }

            except Exception: pass
        return None
