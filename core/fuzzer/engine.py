import asyncio
import re
import logging
from typing import Optional, Dict
from urllib.parse import urlparse
from core.config import Config
from core.memory_cortex import MemoryCortex
from core.waf_bypass import DynamicWAFBypass
from core.fuzzer.constants import get_random_ua
from core.fuzzer.calibrator import FuzzerCalibrator
from core.fuzzer.parser import SensitiveParser

logger = logging.getLogger("BugBot.Fuzzer.Engine")

class FuzzerEngine:
    """Motor de fuzzeo de rutas individuales."""
    
    def __init__(self, semaphore: asyncio.Semaphore, cortex: MemoryCortex, timeout: int = 10):
        self.semaphore = semaphore
        self.cortex = cortex
        self.timeout = timeout
        self.calibrator = FuzzerCalibrator(timeout=timeout)
        self.parser = SensitiveParser()

    async def fuzz_path(self, session, base_url: str, path: str, baseline: dict) -> Optional[Dict]:
        """Prueba una ruta específica en un host de forma sigilosa."""
        cms_noise = ["tag", "image", "events", "download", "category", "author", "page", 
                     "register", "login", "signup", "signin", "forgot", "account", "profile", "home", "main", "app"]
        if path.strip("/").lower() in cms_noise:
            return None
            
        static_asset_dirs = {'/js', '/css', '/images', '/img', '/assets', '/static', '/fonts', '/public'}
        path_with_slash = "/" + path.strip("/")
        if path_with_slash in static_asset_dirs or ("/" + path.rstrip("/")) in static_asset_dirs:
            return None

        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        domain = urlparse(base_url).netloc

        if self.cortex.is_currently_banned(domain):
            return None
        
        await asyncio.sleep(Config.get_jitter())
        
        async with self.semaphore:
            try:
                headers = {"User-Agent": get_random_ua()}
                headers.update(Config.CUSTOM_HEADERS)
                async with session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False) as response:
                    content = await response.text(errors='ignore')
                    content_length = len(content)
                    word_count = len(content.split())
                    
                    if response.status in [403, 429]:
                        waf_type = response.headers.get("Server", "Unknown WAF")
                        retry_after = response.headers.get("Retry-After")
                        cooldown = int(retry_after) if retry_after and retry_after.isdigit() else 1800
                        self.cortex.record_waf_ban(domain, waf_type=waf_type, custom_cooldown=cooldown)
                        return None

                    if self.calibrator.is_false_positive(baseline, response.status, content_length, word_count):
                        return None
                        
                    if response.status in [200, 401, 403, 500]:
                        content_type = response.headers.get("Content-Type", "").lower()
                        sensitive_extensions = [".env", ".sql", ".zip", ".bak", ".log", ".json", "/api/"]
                        if "html" in content_type and any(ext in path.lower() for ext in sensitive_extensions):
                            return None

                        if content_length > 0 and "404" not in content.lower():
                            if response.status == 200:
                                self.cortex.remember_vulnerable_path(domain, f"/{path.lstrip('/')}", "SensitiveFile")

                            waf_poc = None
                            if response.status in [401, 403]:
                                sniper = DynamicWAFBypass(concurrency=3)
                                waf_poc = await sniper.sniper_bypass(url, original_status=response.status)

                            api_mutations_found = []
                            if re.search(r'/v[1-9]/', path.lower()):
                                versions_to_test = ['v1', 'v2', 'v3', 'beta']
                                current_version_match = re.search(r'/(v[1-9])/', path.lower())
                                if current_version_match:
                                    current_ver = current_version_match.group(1)
                                    for v in versions_to_test:
                                        if v != current_ver:
                                            ghost_path = path.lower().replace(f"/{current_ver}/", f"/{v}/")
                                            ghost_url = base_url.rstrip("/") + "/" + ghost_path.lstrip("/")
                                            try:
                                                async with session.get(ghost_url, headers=headers, timeout=self.timeout, allow_redirects=False) as ghost_res:
                                                    if ghost_res.status == 200:
                                                        api_mutations_found.append({"ghost_url": ghost_url, "status": 200, "version_olvidada": v})
                                            except Exception: pass

                            result = {
                                "url": url,
                                "status": response.status,
                                "size": content_length,
                                "path": path,
                                "juicy_extracted": [],
                                "waf_bypass": waf_poc,
                                "ghost_apis_found": api_mutations_found,
                                "severity": "MEDIUM",
                                "finding_type": "VULN"
                            }
                            
                            if "robots.txt" in path.lower() or "sitemap.xml" in path.lower():
                                juicy = await self.parser.parse_sensitive_file(content)
                                if juicy: 
                                    result["juicy_extracted"] = juicy
                                    result["severity"] = "HIGH"
                                    result["finding_type"] = "VULN"
                                else:
                                    result["severity"] = "INFO" 
                                    result["finding_type"] = "RECON"
                            elif any(ext in path.lower() for ext in [".env", ".git/config", ".aws/credentials"]):
                                result["severity"] = "CRITICAL"
                                result["finding_type"] = "VULN"
                                    
                            return result
            except Exception:
                pass
        return None
