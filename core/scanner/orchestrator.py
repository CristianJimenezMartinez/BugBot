import asyncio
import aiohttp
import logging
from typing import List, Dict
from urllib.parse import urlparse

from core.config import Config
from core.memory_cortex import MemoryCortex
from core.scanner.analyzer import ContentAnalyzer
from core.scanner.extractor import SourceMapExtractor

logger = Config.setup_logger("BugBot.Scanner", "bugbot_scanner.log")

# CDNs y librerías de terceros que NUNCA contienen secretos del target
SKIP_JS_PATTERNS = [
    "jquery", "bootstrap", "react.production", "react-dom.production",
    "angular.min", "lodash", "moment.min", "polyfill",
    "chunk-vendors", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "googletagmanager.com", "google-analytics.com",
    "cdn.segment.com", "hotjar.com", "cdn.amplitude.com",
    "browser.sentry-cdn.com", "gstatic.com", "googleapis.com",
    "challenges.cloudflare.com", "wp-includes", "wp-content/themes",
    "cdn.shopify.com", "static.squarespace.com", "cdn.webflow.com",
    "hsstatic.net", "hubspot.com", "intercomcdn.com",
    "zdassets.com", "tawk.to", "livechatinc.com",
    "fonts.gstatic.com", "use.typekit.net"
]

class ScannerOrchestrator:
    """Orquestador atómico para el escaneo de secretos."""
    
    def __init__(self, concurrency: int = 15, timeout: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout
        self.cortex = MemoryCortex()
        self.analyzer = ContentAnalyzer()
        self.extractor = SourceMapExtractor(self.semaphore, timeout)
        self.findings = []

    def _should_skip_js(self, url: str) -> bool:
        """Filtra JS de CDNs y librerías que no contienen secretos del target."""
        url_lower = url.lower()
        return any(pattern in url_lower for pattern in SKIP_JS_PATTERNS)

    async def scan_url(self, session, url: str) -> List[Dict]:
        """Descarga un archivo JS y lo procesa."""
        domain = urlparse(url).netloc
        if self.cortex.is_currently_banned(domain):
            return []

        async with self.semaphore:
            try:
                headers = {"User-Agent": Config.get_random_user_agent()}
                headers.update(Config.CUSTOM_HEADERS)
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status in [403, 429]:
                        waf_type = response.headers.get("Server", "Unknown WAF")
                        retry_after = response.headers.get("Retry-After")
                        cooldown = int(retry_after) if retry_after and retry_after.isdigit() else 1800
                        self.cortex.record_waf_ban(domain, waf_type=waf_type, custom_cooldown=cooldown)
                        return []

                    ctype = response.headers.get("Content-Type", "").lower()
                    valid_types = ["javascript", "json", "text", "html", "xml"]
                    if not any(vt in ctype for vt in valid_types):
                        return []

                    raw_bytes = await response.read()
                    try:
                        content = raw_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        content = raw_bytes.decode('latin-1', errors='replace')
                            
                    if "swagger:" in content.lower() or "openapi:" in content.lower() or "swagger-ui" in content.lower():
                        if "petstore" in content.lower() or "example.com" in content.lower():
                            return []
                    
                    findings = self.analyzer.scan_content(url, content)
                    return findings
            except Exception as e:
                logger.debug(f"[-] Error descargando {url}: {e}")
        return []

    async def _validate_findings(self, session, findings: List[Dict]) -> List[Dict]:
        """Validación activa de secretos encontrados."""
        for f in findings:
            secret_type = f['tipo_secreto']
            match = f['match']
            
            try:
                if secret_type == "Google API Key":
                    is_valid = await self.analyzer.validate_google_key(session, match)
                    f['validated'] = is_valid
                    f['tipo_secreto'] = f"Google API Key [{'🔥 LIVE' if is_valid else '❌ DEAD'}]"
                    if is_valid:
                        f['validation_details'] = "Key has active billing"
                        f['curl_poc'] = f'curl "https://maps.googleapis.com/maps/api/staticmap?center=0,0&zoom=1&size=400x400&key={match}"'

                elif secret_type == "Stripe Key (Live/Test)":
                    result = await self.analyzer.validate_stripe_key(session, match)
                    f['validated'] = result['valid']
                    mode = "LIVE" if result.get('livemode') else "TEST"
                    f['tipo_secreto'] = f"Stripe Key [{'🔥 ' + mode if result['valid'] else '❌ DEAD'}]"
                    if result['valid']:
                        f['validation_details'] = f"Mode: {mode}, Currency: {result.get('currency', 'N/A')}"
                        f['curl_poc'] = f'curl https://api.stripe.com/v1/balance -u "{match}:"'

                elif secret_type == "Slack Token":
                    result = await self.analyzer.validate_slack_token(session, match)
                    f['validated'] = result['valid']
                    f['tipo_secreto'] = f"Slack Token [{'🔥 LIVE' if result['valid'] else '❌ DEAD'}]"
                    if result['valid']:
                        f['validation_details'] = f"Team: {result.get('team')}, User: {result.get('user')}"
                        f['curl_poc'] = f'curl -H "Authorization: Bearer {match}" https://slack.com/api/auth.test'

                elif secret_type == "GitHub Token":
                    result = await self.analyzer.validate_github_token(session, match)
                    f['validated'] = result['valid']
                    f['tipo_secreto'] = f"GitHub Token [{'🔥 LIVE' if result['valid'] else '❌ DEAD'}]"
                    if result['valid']:
                        f['validation_details'] = f"User: {result.get('user')}, Scopes: {result.get('scopes')}"
                        f['curl_poc'] = f'curl -H "Authorization: token {match}" https://api.github.com/user'

                elif secret_type == "SendGrid API Key":
                    result = await self.analyzer.validate_sendgrid_key(session, match)
                    f['validated'] = result['valid']
                    can_send = "CAN SEND EMAIL" if result.get('has_send') else ""
                    f['tipo_secreto'] = f"SendGrid Key [{'🔥 LIVE ' + can_send if result['valid'] else '❌ DEAD'}]"
                    if result['valid']:
                        f['validation_details'] = f"Scopes: {result.get('scopes_count', 0)}, Mail.send: {result.get('has_send')}"
                        f['curl_poc'] = f'curl -H "Authorization: Bearer {match}" https://api.sendgrid.com/v3/scopes'

                elif secret_type in ["AWS Access Key", "AWS Secret Key"]:
                    f['validated'] = None
                    f['tipo_secreto'] = f"{secret_type} [⚠️ Needs pair validation]"
                    f['validation_details'] = "AWS keys require both Access Key + Secret Key to validate. Check nearby code for the pair."
                    
                else:
                    f['validated'] = None
                    
            except Exception as e:
                logger.debug(f"[-] Error validando {secret_type}: {e}")
                f['validated'] = None
                
        return findings

    async def run(self, js_urls: List[str]) -> List[Dict]:
        """Orquestador asíncrono para escanear múltiples archivos JS."""
        if not js_urls:
            return []

        # Pre-filter: Eliminar CDNs y librerías de terceros
        filtered_urls = [url for url in js_urls if not self._should_skip_js(url)]
        skipped = len(js_urls) - len(filtered_urls)
        if skipped > 0:
            logger.info(f"[*] Filtrados {skipped} archivos JS de CDNs/terceros")

        logger.info(f"[*] Iniciando escaneo de secretos en {len(filtered_urls)} archivos JS...")
        
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Escanear el JS por secretos
            scan_tasks = [self.scan_url(session, url) for url in filtered_urls]
            
            # 2. Escanear por la joya: Sourcemaps
            map_tasks = [self.extractor.check_sourcemap(session, url, self.analyzer.scan_content) for url in filtered_urls]
            
            all_tasks = scan_tasks + map_tasks
            results = await asyncio.gather(*all_tasks, return_exceptions=True)
            
            # Flatten y filtrar excepciones
            raw_findings = []
            for result in results:
                if isinstance(result, Exception):
                    logger.debug(f"[-] Error en tarea de scan: {result}")
                    continue
                raw_findings.extend(result)
            
            # Deduplicar por match (mismo secreto en 5 JS → 1 finding)
            seen_matches = set()
            unique_findings = []
            for f in raw_findings:
                match_key = f.get('match', '')
                if match_key not in seen_matches:
                    seen_matches.add(match_key)
                    unique_findings.append(f)
            
            deduped = len(raw_findings) - len(unique_findings)
            if deduped > 0:
                logger.info(f"[*] Deduplicados {deduped} findings repetidos")
            
            # 3. Validación activa de secretos encontrados
            if unique_findings:
                logger.info(f"[*] Validando {len(unique_findings)} secretos contra APIs reales...")
                self.findings = await self._validate_findings(session, unique_findings)
            else:
                self.findings = []
            
            # Estadísticas
            live_count = sum(1 for f in self.findings if f.get('validated') is True)
            dead_count = sum(1 for f in self.findings if f.get('validated') is False)
            
            logger.info(f"[+] Escaneo finalizado. Total: {len(self.findings)} | 🔥 LIVE: {live_count} | ❌ DEAD: {dead_count}")
            return self.findings
