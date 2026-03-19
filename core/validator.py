import asyncio
import aiohttp
import re
import logging
import os
from typing import List, Dict, Optional

from core.config import Config

from core.config import Config

# Configuración de Logging
logger = Config.setup_logger("BugBot.Validator", "bugbot_validator.log")

class Validator:
    """
    Validator Engine Pro (v1.1):
    - Bypass de Soft 404 (Playtika 372KB responses).
    - Inspección parcial (2048 bytes).
    - Heurística de contexto para PII (Phone/Secrets).
    """

    # Firmas de archivos sensibles para validación de contenido
    SIGNATURES = {
        ".env": [r"DB_", r"APP_", r"AWS_", r"SECRET="],
        ".git/config": [r"\[core\]"],
        ".vscode/sftp.json": [r"\"password\"", r"\"host\""],
        "docker-compose.yml": [r"version:", r"services:"],
        "Dockerfile": [r"FROM ", r"WORKDIR ", r"ENV "],
        "web.config": [r"<configuration>", r"<system.webServer>"],
        "phpinfo.php": [r"PHP Version", r"System ", r"Build Date"],
        "firebase.json": [r"databaseURL", r"messagingSenderId"]
    }

    # Palabras clave de contexto para validar PII (Phone Numbers)
    PII_CONTEXT_KEYWORDS = ["phone", "tel", "mobile", "contact", "support", "call", "whatsapp"]
    INTERNATIONAL_PREFIXES = [r"^\+1", r"^\+34", r"^\+44", r"^\+49", r"^\+7", r"^\+972"]

    # Dominios de librerías y servicios comunes (Falsos Positivos de PII - AppSec Principal v1.1)
    PII_BLACKLIST_DOMAINS = [
        "greensock.com", "github.com", "example.com", "w3.org", "test.com",
        "google.com", "microsoft.com", "cloudflare.com", "jquery.com", "gsap.com",
        "sentry.io", "braze.com", "faisalman.com"
    ]

    def __init__(self, concurrency: int = 20, timeout: int = 10):
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    async def _validate_content_signature(self, path: str, content: str) -> bool:
        """Verifica si el contenido coincide con la firma esperada para la extensión."""
        if "<html" in content.lower() or "<!doctype" in content.lower():
            return False

        for ext, patterns in self.SIGNATURES.items():
            if path.endswith(ext) or ext in path:
                return any(re.search(p, content, re.IGNORECASE) for p in patterns)
        return len(content.strip()) > 0

    async def validate_file_exposure(self, session: aiohttp.ClientSession, finding: Dict) -> Optional[Dict]:
        """Bypass de Soft 404 descargando solo los primeros 2048 bytes."""
        url = finding['url']
        path = finding['path']
        async with self.semaphore:
            try:
                async with session.get(url, headers=Config.CUSTOM_HEADERS, timeout=self.timeout) as response:
                    if response.status == 200:
                        chunk = await response.content.read(2048)
                        content = chunk.decode('utf-8', errors='ignore')
                        if await self._validate_content_signature(path, content):
                            finding['confirmed'] = True
                            finding['size_real'] = response.content_length
                            return finding
            except Exception as e:
                logger.debug(f"Error validando {url}: {e}")
        return None

    def validate_pii_match(self, finding: Dict, target_domain: str) -> bool:
        """Filtro heurístico y de negocio para PII."""
        tipo = finding['tipo_secreto']
        match = finding['match']

        # 1. Lógica para Emails: Business Filter
        if tipo == "PII: Email Exposed":
            email_domain = match.split("@")[-1].lower() if "@" in match else ""
            
            # Descartar si está en la blacklist de librerías
            if any(black_domain in email_domain for black_domain in self.PII_BLACKLIST_DOMAINS):
                return False
            
            # Si el email es del dominio objetivo -> CRITICAL_PII (Double Bounty Fuel)
            if target_domain.lower() in email_domain:
                finding['tipo_secreto'] = "CRITICAL_PII: Internal Email Exposed"
                return True
            
            return True

        # 2. Lógica para Teléfonos
        if tipo == "PII: Phone Number":
            if any(re.search(pref, match) for pref in self.INTERNATIONAL_PREFIXES):
                return True
            clean_match = re.sub(r'[\s\-\(\)\+]', '', match)
            return len(clean_match) >= 7

        return True

    async def run(self, secrets: List[Dict], files: List[Dict], target_domain: str) -> Dict[str, List[Dict]]:
        """Orquesta la validación con contexto de dominio."""
        validated_secrets = [s for s in secrets if self.validate_pii_match(s, target_domain)]
        
        validated_files = []
        if files:
            import sys
            connector = None
            if sys.platform == 'win32':
                resolver = aiohttp.ThreadedResolver()
                connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
                
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [self.validate_file_exposure(session, f) for f in files]
                results = await asyncio.gather(*tasks)
                validated_files = [r for r in results if r is not None]
        
        return {
            "secrets": validated_secrets,
            "files": validated_files
        }
