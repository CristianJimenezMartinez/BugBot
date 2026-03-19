import asyncio
import aiohttp
import re
import random
import logging
import socket
import os
import sys
from typing import List, Set, Dict
from core.config import Config

# Compatibilidad Crítica para Windows con aiohttp/aiodns
    import sys

from core.config import Config

# Configuración de Logging
logger = Config.setup_logger("BugBot.Recon", "bugbot_recon.log")

from core.config import Config

class Recon:
    """
    Módulo de Reconocimiento Alta Precisión (v1.1):
    - Smart Scoring: Prioriza subdominios críticos.
    - Takeover Detection: Busca infraestructuras huérfanas.
    - Liveness Check: Descarta hosts que no resuelven IP.
    """
    
    USER_AGENTS = Config.USER_AGENTS

    # Firmas de Subdomain Takeover
    TAKEOVER_SIGNATURES = {
        "Amazon S3": ["NoSuchBucket", "The specified bucket does not exist"],
        "Heroku": ["no such app", "item not found", "heroku-error-404"],
        "GitHub Pages": ["There isn't a GitHub Pages site here", "404 Not Found"],
        "Azure": ["The resource you are looking for has been removed", "404 Web Site not found"],
        "Cloudfront": ["Bad request", "The request could not be satisfied"],
        "Bitbucket": ["Repository not found"]
    }

    def __init__(self, domain: str):
        self.domain = domain
        self.max_retries = 3
        self.timeout = aiohttp.ClientTimeout(total=Config.TIMEOUT)
        self.takeovers = []

    def _get_random_ua(self) -> str:
        return random.choice(self.USER_AGENTS)

    def is_alive(self, host: str) -> bool:
        """Limpieza de 'Muertos': Verifica resolución DNS básica."""
        try:
            socket.gethostbyname(host)
            return True
        except socket.gaierror:
            return False

    def get_score(self, host: str) -> int:
        """Smart Scoring: Asigna prioridad según el nombre del subdominio."""
        host_lower = host.lower()
        score = 0
        for kw in Config.INTEREST_KEYWORDS:
            if kw in host_lower:
                score += 10
        return score

    async def check_takeover(self, session: aiohttp.ClientSession, host: str):
        """Detección de Subdomain Takeover: Análisis de firmas en 404."""
        url = f"http://{host}"
        try:
            headers = {"User-Agent": self._get_random_ua()}
            async with session.get(url, headers=headers, timeout=5, allow_redirects=True) as response:
                if response.status == 404:
                    content = await response.text()
                    for service, sigs in self.TAKEOVER_SIGNATURES.items():
                        if any(sig in content for sig in sigs):
                            logger.critical(f"[!!!] POSIBLE TAKEOVER DETECTADO: {host} -> {service}")
                            self.takeovers.append({
                                'host': host,
                                'service': service,
                                'type': 'Subdomain Takeover'
                            })
        except Exception:
            pass

    async def fetch_crt_sh(self, session: aiohttp.ClientSession) -> Set[str]:
        """Consulta agresiva a crt.sh."""
        url = f"https://crt.sh/?q={self.domain}&output=json"
        try:
            headers = {"User-Agent": self._get_random_ua()}
            async with session.get(url, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    subs = set()
                    for entry in data:
                        name_value = (entry.get('common_name') or '') + "\n" + (entry.get('name_value') or '')
                        for name in re.split(r'[\n,]', name_value):
                            name = name.strip().lower()
                            if name.endswith(self.domain) and name != self.domain:
                                subs.add(name.replace("*.", ""))
                    return subs
        except:
            pass
        return set()

    async def fetch_hacker_target(self, session: aiohttp.ClientSession) -> Set[str]:
        """Consulta a la API de HackerTarget."""
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    text = await response.text()
                    subs = set()
                    for line in text.splitlines():
                        if "," in line:
                            host = line.split(",")[0].strip().lower()
                            if host.endswith(self.domain):
                                subs.add(host)
                    return subs
        except:
            pass
        return set()

    async def fetch_anubis(self, session: aiohttp.ClientSession) -> Set[str]:
        """Consulta a la API de Anubis (jldc.me)."""
        url = f"https://jldc.me/anubis/subdomains/{self.domain}"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    data = await response.json()
                    return {s.strip().lower() for s in data if s.lower().endswith(self.domain)}
        except:
            pass
        return set()

    async def dns_brute_force(self) -> Set[str]:
        """Fuerza bruta DNS ligera para detectar hosts no indexados."""
        found = set()
        loop = asyncio.get_event_loop()
        
        # Primero detectamos si hay WILDCARD para evitar falsos positivos
        random_sub = f"antigravity-check-{random.randint(1000, 9999)}.{self.domain}"
        try:
            await loop.run_in_executor(None, socket.gethostbyname, random_sub)
            logger.warning(f"[!] Wildcard DNS detectado en {self.domain}. Brute force desactivado para evitar ruido.")
            return found
        except:
            pass

        # Si no hay wildcard, procedemos con la lista crítica de Config
        for prefix in Config.BRUTE_FORCE_LIST:
            sub = f"{prefix}.{self.domain}"
            try:
                # Usamos executor para no bloquear el bucle de eventos con DNS síncrono
                await loop.run_in_executor(None, socket.gethostbyname, sub)
                found.add(sub.lower())
            except:
                continue
        return found

    async def run(self) -> List[str]:
        """Orquestador de Recon Deep Hunter (Senior Level)."""
        print(f"[*] Fase 1: Recon Deep Hunter para {self.domain}...")
        
        import sys
        connector = None
        if sys.platform == 'win32':
            resolver = aiohttp.ThreadedResolver()
            connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
            
        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Descubrimiento Pasivo Multi-Fuente
            print(f"[*] Consultando fuentes pasivas (crt.sh, HackerTarget, Anubis)...")
            p_tasks = [
                self.fetch_crt_sh(session),
                self.fetch_hacker_target(session),
                self.fetch_anubis(session)
            ]
            p_results = await asyncio.gather(*p_tasks)
            passive_subs = set().union(*p_results)
            
            # 2. Descubrimiento Activo (Brute Force Lite)
            print(f"[*] Ejecutando Brute Force DNS (prefijos críticos)...")
            active_subs = await self.dns_brute_force()
            
            all_discovered = passive_subs.union(active_subs)
            
            # 3. Verificación de Supervivencia y Takeovers
            print(f"[*] Procesando {len(all_discovered)} subdominios únicos...")
            live_subs = []
            takeover_tasks = []

            for sub in all_discovered:
                if self.is_alive(sub):
                    live_subs.append(sub)
                    takeover_tasks.append(self.check_takeover(session, sub))
                
            if takeover_tasks:
                await asyncio.gather(*takeover_tasks)

            # 4. Reporte Final
            score_count = sum(1 for s in live_subs if self.get_score(s) > 0)
            print(f"[+] Recon: {len(live_subs)} subdominios vivos encontrados ({score_count} de alto interés).")
            if self.takeovers:
                print(f"[!!!] ALERT: {len(self.takeovers)} posibles Subdomain Takeovers encontrados.")
            return live_subs
