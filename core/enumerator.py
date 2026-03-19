import aiohttp
import asyncio
import logging
from typing import List, Set
from core.config import Config

logger = logging.getLogger("BugBot.Enumerator")

class SubdomainEnumerator:
    """
    Motor OSINT de BugBot: Extrae subdominios ocultos de fuentes públicas (Pasivo).
    Totalmente legal y silencioso (No toca la infraestructura del cliente).
    """
    def __init__(self, timeout: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        
    async def get_from_crtsh(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        """Extrae subdominios reportados en los Certificados TLS/SSL públicos."""
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                    except Exception:
                        # crt.sh a veces devuelve HTML de error/timeout en lugar de JSON
                        return set()

                    for entry in data:
                        name = entry.get('name_value', '')
                        if name:
                            # Puede devolver varios dominios separados por salto de línea
                            for sub in name.split('\n'):
                                sub = sub.strip().lower()
                                if sub.endswith(domain) and '*' not in sub:
                                    subdomains.add(sub)
        except Exception as e:
            logger.debug(f"[-] Error en crt.sh para {domain}: {e}")
            
        return subdomains

    async def get_from_hackertarget(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        """Usa la API pública de HackerTarget para buscar DNS footprinting."""
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    text = await response.text()
                    # 2. Filtrado estricto anti-cuotas y errores de API
                    if not any(noise in text.lower() for noise in ["error", "api count exceeded", "quota", "membership"]):
                        for line in text.split('\n'):
                            if ',' in line:
                                sub = line.split(',')[0].strip().lower()
                                # Validar subdominio real (sin espacios ni ruido de API)
                                if sub.endswith(domain) and " " not in sub and "api" not in sub:
                                    subdomains.add(sub)
        except Exception as e:
            logger.debug(f"[-] Error en HackerTarget para {domain}: {e}")
            
        return subdomains

    async def get_from_alienvault(self, domain: str, session: aiohttp.ClientSession) -> Set[str]:
        """Extrae subdominios usando la base de datos de Passive DNS de AlienVault OTX."""
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            async with session.get(url, timeout=self.timeout) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        for entry in data.get('passive_dns', []):
                            hostname = entry.get('hostname', '').strip().lower()
                            if hostname.endswith(domain) and '*' not in hostname:
                                subdomains.add(hostname)
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"[-] Error en AlienVault para {domain}: {e}")
            
        return subdomains

    async def check_dns(self, subdomain: str) -> bool:
        """Verifica si un subdominio resuelve en DNS para evitar ruido."""
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.getaddrinfo(subdomain, None), timeout=2.0)
            return True
        except Exception:
            return False

    async def enumerate(self, domain: str) -> List[str]:
        """Orquesta la extracción pasiva desde múltiples fuentes OSINT."""
        print(f"[*] 🌐 INTELIGENCIA OSINT: Buscando subdominios ocultos para {domain}...")
        subdomains = set()
        
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            tasks = [
                self.get_from_crtsh(domain, session),
                self.get_from_hackertarget(domain, session),
                self.get_from_alienvault(domain, session)
            ]
            
            results = await asyncio.gather(*tasks)
            for res in results:
                subdomains.update(res)
                
        subdomains.add(domain)
        
        # [Fase 11] Filtrado de Resolución DNS para evitar ERR_NAME_NOT_RESOLVED
        print(f"[*] 🔍 Verificando resolución DNS de {len(subdomains)} potenciales objetivos...")
        dns_tasks = [self.check_dns(sub) for sub in subdomains]
        dns_results = await asyncio.gather(*dns_tasks)
        
        final_list = sorted([sub for sub, exists in zip(subdomains, dns_results) if exists])
        
        dropped = len(subdomains) - len(final_list)
        print(f"[+] 🔍 OSINT COMPLETADO: Se descubrieron {len(final_list)} subdominios VIVOS para {domain} ({dropped} descartados por DNS)")
        return final_list
