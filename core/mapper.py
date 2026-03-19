import asyncio
import aiohttp
import socket
import logging
import re
import os
from bs4 import BeautifulSoup
from typing import List, Dict
from core.config import Config

class Mapper:
    """
    Motor de Enriquecimiento Gran Angular (v1.0)
    - Resuelve IPs y Títulos Web.
    - Aplica scoring visual (⭐).
    - Genera tabla consolidada para revisión manual.
    """
    
    def __init__(self, concurrency: int = 20):
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=5)
        self.headers = {"User-Agent": Config.get_random_user_agent()}

    async def get_ip(self, host: str) -> str:
        """Resolución DNS asíncrona (vía threads)."""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, socket.gethostbyname, host)
        except:
            return "N/A"

    async def get_title(self, session: aiohttp.ClientSession, host: str) -> str:
        """Obtiene el título de la web (HTTP/HTTPS)."""
        for proto in ["https://", "http://"]:
            url = f"{proto}{host}"
            try:
                async with session.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True) as response:
                    if response.status == 200:
                        text = await response.text()
                        soup = BeautifulSoup(text, 'html.parser')
                        title = soup.title.string.strip() if soup.title else "No Title"
                        # Limpiar saltos de línea y exceso de espacios
                        return " ".join(title.split())
            except:
                continue
        return "N/A"

    def has_interest(self, host: str) -> bool:
        """Verifica si el subdominio contiene keywords de interés."""
        host_lower = host.lower()
        return any(kw in host_lower for kw in Config.INTEREST_KEYWORDS)

    async def process_host(self, session: aiohttp.ClientSession, host: str) -> Dict:
        """Procesa un host individual para el mapa."""
        ip = await self.get_ip(host)
        title = await self.get_title(session, host)
        star = "⭐" if self.has_interest(host) else ""
        
        return {
            'host': host,
            'ip': ip,
            'title': title,
            'interest': star
        }

    async def run(self, hosts: List[str]) -> List[Dict]:
        """Orquestador del enriquecimiento masivo."""
        results = []
        import sys
        connector = None
        if sys.platform == 'win32':
            resolver = aiohttp.ThreadedResolver()
            connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
            
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.process_host(session, host) for host in hosts]
            results = await asyncio.gather(*tasks)
        return results

    @staticmethod
    def generate_markdown_table(results: List[Dict]) -> str:
        """Genera la tabla final en formato Markdown."""
        md = "| Interés | Subdominio | IP Pública | Título de la Web |\n"
        md += "| :---: | :--- | :--- | :--- |\n"
        
        # Ordenar: primero los de interés, luego por host
        sorted_results = sorted(results, key=lambda x: (x['interest'] == "", x['host']))
        
        for r in sorted_results:
            md += f"| {r['interest']} | `{r['host']}` | `{r['ip']}` | {r['title']} |\n"
        
        return md
