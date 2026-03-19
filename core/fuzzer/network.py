import asyncio
import socket
import ssl
import urllib.request
from urllib.error import HTTPError
from urllib.parse import urlparse

class NetworkHunter:
    """Motor de red atómico para verificación de hosts."""
    
    @staticmethod
    async def check_host(url: str) -> bool:
        """Ping estricto C-Level + HTTP-Level."""
        def _sync_ping():
            parsed = urlparse(url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            try:
                socket.setdefaulttimeout(3.0)
                ip = socket.gethostbyname(host)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                result = s.connect_ex((ip, port))
                s.close()
                if result != 0: return False
            except Exception: return False
                
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=4.0, context=ctx) as response:
                    response.read(1)
                return True
            except HTTPError: return True 
            except Exception: return False

        return await asyncio.to_thread(_sync_ping)
