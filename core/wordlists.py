import os
import aiohttp
import asyncio
import logging
from core.config import Config

logger = logging.getLogger("BugBot.WordlistManager")

class WordlistManager:
    """
    Gestor de Inteligencia Táctica (v1.0):
    - Descarga automática y asíncrona de diccionarios profesionales (SecLists).
    - Prevención de descargas redundantes (comprueba existencia).
    - Guardado centralizado en /data/wordlists.
    """
    
    # Repositorios base seguros (Raw GitHub)
    SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    
    # Diccionarios Tácticos (Optimizados para Bug Bounty y Fuzzing Inteligente)
    WORDLISTS = {
        # Configuración General y Archivos Olvidados (Reemplazo del 'Sniper')
        "common_config": f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-directories.txt",
        
        # Extensiones y Backups Sensibles
        "backups_logs": f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-files.txt",
        
        # CMS y Bases de Datos
        "wp_plugins": f"{SECLISTS_BASE}/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
        
        # Tecnologías Específicas (Fuzzing Inteligente)
        "apache": f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-words-lowercase.txt",
        "nginx": f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-words.txt"
    }

    def __init__(self):
        self.wordlist_dir = os.path.join(Config.DATA_DIR, "wordlists")
        os.makedirs(self.wordlist_dir, exist_ok=True)

    async def _download_file(self, session: aiohttp.ClientSession, name: str, url: str):
        file_path = os.path.join(self.wordlist_dir, f"{name}.txt")
        
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            print(f"[*] Diccionario '{name}' ya está en caché.")
            return True

        print(f"[*] Descargando munición táctica: {name}...")
        try:
            async with session.get(url, timeout=30) as response:
                if response.status == 200:
                    content = await response.text()
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    print(f"[+] Diccionario '{name}' descargado correctamente.")
                    return True
                else:
                    logger.error(f"[-] Error descargando {name}: HTTP {response.status}")
                    print(f"[-] Fallo en la descarga de '{name}' (Status {response.status}).")
                    return False
        except Exception as e:
            logger.error(f"[-] Excepción descargando {name}: {e}")
            print(f"[-] Error crítico descargando '{name}': {e}")
            return False

    async def update_arsenal(self):
        """Descarga todos los diccionarios tácticos de forma concurrente."""
        print("[*] Abriendo Armería... Verificando diccionarios tácticos (SecLists).")
        
        resolver = aiohttp.ThreadedResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=True)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self._download_file(session, name, url) for name, url in self.WORDLISTS.items()]
            results = await asyncio.gather(*tasks)
            
        if all(results):
            print("[+] ¡Arsenal Ciber completado! Todos los diccionarios están listos en data/wordlists.")
        else:
            print("[!] Aviso: Algunos diccionarios no pudieron ser descargados. Revisa tu conexión.")

    def get_wordlist(self, name: str) -> list:
        """Carga un diccionario en memoria, limpiando líneas vacías y comentarios."""
        file_path = os.path.join(self.wordlist_dir, f"{name}.txt")
        if not os.path.exists(file_path):
            return []
            
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            # Ignorar comentarios '#' y líneas vacías
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

if __name__ == '__main__':
    import sys
    import sys
        
    async def run():
        manager = WordlistManager()
        await manager.update_arsenal()
        
    asyncio.run(run())
