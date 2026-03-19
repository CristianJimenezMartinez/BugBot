import asyncio
import logging
import aiohttp
from core.oob_engine import OOBEngine
from core.config import Config

# Forzar logs a nivel DEBUG para ver el fallo exacto
logging.basicConfig(level=logging.DEBUG)

async def test_oob():
    print("[*] Iniciando prueba de OOB Engine con Fallback y Debug...")
    oob = OOBEngine()
    
    # Probar manualmente el conector primero
    try:
        connector = Config.get_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get("https://oast.fun", timeout=5) as r:
                print(f"[DEBUG] Test oast.fun simplificado: {r.status}")
    except Exception as e:
        print(f"[DEBUG] Error en test simplificado: {e}")

    host = await oob.register()
    if host:
        print(f"[+] Éxito: Canal establecido en {host}")
    else:
        print("[-] Error: No se pudo establecer el canal OOB.")

if __name__ == "__main__":
    asyncio.run(test_oob())
