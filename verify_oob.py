import asyncio
import logging
from core.oob_engine import OOBEngine

logging.basicConfig(level=logging.INFO)

async def test_oob():
    print("[*] Iniciando prueba de OOB Engine con Fallback...")
    oob = OOBEngine()
    host = await oob.register()
    if host:
        print(f"[+] Éxito: Canal establecido en {host}")
        payload = oob.generate_payload("https://test.com", "vuln_param")
        print(f"[+] Payload generado: {payload}")
    else:
        print("[-] Error: No se pudo establecer el canal OOB.")

if __name__ == "__main__":
    asyncio.run(test_oob())
