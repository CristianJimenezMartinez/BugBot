import asyncio
import aiohttp
import sys

async def test():
    try:
        # Forzar ThreadedResolver para evitar aiodns en Windows
        resolver = aiohttp.ThreadedResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, use_dns_cache=False)
        
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get("https://oast.fun", timeout=10) as resp:
                print(f"[+] Status oast.fun: {resp.status}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    asyncio.run(test())
