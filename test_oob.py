import asyncio
import aiohttp
import sys

servers = [
    "https://interact.sh",
    "https://interactsh.com",
    "https://oast.me",
    "https://oast.fun",
    "https://oast.live",
    "https://oast.site",
    "https://oast.online",
    "https://oast.pro"
]

async def check(url):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as resp:
                print(f"[+] {url}: {resp.status}")
                return True
    except Exception as e:
        print(f"[-] {url}: {e}")
        return False

async def main():
    tasks = [check(url) for url in servers]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
