import asyncio
import aiohttp
import time
import sys

async def check():
    url = 'https://analystday.playtika.com'
    print(f'Checking {url}...')
    start = time.time()
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        resolver = aiohttp.ThreadedResolver()
        connector = aiohttp.TCPConnector(resolver=resolver, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(url, timeout=timeout) as resp:
                print(f'Alive! Status: {resp.status}')
    except Exception as e:
        print(f'Dead! Error: {type(e).__name__} - {e}')
    print(f'Time taken: {time.time() - start:.2f}s')

# No forzar SelectorEventLoop
import sys
asyncio.run(check())
